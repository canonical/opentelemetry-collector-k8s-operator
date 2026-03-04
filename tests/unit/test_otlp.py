# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoints and rules transfer."""

import dataclasses
import json
from unittest.mock import patch

import pytest
from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State

from src.integrations import cyclic_otlp_relations_exist
from src.otlp import OtlpConsumerAppData, OtlpEndpoint, OtlpProviderAppData, RulesModel

ALL_PROTOCOLS = ["grpc", "http"]
ALL_TELEMETRIES = ["logs", "metrics", "traces"]
EMPTY_CONSUMER = {
    "rules": json.dumps({"logql": {}, "promql": {}}),
    "metadata": json.dumps({}),
}
SEND_OTLP = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
RECEIVE_OTLP = Relation("receive-otlp", remote_app_data=EMPTY_CONSUMER)
OTELCOL_METADATA = {
    "application": "opentelemetry-collector-k8s",
    "charm_name": "opentelemetry-collector-k8s",
    "model": "otelcol",
    "model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
    "unit": "opentelemetry-collector-k8s/0",
}


def _replace(*args, **kwargs):
    return dataclasses.replace(*args, **kwargs)


def _decompress(rules: str) -> dict:
    return json.loads(LZMABase64.decompress(rules))


def test_send_otlp(ctx, otelcol_container):
    # GIVEN otelcol supports (defined by OtlpProvider) a subset of OTLP protocols and telemetries
    # * a remote app provides multiple OtlpEndpoints
    remote_app_data_1 = {
        "endpoints": json.dumps(
            [
                {
                    "protocol": "http",
                    "endpoint": "http://provider-123.endpoint:4318",
                    "telemetries": ["logs", "metrics"],
                }
            ]
        )
    }
    remote_app_data_2 = {
        "endpoints": json.dumps(
            [
                {
                    "protocol": "grpc",
                    "endpoint": "http://provider-456.endpoint:4317",
                    "telemetries": ["traces"],
                },
                {
                    "protocol": "http",
                    "endpoint": "http://provider-456.endpoint:4318",
                    "telemetries": ["metrics"],
                },
            ]
        )
    }

    expected_endpoints = {
        456: OtlpEndpoint(
            protocol="http",
            endpoint="http://provider-456.endpoint:4318",
            telemetries=["metrics"],
        ),
        123: OtlpEndpoint(
            protocol="http",
            endpoint="http://provider-123.endpoint:4318",
            telemetries=["logs", "metrics"],
        ),
    }

    # WHEN they are related over the "send-otlp" endpoint
    provider_1 = Relation(
        "send-otlp",
        id=123,
        remote_app_data=remote_app_data_1,
    )
    provider_2 = Relation(
        "send-otlp",
        id=456,
        remote_app_data=remote_app_data_2,
    )
    state = State(
        relations=[provider_1, provider_2],
        leader=True,
        containers=otelcol_container,
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        remote_endpoints = mgr.charm.otlp_consumer.endpoints

    # THEN the returned endpoints are filtered accordingly
    assert {k: v.model_dump() for k, v in remote_endpoints.items()} == {
        k: v.model_dump() for k, v in expected_endpoints.items()
    }


@patch("socket.getfqdn", new=lambda *args: "fqdn")
def test_receive_otlp(ctx, otelcol_container):
    expected_endpoints = {
        "endpoints": [
            {
                "protocol": "http",
                "endpoint": "http://fqdn:4318",
                "telemetries": ["metrics"],
            }
        ],
    }

    # GIVEN a receive-otlp relation
    state = State(
        leader=True,
        containers=otelcol_container,
        relations=[RECEIVE_OTLP],
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)
    local_app_data = list(state_out.relations)[0].local_app_data

    # THEN otelcol offers its supported (defined by OtlpProvider) OTLP endpoints in the databag
    assert (actual_endpoints := json.loads(local_app_data.get("endpoints", "[]")))
    assert (
        OtlpProviderAppData.model_validate({"endpoints": actual_endpoints}).model_dump()
        == expected_endpoints
    )


@pytest.mark.parametrize(
    "relations, is_cyclic",
    (
        (
            [
                _replace(SEND_OTLP, remote_app_name="a"),
                _replace(RECEIVE_OTLP, remote_app_name="b"),
            ],
            False,
        ),
        (
            [
                _replace(SEND_OTLP, remote_app_name="b"),
                _replace(RECEIVE_OTLP, remote_app_name="a"),
            ],
            False,
        ),
        (
            [
                _replace(SEND_OTLP, remote_app_name="a"),
                _replace(RECEIVE_OTLP, remote_app_name="a"),
            ],
            True,
        ),
        (
            [
                _replace(SEND_OTLP, remote_app_name="a", id=123),
                _replace(SEND_OTLP, remote_app_name="b", id=456),
                _replace(RECEIVE_OTLP, remote_app_name="b"),
            ],
            True,
        ),
    ),
)
def test_cyclic_relations(ctx, otelcol_container, relations, is_cyclic):
    # GIVEN multiple OTLP send and receive relations
    state = State(
        relations=relations,
        leader=True,
        containers=otelcol_container,
    )

    # WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        mgr.run()
        result = cyclic_otlp_relations_exist(mgr.charm)

    # THEN the charm correctly identifies cyclic relations (one-level deep)
    assert result == is_cyclic


@pytest.mark.parametrize("forward_rules", [True, False])
def test_forwarding_otlp_rule_counts(ctx, otelcol_container, forward_rules):
    # GIVEN forwarding of rules is either enabled or disabled
    # * a receive-otlp relation (without rules) in the databag
    # * two send-otlp relations
    databag = {"rules": json.dumps({"logql": {}, "promql": {}}, sort_keys=True), "metadata": "{}"}
    receiver = Relation("receive-otlp", remote_app_data=databag)
    sender_1 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    sender_2 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[receiver, sender_1, sender_2],
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            assert (decompressed := _decompress(relation.local_app_data.get("rules")))
            databag = OtlpConsumerAppData.model_validate({"rules": decompressed, "metadata": {}})

            # THEN bundled rules are included in the forwarded databag
            assert isinstance(databag.rules, RulesModel)
            logql_group_names = {r.get("name") for r in databag.rules.logql.get("groups", [])}
            promql_group_names = {r.get("name") for r in databag.rules.promql.get("groups", [])}
            assert not logql_group_names
            assert (
                "otelcol_f4d59020_opentelemetry_collector_k8s_Exporter_alerts"
                in promql_group_names
            )


def test_forwarded_rules_have_topology(ctx, otelcol_container):
    """Test that otelcol adds its own topology metadata in the databag.

    This test ensures that rules are always labeled even if labels are not
    present in the upstream rules already. This is easier than checking if
    rules are labeled in the send-otlp databag since cos-lib tests the rest of
    the labeling rules feature.
    """
    # GIVEN an upstream receive-otlp databag with no metadata
    # * a send-otlp relation
    rules = {"logql": {}, "promql": {}}
    databag = {"rules": json.dumps(rules), "metadata": "{}"}
    receiver = Relation("receive-otlp", remote_app_data=databag)
    sender_1 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    sender_2 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[receiver, sender_1, sender_2],
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)
    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            # THEN otelcol adds its own topology metadata to the databag
            assert json.loads(relation.local_app_data.get("metadata")) == OTELCOL_METADATA
