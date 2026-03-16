# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoints and rules transfer."""

import dataclasses
import json
from unittest.mock import patch

import pytest
from charmlibs.interfaces.otlp import OtlpEndpoint
from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State

from src.integrations import cyclic_otlp_relations_exist, send_otlp

SEND_OTLP = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
RECEIVE_OTLP = Relation("receive-otlp", remote_app_data={"rules": "{}", "metadata": "{}"})
OTELCOL_METADATA = {
    "application": "opentelemetry-collector-k8s",
    "charm_name": "opentelemetry-collector-k8s",
    "model": "otelcol",
    "model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
    "unit": "opentelemetry-collector-k8s/0",
}
OTELCOL_TOPOLOGY = {
    "juju_application": "opentelemetry-collector-k8s",
    "charm_name": "opentelemetry-collector-k8s",
    "model": "otelcol",
    "model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
}
LOGQL_ALERT = {
    "name": "otelcol_f4d59020_charm_x_foo_alerts",
    "rules": [
        {
            "alert": "HighLogVolume",
            "expr": 'count_over_time({job=~".+"}[30s]) > 100',
            "labels": {"severity": "high"},
        },
    ],
}
LOGQL_RECORD = {
    "name": "otelcol_f4d59020_charm_x_foobar_alerts",
    "rules": [
        {
            "record": "log:error_rate:rate5m",
            "expr": 'sum by (service) (rate({job=~".+"} | json | level="error" [5m]))',
            "labels": {"severity": "high"},
        }
    ],
}
PROMQL_ALERT = {
    "name": "otelcol_f4d59020_charm_x_bar_alerts",
    "rules": [
        {
            "alert": "Workload Missing",
            "expr": 'up{job=~".+"} == 0',
            "for": "0m",
            "labels": {"severity": "critical"},
        },
    ],
}
PROMQL_RECORD = {
    "name": "otelcol_f4d59020_charm_x_barfoo_alerts",
    "rules": [
        {
            "record": "code:prometheus_http_requests_total:sum",
            "expr": 'sum by (code) (prometheus_http_requests_total{job=~".+"})',
            "labels": {"severity": "high"},
        }
    ],
}
ALL_RULES = {
    "logql": {"groups": [LOGQL_ALERT, LOGQL_RECORD]},
    "promql": {"groups": [PROMQL_ALERT, PROMQL_RECORD]},
}


def _replace(*args, **kwargs):
    return dataclasses.replace(*args, **kwargs)


def _decompress(rules: str) -> dict:
    return json.loads(LZMABase64.decompress(rules))


def test_send_otlp(ctx, otelcol_container):
    # GIVEN otelcol supports (defined by OtlpRequirer) a subset of OTLP protocols and telemetries
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
        remote_endpoints = send_otlp(mgr.charm)

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
    assert actual_endpoints == expected_endpoints["endpoints"]


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
    databag = {"rules": json.dumps(ALL_RULES, sort_keys=True), "metadata": "{}"}
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

            # THEN bundled rules are included in the forwarded databag
            databag_rule_count = 2
            logql_generic_rule_count = 0
            logql_bundled_rule_count = 0
            promql_generic_rule_count = 1
            promql_bundled_rule_count = 3
            promql_count = (
                (databag_rule_count if forward_rules else 0)
                + promql_bundled_rule_count
                + promql_generic_rule_count
            )
            logql_count = (
                (databag_rule_count if forward_rules else 0)
                + logql_bundled_rule_count
                + logql_generic_rule_count
            )
            logql_groups = decompressed["logql"].get("groups", [])
            promql_groups = decompressed["promql"].get("groups", [])
            assert len(logql_groups) == logql_count
            assert len(promql_groups) == promql_count


def test_forwarded_rules_have_topology(ctx, otelcol_container):
    """Test that otelcol adds its own topology metadata in the databag.

    This test ensures that rules are always labeled even if labels are not
    present in the upstream rules already. `cos-lib` tests the rest of the
    labeling rules feature.
    """
    # GIVEN an upstream receive-otlp databag with no metadata
    # * a send-otlp relation
    receiver = Relation("receive-otlp", remote_app_data={"rules": "{}", "metadata": "{}"})
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
