# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Unit tests for rules_forwarded_with_topology.feature."""

import dataclasses
import json

from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State
from pytest_bdd import scenarios, given, parsers, then, when
from unittest.mock import patch

import pytest
from charmlibs.interfaces.otlp import OtlpEndpoint
from ops.testing import Model, Relation, State

from src.integrations import cyclic_otlp_relations_exist, send_otlp

scenarios("features/otlp.feature")


# ----- HELPERS -----


def _replace(*args, **kwargs):
    return dataclasses.replace(*args, **kwargs)

def _decompress(rules: str) -> dict:
    return json.loads(LZMABase64.decompress(rules))


# ----- GIVEN -----


@given("juju topology of an otelcol unit", target_fixture="otelcol_metadata")
def otelcol_juju_topology():
    return {
        "application": "opentelemetry-collector-k8s",
        "charm_name": "opentelemetry-collector-k8s",
        "model": "otelcol",
        "model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
        "unit": "opentelemetry-collector-k8s/0",
    }


# ----- STATE -----


# Relations
@given(
    "a send-otlp relation with a provider offering no OTLP endpoints", target_fixture="relation"
)
def send_otlp_rel_no_endpoints():
    return Relation("send-otlp", remote_app_data={"endpoints": "[]"})


@given("a receive-otlp relation with a requirer offering no rules", target_fixture="relation")
def receive_otlp_rel_no_rules():
    return Relation("receive-otlp", remote_app_data={"rules": "{}", "metadata": "{}"})


@given(
    "a send-otlp relation with a provider offering an HTTP OTLP endpoint for logs and metrics",
    target_fixture="relation",
)
def send_otlp_rel_http_endpoint_for_logs_and_metrics():
    return Relation(
        "send-otlp",
        id=123,
        remote_app_data={
            "endpoints": json.dumps(
                [
                    {
                        "protocol": "http",
                        "endpoint": "http://provider-123.endpoint:4318",
                        "telemetries": ["logs", "metrics"],
                    }
                ]
            )
        },
    )


@given(
    "a send-otlp relation with a provider offering two OTLP endpoints: gRPC for traces and HTTP for metrics",
    target_fixture="relation",
)
def send_otlp_rel_two_endpoints():
    return Relation(
        "send-otlp",
        id=456,
        remote_app_data={
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
        },
    )


@given(parsers.parse('the remote app is named: "{name}"'), target_fixture="relation")
def update_remote_app_name(relation, name):
    return _replace(relation, remote_app_name=name)

@given(parsers.parse('the remote app has id: {id:d}'), target_fixture="relation")
def update_remote_app_id(relation, id):
    return _replace(relation, id=id)

# Config
@given(parsers.parse('"{config}" config is set to True'), target_fixture="config")
def bool_config_true(config):
    return {config: True}


@given(parsers.parse('"{config}" config is set to False'), target_fixture="config")
def bool_config_false(config):
    return {config: False}


@given("the operator is initialized", target_fixture="state")
def base_state(otelcol_container):
    return State(
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )


# State
@when("integrated with our charm", target_fixture="state")
def integrate(state, relation):
    updated_relations = list(state.relations).copy()
    updated_relations.append(relation)
    return _replace(state, relations=updated_relations)


@when("the charm config is applied", target_fixture="state")
def update_config(state, config):
    updated_config = state.config.copy()
    updated_config.update(config)
    return _replace(state, config=updated_config)


# ----- EVENTS -----


@when(parsers.parse('the operator executes the "{event}" event'), target_fixture="state_out")
def operator_executes_event(ctx, state, event):
    with patch("socket.getfqdn", new=lambda *args: "fqdn"):
        return ctx.run(getattr(ctx.on, event)(), state=state)


@when(
    parsers.parse('the operator executes the "{event}" event and returns a charm'),
    target_fixture="charm",
)
def operator_executes_event_and_returns_charm(ctx, state, event):
    with patch("socket.getfqdn", new=lambda *args: "fqdn"):
        with ctx(getattr(ctx.on, event)(), state=state) as mgr:
            return mgr.charm


# ----- THEN -----


@then("the provider offers an HTTP OTLP endpoint for metrics")
def bundled_promql_alert_rules_are_published_to_local_appdata(state_out):
    expected_endpoints = {
        "endpoints": [
            {
                "protocol": "http",
                "endpoint": "http://fqdn:4318",
                "telemetries": ["metrics"],
            }
        ],
    }
    local_app_data = list(state_out.relations)[0].local_app_data
    assert (actual_endpoints := json.loads(local_app_data.get("endpoints", "[]")))
    assert actual_endpoints == expected_endpoints["endpoints"]


@then("the bundled rules are sent to the provider")
def bundled_rules_in_forwarded_databag(state_out):
    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            assert (decompressed := _decompress(relation.local_app_data.get("rules")))
            logql_group_names = {r.get("name") for r in decompressed["logql"].get("groups", [])}
            promql_group_names = {r.get("name") for r in decompressed["promql"].get("groups", [])}
            assert not logql_group_names
            assert (
                "otelcol_f4d59020_opentelemetry_collector_k8s_Exporter_alerts"
                in promql_group_names
            )


@then("otelcol adds its own topology metadata to the databag")
def otelcol_adds_topology_metadata(state_out, otelcol_metadata):
    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            assert json.loads(relation.local_app_data.get("metadata")) == otelcol_metadata


@then("the requirer chooses two OTLP endpoints: HTTP for metrics and HTTP for logs and metrics")
def expected_endpoint_support(charm):
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
    remote_endpoints = send_otlp(charm)
    assert {k: v.model_dump() for k, v in remote_endpoints.items()} == {
        k: v.model_dump() for k, v in expected_endpoints.items()
    }

@then(
    parsers.parse(
        'the data transfer is cyclic: "{truth:YesNo}"', extra_types={"YesNo": lambda s: s == "yes"}
    )
)
def relations_are_cyclic(charm, truth):
    assert truth == cyclic_otlp_relations_exist(charm)
