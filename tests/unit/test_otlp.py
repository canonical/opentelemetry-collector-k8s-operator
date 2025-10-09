# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Dashboard forwarding to Grafana."""

import json

from ops.testing import Container, Relation, State

from src.constants import CONFIG_PATH
from tests.unit.helpers import get_otelcol_file


def test_send_otlp_favoring_grpc(ctx, execs):
    """Scenario: Dashboards are forwarded when a dashboard provider is related."""
    # GIVEN otelcol prefers the gRPC endpoint
    # AND a remote app provides both gRPC and HTTP OTLP endpoints
    provides = [
        {"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["logs"]},
        {"protocol": "http", "endpoint": "http://host:4318", "telemetries": ["metrics"]},
    ]

    # WHEN they are related over the "send-otlp" endpoint
    provider = Relation(
        "send-otlp",
        id=123,
        remote_app_data={"data": json.dumps(provides)},
    )
    state = State(
        relations=[provider],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    # THEN the gRPC exporter (otlp) is preferred and written to the config file
    exporter_name = "otlp/rel-123"
    exporter_config = {
        "endpoint": "http://host:4317",
        "tls": {"insecure": True, "insecure_skip_verify": False},
    }
    exporter_telemetries = provides[0].get("telemetries")
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # TODO: Why is the debug exporter also in the list of exporters?
    assert cfg["exporters"].get(exporter_name) == exporter_config
    for pipeline in cfg["service"]["pipelines"]:
        if pipeline.split("/")[0] in exporter_telemetries:
            assert cfg["service"]["pipelines"][pipeline]["exporters"] == [exporter_name]
        else:
            assert exporter_name not in cfg["service"]["pipelines"][pipeline]["exporters"]


def test_send_otlp_over_http(ctx, execs):
    """Scenario: Dashboards are forwarded when a dashboard provider is related."""
    # GIVEN otelcol prefers the gRPC endpoint
    # AND a remote app provides only the HTTP OTLP endpoint
    provides = [
        {"protocol": "http", "endpoint": "http://host:4318", "telemetries": ["logs", "traces"]}
    ]

    # WHEN they are related over the "send-otlp" endpoint
    provider = Relation(
        "send-otlp",
        id=123,
        remote_app_data={"data": json.dumps(provides)},
    )
    state = State(
        relations=[provider],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    # THEN the http exporter (otlphttp) is written to the config file
    exporter_name = "otlphttp/rel-123"
    exporter_config = {
        "endpoint": "http://host:4318",
        "tls": {"insecure": True, "insecure_skip_verify": False},
    }
    exporter_telemetries = provides[0].get("telemetries")
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # TODO: Why is the debug exporter also in the list of exporters?
    assert cfg["exporters"].get(exporter_name) == exporter_config
    for pipeline in cfg["service"]["pipelines"]:
        if pipeline.split("/")[0] in exporter_telemetries:
            assert cfg["service"]["pipelines"][pipeline]["exporters"] == [exporter_name]
        else:
            assert exporter_name not in cfg["service"]["pipelines"][pipeline]["exporters"]


def test_receive_otlp(ctx, execs):
    """Scenario: Dashboards are forwarded when a dashboard provider is related."""
    # GIVEN otelcol prefers the gRPC endpoint
    # AND a remote app provides only the HTTP OTLP endpoint

    # WHEN they are related over the "send-otlp" endpoint
    state = State(
        relations=[Relation("receive-otlp")],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    expected_endpoints = [
        '{"protocol":"grpc","endpoint":"http://laptop:4317","telemetries":["logs","metrics","traces"]}',
        '{"protocol":"http","endpoint":"http://laptop:4318","telemetries":["logs","metrics","traces"]}',
    ]
    for rel in state_out.relations:
        endpoints = json.loads(rel.local_app_data.get("data"))
        assert endpoints == expected_endpoints
