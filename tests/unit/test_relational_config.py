# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Relation-dependant Opentelemetry-collector config."""

import json
from helpers import get_otelcol_file
from ops.testing import Container, Relation, State

from constants import CONFIG_PATH


def check_valid_pipelines(cfg):
    """Assert that each pipeline has at least one receiver-exporter pair."""
    pipelines = [cfg["service"]["pipelines"][p] for p in cfg["service"]["pipelines"]]
    pairs = [(len(p["receivers"]) > 0, len(p["exporters"]) > 0) for p in pipelines]
    assert all(all(condition for condition in pair) for pair in pairs)


def test_no_relations(ctx, execs):
    """Scenario: Direct signals to debug if no data sink exists."""
    # GIVEN no relations
    state_in = State(containers=[Container(name="otelcol", can_connect=True, execs=execs)])
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the config file exists and the pebble service is running
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_loki_exporter(ctx, execs):
    """Scenario: Fan-out logging architecture."""
    # GIVEN a relation to multiple Loki units
    remote_units_data = {
        0: {"endpoint": '{"url": "http://fqdn-0:3100/loki/api/v1/push"}'},
        1: {"endpoint": '{"url": "http://fqdn-1:3100/loki/api/v1/push"}'},
    }
    data_sink = Relation(
        endpoint="send-loki-logs", interface="loki_push_api", remote_units_data=remote_units_data
    )
    container = Container(name="otelcol", can_connect=True, execs=execs)
    state_in = State(
        relations=[data_sink],
        containers=[container],
    )
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the config file exists and the pebble service is running
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # AND one exporter per loki unit in relation exists in the config
    loki_exporters = [f"loki/send-loki-logs/{idx}" for idx in range(len(remote_units_data))]
    assert set(loki_exporters).issubset(set(cfg["exporters"].keys()))
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_prometheus_exporter(ctx, execs):
    """Scenario: Fan-out remote writing architecture."""
    # GIVEN a relation to multiple Prometheus units
    remote_units_data = {
        0: {"remote_write": '{"url": "http://fqdn-0:9090/api/v1/write"}'},
        1: {"remote_write": '{"url": "http://fqdn-1:9090/api/v1/write"}'},
    }
    data_sink = Relation(
        endpoint="send-remote-write",
        interface="prometheus_remote_write",
        remote_units_data=remote_units_data,
    )
    container = Container(name="otelcol", can_connect=True, execs=execs)
    state_in = State(
        relations=[data_sink],
        containers=[container],
    )
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the config file exists and the pebble service is running
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # AND one exporter per prometheus unit in relation exists in the config
    prom_exporters = [
        f"prometheusremotewrite/send-remote-write/{idx}" for idx in range(len(remote_units_data))
    ]
    assert set(prom_exporters).issubset(set(cfg["exporters"].keys()))
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_cloud_integrator(ctx, execs):
    """Scenario: Fan-out remote writing architecture."""
    # GIVEN a relation to a Grafana Cloud Integrator unit
    remote_app_data = {
        "loki_url": "http://fqdn-0:3100/loki/api/v1/push",
        "prometheus_url": "http://fqdn-1:9090/api/v1/write",
        "username": "user",
        "password": "pass",
    }
    data_sink = Relation(
        endpoint="cloud-config",
        interface="grafana_cloud_config",
        remote_app_data=remote_app_data,
    )
    container = Container(name="otelcol", can_connect=True, execs=execs)
    state_in = State(
        relations=[data_sink],
        containers=[container],
    )
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the config file exists and the pebble service is running
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # AND the exporters for the cloud-integrator exists in the config
    expected_exporters = {"loki/cloud-config", "prometheusremotewrite/cloud-config"}
    assert expected_exporters.issubset(set(cfg["exporters"].keys()))
    # AND the basicauth extension is configured
    assert "basicauth/cloud-integrator" in cfg["extensions"]
    # AND the exporters are using the basicauth configuration
    assert (
        cfg["exporters"]["loki/cloud-config"]["auth"]["authenticator"]
        == "basicauth/cloud-integrator"
    )
    assert (
        cfg["exporters"]["prometheusremotewrite/cloud-config"]["auth"]["authenticator"]
        == "basicauth/cloud-integrator"
    )
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_traces_receivers(ctx, execs):
    """Scenario: Fan-out tracing architecture."""
    # GIVEN a relation to a charm that sends traces
    local_app_data = {
        "receivers": json.dumps(
            [
                {
                    "protocol": {"name": "otlp_grpc", "type": "grpc"},
                    "url": "otel-0.otel-endpoints.ha-https-minio.svc.cluster.local:4317",
                },
                {
                    "protocol": {"name": "otlp_http", "type": "http"},
                    "url": "http://otel-0.otel-endpoints.ha-https-minio.svc.cluster.local:4318",
                },
                {
                    "protocol": {"name": "jaeger_grpc", "type": "grpc"},
                    "url": "http://otel-0.otel-endpoints.ha-https-minio.svc.cluster.local:14250",
                },
            ]
        )
    }
    remote_app_data = {"receivers": json.dumps(["otlp_http", "jaeger_grpc"])}
    data_sink = Relation(
        endpoint="receive-traces",
        interface="tracing",
        remote_app_data=remote_app_data,
        local_app_data=local_app_data,
    )
    container = Container(name="otelcol", can_connect=True, execs=execs)
    state_in = State(
        relations=[data_sink],
        containers=[container],
    )
    # WHEN any event executes the reconciler
    state_out: State = ctx.run(ctx.on.update_status(), state_in)
    # THEN the config file exists and the pebble service is running
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # AND the receivers for tracing exists in the config
    expected_receivers = {"otlp", "jaeger/receive-traces/opentelemetry-collector-k8s/0"}
    assert expected_receivers.issubset(set(cfg["receivers"].keys()))
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_traces_exporters(ctx, execs):
    """Scenario: Fan-out tracing architecture to Tempo."""
    # GIVEN a relation to a Tempo charm
    remote_app_data = {
        "receivers": json.dumps(
            [
                {
                    "protocol": {"name": "otlp_grpc", "type": "grpc"},
                    "url": "otel-0.otel-endpoints.ha-https-minio.svc.cluster.local:4317",
                },
                {
                    "protocol": {"name": "otlp_http", "type": "http"},
                    "url": "http://otel-0.otel-endpoints.ha-https-minio.svc.cluster.local:4318",
                },
                {
                    "protocol": {"name": "jaeger_grpc", "type": "grpc"},
                    "url": "http://otel-0.otel-endpoints.ha-https-minio.svc.cluster.local:14250",
                },
            ]
        )
    }
    local_app_data = {"receivers": json.dumps(["otlp_http", "jaeger_grpc"])}
    data_sink = Relation(
        endpoint="send-traces",
        interface="tracing",
        remote_app_data=remote_app_data,
        local_app_data=local_app_data,
    )
    container = Container(name="otelcol", can_connect=True, execs=execs)
    state_in = State(
        relations=[data_sink],
        containers=[container],
    )
    # WHEN any event executes the reconciler
    state_out: State = ctx.run(ctx.on.update_status(), state_in)
    # THEN the config file exists and the pebble service is running
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # AND the exporters for tracing exists in the config
    expected_exporters = {"otlphttp/send-traces"}
    assert expected_exporters.issubset(set(cfg["exporters"].keys()))
    # AND the pipelines are valid
    check_valid_pipelines(cfg)
