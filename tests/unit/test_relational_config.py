#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Relation-dependant Opentelemetry-collector config.

Scenario: Relate to a data sink
    Given   A valid config requires at least one pipeline and it must have a at least one
            receiver-exporter pair
    And     An OTLP receiver is added to all signal (logs, metrics, traces) pipelines
    When    A data-sink charm is integrated with the otelcol charm
    Then    A relevant exporter is added to the config

Scenario: Relate to a data source
    Given   A valid config requires at least one pipeline and it must have a at least one
            receiver-exporter pair
    When    A data-source charm is integrated with the otelcol charm
    Then    A relevant receiver is added to the config
    And     If there is no exporter for that pipeline
    Then    A debug exporter is added for that receiver-exporter pair to ensure a valid config
"""

import yaml
from ops.testing import Container, Context, Relation, State


def check_valid_pipelines(cfg):
    """Assert that each pipeline has at least one receiver-exporter pair."""
    pipelines = [cfg["service"]["pipelines"][p] for p in cfg["service"]["pipelines"]]
    pairs = [(len(p["receivers"]) > 0, len(p["exporters"]) > 0) for p in pipelines]
    assert all(all(condition for condition in pair) for pair in pairs)


def test_no_relations(otelcol_charm):
    # GIVEN No relations
    ctx = Context(otelcol_charm)
    state_in = State(containers=[Container(name="otelcol", can_connect=True)])
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    otelcol = state_out.get_container("otelcol")
    # THEN the otelcol service has started
    assert otelcol.services["otelcol"].is_running()
    fs = otelcol.get_filesystem(ctx)
    otelcol_config = fs.joinpath(*otelcol_charm._config_path.strip("/").split("/"))
    # AND the otelcol config was pushed to the workload container
    assert otelcol_config.exists()
    cfg = yaml.safe_load(otelcol_config.read_text())
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_loki_exporter(otelcol_charm):
    # GIVEN A relation to multiple Loki units
    remote_units_data = {
        0: {"endpoint": '{"url": "http://fqdn-0:3100/loki/api/v1/push"}'},
        1: {"endpoint": '{"url": "http://fqdn-1:3100/loki/api/v1/push"}'},
    }
    data_sink = Relation(
        endpoint="send-loki-logs", interface="loki_push_api", remote_units_data=remote_units_data
    )
    ctx = Context(otelcol_charm)
    container = Container(name="otelcol", can_connect=True)
    state_in = State(
        relations=[data_sink],
        containers=[container],
    )
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    otelcol = state_out.get_container("otelcol")
    # THEN the otelcol service has started
    assert otelcol.services["otelcol"].is_running()
    fs = otelcol.get_filesystem(ctx)
    otelcol_config = fs.joinpath(*otelcol_charm._config_path.strip("/").split("/"))
    # AND the otelcol config was pushed to the workload container
    assert otelcol_config.exists()
    cfg = yaml.safe_load(otelcol_config.read_text())
    # AND one exporter per loki unit in relation exists in the config
    prom_exporters = [f"loki/{idx}" for idx in range(len(remote_units_data))]
    assert set(prom_exporters).issubset(set(cfg["exporters"].keys()))
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_prometheus_exporter(otelcol_charm):
    # GIVEN A relation to multiple Prometheus units
    remote_units_data = {
        0: {"remote_write": '{"url": "http://fqdn-0:9090/api/v1/write"}'},
        1: {"remote_write": '{"url": "http://fqdn-1:9090/api/v1/write"}'},
    }
    data_sink = Relation(
        endpoint="send-remote-write",
        interface="prometheus_remote_write",
        remote_units_data=remote_units_data,
    )
    ctx = Context(otelcol_charm)
    container = Container(name="otelcol", can_connect=True)
    state_in = State(
        relations=[data_sink],
        containers=[container],
    )
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    otelcol = state_out.get_container("otelcol")
    # THEN the otelcol service has started
    assert otelcol.services["otelcol"].is_running()
    fs = otelcol.get_filesystem(ctx)
    otelcol_config = fs.joinpath(*otelcol_charm._config_path.strip("/").split("/"))
    # AND the otelcol config was pushed to the workload container
    assert otelcol_config.exists()
    cfg = yaml.safe_load(otelcol_config.read_text())
    # AND one exporter per prometheus unit in relation exists in the config
    prom_exporters = [f"prometheusremotewrite/{idx}" for idx in range(len(remote_units_data))]
    assert set(prom_exporters).issubset(set(cfg["exporters"].keys()))
    # AND the pipelines are valid
    check_valid_pipelines(cfg)
