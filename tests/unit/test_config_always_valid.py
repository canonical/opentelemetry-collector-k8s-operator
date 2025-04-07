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

from ops.testing import Container, Relation, State, Context


async def test_update_data_sink(otelcol_charm):
    """Send metrics from Avalanche to Prometheus with Otel-collector."""
    data_sink = Relation(
        endpoint="send-remote-write",
        interface="prometheus_remote_write",
        local_unit_data={"abc": "foo"},
        remote_app_data={"cde": "baz!"},
    )
    ctx = Context(otelcol_charm)
    container = Container(name="otelcol", can_connect=True)
    state_in = State(
        relations=[data_sink],
        containers=[container],
        leader=True,
    )
    # TODO I am getting FileNotFoundErrors for the src/alerts and src/dashboards dirs, why is scenario not finding these?
    state_out = ctx.run(ctx.on.update_status(), state_in)

    otelcol = state_out.get_container("otelcol")

    # # THEN the agent has started
    assert otelcol.services["otelcol"].is_running()
    # # AND the otelcol config which was pushed to the workload container
    fs = otelcol.get_filesystem(ctx)
    # otelcol_config = fs.joinpath(*CONFIG_PATH.strip("/").split("/"))
    # assert otelcol_config.exists()
    # yml = yaml.safe_load(otelcol_config.read_text())
    # assert yml["traces"] == {}

    # -------------------------------------------
    # TODO Move to unit test (with basic YAML pipeline validation)
    # 1. Scenario relation tests
    # 2. Test the config builder as a config builder with otelcol validate (without ops) https://github.com/canonical/loki-k8s-operator/blob/e61769afa165800c750c1f3e4364fc7304bd3024/tests/unit/test_transform.py#L24
    # TODO Capture frustration in writing, easy itests hard to scenario
    # -------------------------------------------
