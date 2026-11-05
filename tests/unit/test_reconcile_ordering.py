# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: stage artifacts -> workload (re)start -> forward over relation data."""

from ops.testing import State

from src import charm
from src.charm import OpenTelemetryCollectorK8sCharm


def test_service_restarted_before_rules_and_dashboards_forwarded(ctx, otelcol_container, mocker):
    state = State(containers=otelcol_container, leader=True)
    manager = mocker.Mock()
    replan_spy = mocker.spy(charm, "replan_with_trust_store")
    forward_spy = mocker.spy(OpenTelemetryCollectorK8sCharm, "_forward_alerts_and_dashboards")
    manager.attach_mock(replan_spy, "replan")
    manager.attach_mock(forward_spy, "forward")

    ctx.run(ctx.on.update_status(), state=state)

    assert [call[0] for call in manager.mock_calls] == ["replan", "forward"]


def test_artifacts_staged_before_forwarded(ctx, otelcol_container, mocker):
    state = State(containers=otelcol_container, leader=True)
    manager = mocker.Mock()
    expected_order = [
        "cleanup",
        "stage_received_otlp_rules",
        "stage_loki_alert_rules",
        "forward_send_loki_logs_alerts",
        "stage_metrics_alert_rules",
        "forward_send_remote_write_alerts",
        "forward_otlp_rules",
        "forward_dashboards",
    ]
    for name in expected_order:
        manager.attach_mock(mocker.spy(charm.integrations, name), name)

    ctx.run(ctx.on.update_status(), state=state)

    assert [call[0] for call in manager.mock_calls] == expected_order
