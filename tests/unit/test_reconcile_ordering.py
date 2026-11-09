# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: workload (re)start -> stage artifacts -> forward over relation data."""

from ops.testing import State

from src import charm
from src.charm import OpenTelemetryCollectorK8sCharm


def test_service_restarted_before_rules_and_dashboards_forwarded(ctx, otelcol_container, mocker):
    state = State(containers=otelcol_container, leader=True)
    manager = mocker.Mock()
    replan_spy = mocker.spy(charm, "replan_with_trust_store")
    forward_spy = mocker.spy(OpenTelemetryCollectorK8sCharm, "forward_artifacts")
    manager.attach_mock(replan_spy, "replan")
    manager.attach_mock(forward_spy, "forward")

    ctx.run(ctx.on.update_status(), state=state)

    assert [call[0] for call in manager.mock_calls] == ["replan", "forward"]


def test_artifacts_staged_before_forwarded(ctx, otelcol_container, mocker):
    state = State(containers=otelcol_container, leader=True)
    manager = mocker.Mock()
    manager.attach_mock(mocker.spy(charm.integrations, "cleanup"), "cleanup")
    manager.attach_mock(mocker.spy(OpenTelemetryCollectorK8sCharm, "stage_artifacts"), "stage")
    manager.attach_mock(mocker.spy(OpenTelemetryCollectorK8sCharm, "forward_artifacts"), "forward")

    ctx.run(ctx.on.update_status(), state=state)

    assert [call[0] for call in manager.mock_calls] == ["cleanup", "stage", "forward"]
