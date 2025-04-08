# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

from typing import Dict
from pytest_operator.plugin import OpsTest

# pyright: reportAttributeAccessIssue = false


async def test_logs_pipeline(ops_test: OpsTest, charm: str, charm_resources: Dict[str, str]):
    """Scenario: loki-to-loki formatted log forwarding."""
    assert ops_test.model
    # GIVEN a model with flog, otel-collector, and loki charms
    flog_app_name = "flog-k8s"
    otelcol_app_name = "otel-collector-k8s"
    loki_app_name = "loki-k8s"
    await ops_test.model.deploy(flog_app_name)
    await ops_test.model.deploy(charm, otelcol_app_name, resources=charm_resources)
    await ops_test.model.deploy(loki_app_name, trust=True)
    # WHEN they are related to over the loki_push_api interface
    await ops_test.model.integrate(
        f"{flog_app_name}:log-proxy", f"{otelcol_app_name}:receive-loki-logs"
    )
    await ops_test.model.integrate(
        f"{otelcol_app_name}:send-loki-logs", f"{loki_app_name}:logging"
    )
    await ops_test.model.wait_for_idle(status="active")
    # THEN logs arrive in loki
    juju_cmd = ["ssh", "--container", "loki", f"{loki_app_name}/0", "/usr/bin/logcli labels"]
    rc, labels, _ = await ops_test.juju(*juju_cmd)
    assert rc == 0
    assert "juju_application" in labels
