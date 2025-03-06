#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Ingested logs are forwarded.

Scenario: loki-to-loki formatted log forwarding
    When otelcol is integrated with zinc and loki over logging-consumer and logging-provider respectively
    Then zinc logs are forwarded to loki
"""

from typing import Dict
from pytest_operator.plugin import OpsTest

# pyright: reportAttributeAccessIssue = false


async def test_logs_pipeline(ops_test: OpsTest, charm: str, charm_resources: Dict[str, str]):
    """Send logs from Zinc to Loki with Otel-collector."""
    assert ops_test.model
    # GIVEN a model with zinc, otel-collector, and loki charms
    zinc_app_name = "zinc-k8s"
    otelcol_app_name = "otel-collector-k8s"
    loki_app_name = "loki-k8s"
    await ops_test.model.deploy(zinc_app_name)
    await ops_test.model.deploy(charm, otelcol_app_name, resources=charm_resources)
    await ops_test.model.deploy(loki_app_name, trust=True)
    # WHEN they are related to logging-consumer and logging-provider
    # TODO What about when we have logging with LogForwarder in Zinc?
    await ops_test.model.integrate(
        f"{zinc_app_name}:log-proxy", f"{otelcol_app_name}:logging-provider"
    )
    await ops_test.model.integrate(
        f"{otelcol_app_name}:logging-consumer", f"{loki_app_name}:logging"
    )
    await ops_test.model.wait_for_idle(status="active")
