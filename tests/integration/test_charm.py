#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Healthy deployment.

Scenario: Standalone deployment
    When otelcol is deployed standalone
    Then all pebble checks pass
"""

import sh
from typing import Dict

import jubilant

# pyright: reportAttributeAccessIssue = false


def _get_pebble_checks(juju: jubilant.Juju, app_name: str):
    """Get the pebble checks results."""
    return sh.juju.ssh(
        f"--model={juju.model}",
        "--container=otelcol",
        f"{app_name}/leader",
        "pebble checks",
    )


async def test_pebble_checks(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Deploy the charm."""
    app_name = "otel-collector-k8s"
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.wait(jubilant.all_active)
    pebble_checks = _get_pebble_checks(juju=juju, app_name=app_name)
    assert "down" not in pebble_checks
