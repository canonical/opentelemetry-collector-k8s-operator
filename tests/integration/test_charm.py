#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Healthy deployment.

Scenario: Standalone deployment
    When otelcol is deployed standalone
    Then all pebble checks pass
"""

from typing import Optional
import jubilant
import sh
from pytest_jubilant import Juju

# pyright: reportAttributeAccessIssue = false



def _get_pebble_checks(app_name: str, model: Optional[str]):
    """Get the pebble checks results."""
    assert model
    return sh.juju.ssh(
        f"--model={model}",
        "--container=otelcol",
        f"{app_name}/leader",
        "pebble checks",
    )


def test_pebble_checks(juju: Juju, charm, charm_resources):
    """Deploy the charm."""
    sh.juju.switch(juju.model)
    app_name = "otel-collector-k8s"
    juju.deploy(f"./{charm.charm}", app_name, resources=charm_resources)
    juju.wait(jubilant.all_active, delay=10, timeout=60)
    pebble_checks = _get_pebble_checks(app_name, juju.model)
    assert "down" not in pebble_checks
