#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Healthy deployment.

Scenario: Standalone deployment
    When otelcol is deployed standalone
    Then all pebble checks pass
"""

from typing import Dict, Optional

import jubilant
import sh

# pyright: reportAttributeAccessIssue = false



def _get_pebble_checks(model: Optional[str], app_name: str):
    """Get the pebble checks results."""
    assert model
    return sh.juju.ssh(
        f"--model={model}",
        "--container=otelcol",
        f"{app_name}/leader",
        "pebble checks",
    )


def test_pebble_checks(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Deploy the charm."""
    sh.juju.switch(juju.model)
    app_name = "otel-collector-k8s"
    juju.deploy(charm, app_name, resources=charm_resources)
    juju.wait(jubilant.all_active, delay=10, timeout=60)
    pebble_checks = _get_pebble_checks(model=juju.model, app_name=app_name)
    assert "down" not in pebble_checks
