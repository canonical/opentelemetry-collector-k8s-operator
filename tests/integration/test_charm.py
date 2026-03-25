#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Healthy deployment.

Scenario: Standalone deployment
    When otelcol is deployed standalone
    Then all pebble checks pass
"""

from typing import Dict

import jubilant


def _get_pebble_checks(juju: jubilant.Juju, unit_name: str):
    """Get the pebble checks results."""
    return juju.ssh(unit_name, command="pebble checks", container="otelcol")


def test_pebble_checks(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Deploy the charm."""
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.wait(jubilant.all_active)
    pebble_checks = _get_pebble_checks(juju=juju, unit_name="otelcol/leader")
    assert "down" not in pebble_checks
