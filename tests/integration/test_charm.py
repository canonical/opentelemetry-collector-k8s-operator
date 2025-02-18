#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Basic integration test for the charm."""

import sh
import yaml
from typing import Dict
from pytest_operator.plugin import OpsTest

# pyright: reportAttributeAccessIssue = false


def _charm_resources(metadata_file="charmcraft.yaml") -> Dict[str, str]:
    with open(metadata_file, "r") as file:
        metadata = yaml.safe_load(file)
    resources = {}
    for res, data in metadata["resources"].items():
        resources[res] = data["upstream-source"]
    return resources


def _get_pebble_checks(ops_test: OpsTest, app_name: str):
    """Get the pebble checks results."""
    assert ops_test.model
    return sh.juju.ssh(
        f"--model={ops_test.model.name}",
        "--container=otelcol",
        f"{app_name}/leader",
        "pebble checks",
    )


async def test_pebble_checks(ops_test: OpsTest, charm: str):
    """Deploy the charm."""
    assert ops_test.model
    app_name = "otel-collector-k8s"
    await ops_test.model.deploy(charm, app_name, resources=_charm_resources())
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", raise_on_error=False)
    pebble_checks = _get_pebble_checks(ops_test=ops_test, app_name=app_name)
    assert "down" not in pebble_checks
