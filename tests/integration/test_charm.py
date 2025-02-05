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


async def test_pebble_checks(ops_test: OpsTest, charm: str):
    """Deploy the charm."""
    assert ops_test.model is not None
    app_name = "otel-collector-k8s"
    await ops_test.model.deploy(charm, app_name, resources=_charm_resources())
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", raise_on_error=False)
    pebble_checks = sh.juju.ssh(
        "--container", "opentelemetry-collector", f"{app_name}-0", "pebble checks"
    )
    assert "down" not in pebble_checks
