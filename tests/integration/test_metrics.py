#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Test that otel-collector can integrate with Prometheus."""

import sh
import yaml
import json
from typing import Dict
from pytest_operator.plugin import OpsTest
from helpers import get_application_ip

# pyright: reportAttributeAccessIssue = false


def _charm_resources(metadata_file="charmcraft.yaml") -> Dict[str, str]:
    with open(metadata_file, "r") as file:
        metadata = yaml.safe_load(file)
    resources = {}
    for res, data in metadata["resources"].items():
        resources[res] = data["upstream-source"]
    return resources


async def test_metrics_pipeline(ops_test: OpsTest, charm: str):
    """Send metrics from Avalanche to Prometheus with Otel-collector."""
    assert ops_test.model
    # GIVEN a model with avalanche, otel-collector, and prometheus charms
    av_app_name = "avalanche-k8s"
    otel_app_name = "otel-collector-k8s"
    prom_app_name = "prometheus-k8s"
    await ops_test.model.deploy(av_app_name)
    await ops_test.model.deploy(charm, otel_app_name, resources=_charm_resources())
    await ops_test.model.deploy(prom_app_name, trust=True)

    # WHEN they are related to scrape and remote-write
    await ops_test.model.integrate(
        f"{av_app_name}:metrics-endpoint", f"{otel_app_name}:metrics-endpoint"
    )
    await ops_test.model.integrate(
        f"{otel_app_name}:send-remote-write", f"{prom_app_name}:receive-remote-write"
    )
    await ops_test.model.wait_for_idle(status="active", raise_on_error=False, idle_period=60)

    prom_ip = await get_application_ip(ops_test, prom_app_name)

    # THEN rules arrive in prometheus
    data = json.loads(sh.curl(f"{prom_ip}:9090/api/v1/rules"))["data"]
    group_names = [group["name"] for group in data["groups"]]
    assert any("_avalanche_k8s_" in item for item in group_names)

    # AND alerts arrive in prometheus
    data = json.loads(sh.curl(f"{prom_ip}:9090/api/v1/alerts"))["data"]
    charm_names = [alert["labels"]["juju_charm"] for alert in data["alerts"]]
    assert any("avalanche-k8s" in item for item in charm_names)

    # AND job labels in prometheus contain otel and avalanche
    job_names = json.loads(sh.curl(f"{prom_ip}:9090/api/v1/label/jobs/values"))["data"]
    assert any("avalanche-k8s" in item for item in job_names)
    assert any("otel-collector-k8s" in item for item in job_names)
