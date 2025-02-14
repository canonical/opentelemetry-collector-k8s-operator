#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Test that otel-collector can integrate with Prometheus."""

import sh
import yaml
import time
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
    await ops_test.model.deploy(av_app_name)
    await ops_test.model.wait_for_idle(apps=[av_app_name], status="active", raise_on_error=False)
    otel_app_name = "otel-collector-k8s"
    config = {
        "self_scrape_interval": "5s",
    }
    await ops_test.model.deploy(charm, otel_app_name, resources=_charm_resources(), config=config)
    await ops_test.model.wait_for_idle(apps=[otel_app_name], status="active", raise_on_error=False)
    prom_app_name = "prometheus-k8s"
    await ops_test.model.deploy(prom_app_name, trust=True)
    await ops_test.model.wait_for_idle(apps=[prom_app_name], status="active", raise_on_error=False)

    # WHEN they are related to scrape and remote-write
    await ops_test.model.integrate(
        f"{av_app_name}:metrics-endpoint", f"{otel_app_name}:metrics-endpoint"
    )
    await ops_test.model.integrate(
        f"{otel_app_name}:send-remote-write", f"{prom_app_name}:receive-remote-write"
    )

    prom_ip = await get_application_ip(ops_test, prom_app_name)
    # TODO This is flaky, we need a way to ensure that all the scrape jobs have made it to Prom before asserting
    #   Also, waiting 70 seconds isnt great, we should either tenacity retry until ready or have a health check
    time.sleep(70)  # The default scrape_interval is 60 seconds
    # THEN rules arrive in prometheus
    rules = json.loads(sh.curl(f"{prom_ip}:9090/api/v1/rules"))
    group_names = [group["name"] for group in rules["data"]["groups"]]
    assert any('_avalanche_k8s_' in item for item in group_names)
    # AND alerts arrive in prometheus
    alerts = json.loads(sh.curl(f"{prom_ip}:9090/api/v1/alerts"))
    charm_names = [alert["labels"]["juju_charm"] for alert in alerts["data"]["alerts"]]
    assert any('avalanche-k8s' in item for item in charm_names)

    # import pytest
    # from tenacity import retry, stop_after_delay, wait_fixed
    # @retry(stop=stop_after_delay(10), wait=wait_fixed(7))  # The default scrape_interval is 60 seconds
    # def check_curl(endpoint: str, key: str):
    #     assert sh.curl(endpoint)["data"][key]
    # check_curl(f"{prom_ip}:9090/api/v1/rules")
    # check_curl(f"{prom_ip}:9090/api/v1/alerts", "alerts")
