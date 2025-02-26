#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Scraped metrics are remote-written.

Scenario: scrape-to-remote-write forwarding
    When otelcol is integrated with avalanche and prometheus over scrape and remote write respectively
    Then avalanche metrics are forwarded to prometheus with topology
"""

import yaml
import json
from typing import Dict
from pytest_operator.plugin import OpsTest
from helpers import get_application_ip
from tenacity import retry, stop_after_attempt, wait_fixed
from requests import request

# pyright: reportAttributeAccessIssue = false


@retry(stop=stop_after_attempt(7), wait=wait_fixed(5))
async def _retry_prom_alerts_api(endpoint: str):
    response = request("GET", endpoint).text
    data = json.loads(response)["data"]
    charm_names = [alert["labels"]["juju_charm"] for alert in data["alerts"]]
    assert any("avalanche-k8s" in item for item in charm_names)


@retry(stop=stop_after_attempt(7), wait=wait_fixed(5))
async def _retry_prom_jobs_api(endpoint: str):
    job_names = json.loads(request("GET", endpoint).text)["data"]
    assert any("avalanche-k8s" in item for item in job_names)
    assert any("otel-collector-k8s" in item for item in job_names)


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
    otelcol_app_name = "otel-collector-k8s"
    prom_app_name = "prometheus-k8s"
    await ops_test.model.deploy(av_app_name)
    await ops_test.model.deploy(charm, otelcol_app_name, resources=_charm_resources())
    await ops_test.model.deploy(prom_app_name, trust=True)
    # WHEN they are related to scrape and remote-write
    await ops_test.model.integrate(
        f"{av_app_name}:metrics-endpoint", f"{otelcol_app_name}:metrics-endpoint"
    )
    await ops_test.model.integrate(
        f"{otelcol_app_name}:send-remote-write", f"{prom_app_name}:receive-remote-write"
    )
    await ops_test.model.wait_for_idle(status="active")
    # THEN rules arrive in prometheus
    prom_ip = await get_application_ip(ops_test, prom_app_name)
    data = json.loads(request("GET", f"http://{prom_ip}:9090/api/v1/rules").text)["data"]
    group_names = [group["name"] for group in data["groups"]]
    assert any("_avalanche_k8s_" in item for item in group_names)
    # AND the AlwaysFiring alerts from Avalanche arrive in prometheus
    await _retry_prom_alerts_api(f"http://{prom_ip}:9090/api/v1/alerts")
    # AND juju_application labels in prometheus contain otel-collector and avalanche
    await _retry_prom_jobs_api(f"http://{prom_ip}:9090/api/v1/label/juju_application/values")
    # AND avalanche metrics arrive in prometheus
    params = {"query": 'count({__name__=~"avalanche_metric_.+"})'}
    data = json.loads(request("GET", f"http://{prom_ip}:9090/api/v1/query", params=params).text)["data"]
    avalanche_metric_count = int(data["result"][0]["value"][1])
    assert avalanche_metric_count > 0
