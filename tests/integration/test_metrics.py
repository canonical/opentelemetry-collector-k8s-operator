# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Scraped metrics are remote-written."""

import pathlib
import json
from typing import Dict
from tenacity import retry, stop_after_attempt, wait_fixed
from requests import request

import jubilant

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


@retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
def _retry_prom_alerts_api(endpoint: str):
    response = request("GET", endpoint).text
    data = json.loads(response)["data"]
    charm_names = [alert["labels"]["juju_charm"] for alert in data["alerts"]]
    assert any("avalanche-k8s" in item for item in charm_names)


@retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
def _retry_prom_jobs_api(endpoint: str):
    job_names = json.loads(request("GET", endpoint).text)["data"]
    assert any("avalanche" in item for item in job_names)
    assert any("otelcol" in item for item in job_names)


@retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
def _retry_avalanche_metrics_arrive_prom(prom_ip: str):
    params = {"query": 'count({__name__=~"avalanche_metric_.+"})'}
    data = json.loads(request("GET", f"http://{prom_ip}:9090/api/v1/query", params=params).text)[
        "data"
    ]
    avalanche_metric_count = int(data["result"][0]["value"][1])
    assert avalanche_metric_count > 0


def test_metrics_pipeline(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: scrape-to-remote-write forwarding."""
    # GIVEN a model with avalanche, otel-collector, and prometheus charms
    juju.deploy("avalanche-k8s", app="avalanche", channel="2/edge", trust=True)
    juju.deploy("prometheus-k8s", app="prometheus", channel="2/edge", trust=True)
    juju.deploy(charm, app="otelcol", resources=charm_resources, trust=True)
    # WHEN they are related via scrape and remote-write
    juju.integrate("avalanche", "otelcol:metrics-endpoint")
    juju.integrate("otelcol:send-remote-write", "prometheus")
    juju.wait(jubilant.all_active, delay=10, timeout=600)
    prom_ip = juju.status().apps["prometheus"].units["prometheus/0"].address
    # THEN the AlwaysFiring alerts from Avalanche arrive in prometheus
    _retry_prom_alerts_api(f"http://{prom_ip}:9090/api/v1/alerts")
    # AND juju_application labels in prometheus contain otel-collector and avalanche
    _retry_prom_jobs_api(f"http://{prom_ip}:9090/api/v1/label/juju_application/values")
    # AND avalanche metrics arrive in prometheus
    _retry_avalanche_metrics_arrive_prom(prom_ip)
    # AND rules arrive in prometheus
    data = json.loads(request("GET", f"http://{prom_ip}:9090/api/v1/rules").text)["data"]
    group_names = [group["name"] for group in data["groups"]]
    assert any("_avalanche_" in item for item in group_names)
