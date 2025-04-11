# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Scraped metrics are remote-written."""

import pathlib
import tempfile
import textwrap
import sh
import json
from typing import Dict
from tenacity import retry, stop_after_attempt, wait_fixed
from requests import request

import jubilant

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


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


async def test_metrics_pipeline(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: scrape-to-remote-write forwarding."""
    sh.juju.switch(juju.model)

    # GIVEN a model with avalanche, otel-collector, and prometheus charms
    bundle = textwrap.dedent(f"""
        bundle: kubernetes
        applications:
          avalanche:
            charm: avalanche-k8s
            channel: 1/edge
            trust: true
          otelcol:
            charm: {charm}
            resources:
              opentelemetry-collector-image: {charm_resources["opentelemetry-collector-image"]}
          prometheus:
            charm: prometheus-k8s
            channel: latest/edge
            trust: true
        relations:
        - - avalanche:metrics-endpoint
          - otelcol:metrics-endpoint
        - - otelcol:send-remote-write
          - prometheus:receive-remote-write

    """)
    # WHEN they are related to scrape and remote-write
    with tempfile.NamedTemporaryFile(dir=TEMP_DIR, suffix=".yaml") as f:
        f.write(bundle.encode())
        f.flush()
        juju.deploy(f.name, trust=True)
    juju.wait(jubilant.all_active, delay=10, timeout=600)
    # THEN rules arrive in prometheus
    prom_ip = sh.kubectl.get.pod(
        "prometheus", namespace=juju.model, o="jsonpath='{.items[*].status.podIP}'"
    )
    data = json.loads(request("GET", f"http://{prom_ip}:9090/api/v1/rules").text)["data"]
    group_names = [group["name"] for group in data["groups"]]
    assert any("_avalanche_k8s_" in item for item in group_names)
    # AND the AlwaysFiring alerts from Avalanche arrive in prometheus
    await _retry_prom_alerts_api(f"http://{prom_ip}:9090/api/v1/alerts")
    # AND juju_application labels in prometheus contain otel-collector and avalanche
    await _retry_prom_jobs_api(f"http://{prom_ip}:9090/api/v1/label/juju_application/values")
    # AND avalanche metrics arrive in prometheus
    params = {"query": 'count({__name__=~"avalanche_metric_.+"})'}
    data = json.loads(request("GET", f"http://{prom_ip}:9090/api/v1/query", params=params).text)[
        "data"
    ]
    avalanche_metric_count = int(data["result"][0]["value"][1])
    assert avalanche_metric_count > 0
