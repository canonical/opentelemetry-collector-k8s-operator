# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Scraped metrics are remote-written."""

import json
import pathlib
import tempfile
import textwrap

import jubilant
import sh
from pytest_jubilant import Juju
from requests import request
from tenacity import retry, stop_after_attempt, wait_fixed

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


@retry(stop=stop_after_attempt(7), wait=wait_fixed(5))
def _retry_prom_alerts_api(endpoint: str):
    response = request("GET", endpoint).text
    data = json.loads(response)["data"]
    charm_names = [alert["labels"]["juju_charm"] for alert in data["alerts"]]
    assert any("avalanche-k8s" in item for item in charm_names)


@retry(stop=stop_after_attempt(7), wait=wait_fixed(5))
def _retry_prom_jobs_api(endpoint: str):
    job_names = json.loads(request("GET", endpoint).text)["data"]
    assert any("avalanche" in item for item in job_names)
    assert any("otelcol" in item for item in job_names)


def test_metrics_pipeline(juju: Juju, charm, charm_resources):
    """Scenario: scrape-to-remote-write forwarding."""
    sh.juju.switch(juju.model)

    # GIVEN a model with avalanche, otel-collector, and prometheus charms
    # TODO Add ./ in front of charm
    bundle = textwrap.dedent(f"""
        bundle: kubernetes
        applications:
          avalanche:
            charm: avalanche-k8s
            channel: 1/edge
            scale: 1
            trust: true
          otelcol:
            charm: {charm}
            scale: 1
            resources:
              opentelemetry-collector-image: {charm_resources["opentelemetry-collector-image"]}
          prometheus:
            charm: prometheus-k8s
            channel: latest/edge
            scale: 1
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
    prom_ip = juju.status().apps["prometheus"].units["prometheus/0"].address
    data = json.loads(request("GET", f"http://{prom_ip}:9090/api/v1/rules").text)["data"]
    group_names = [group["name"] for group in data["groups"]]
    assert any("_avalanche_" in item for item in group_names)
    # AND the AlwaysFiring alerts from Avalanche arrive in prometheus
    _retry_prom_alerts_api(f"http://{prom_ip}:9090/api/v1/alerts")
    # AND juju_application labels in prometheus contain otel-collector and avalanche
    _retry_prom_jobs_api(f"http://{prom_ip}:9090/api/v1/label/juju_application/values")
    # AND avalanche metrics arrive in prometheus
    params = {"query": 'count({__name__=~"avalanche_metric_.+"})'}
    data = json.loads(request("GET", f"http://{prom_ip}:9090/api/v1/query", params=params).text)[
        "data"
    ]
    avalanche_metric_count = int(data["result"][0]["value"][1])
    assert avalanche_metric_count > 0
