# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested traces are pushed to Tempo."""

import json
from minio import Minio
from typing import Dict
from tenacity import retry, stop_after_attempt, wait_fixed
from requests import request

import jubilant

# pyright: reportAttributeAccessIssue = false


@retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
async def check_grafana_traces(tempo_ip: str):
    response = request(
        "GET", f"http://{tempo_ip}:3200/api/search", params={"juju_charm": "grafana-k8s"}
    )
    traces = json.loads(response.text)["traces"]
    assert traces


async def test_metrics_pipeline(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: scrape-to-remote-write forwarding."""
    # sh.juju.switch(juju.model)
    minio_user = "accesskey"
    minio_pass = "secretkey"
    minio_bucket = "tempo"

    # GIVEN a model with grafana, otel-collector, and tempo charms
    juju.deploy(
        charm=charm,
        app="otelcol",
        resources={
            "opentelemetry-collector-image": "ghcr.io/canonical/opentelemetry-collector:dev"
        },
        trust=True,
    )
    juju.deploy(charm="grafana-k8s", app="grafana", channel="2/edge", trust=True)
    juju.deploy(charm="tempo-coordinator-k8s", app="tempo", channel="2/edge", trust=True)
    juju.deploy(charm="tempo-worker-k8s", app="tempo-worker", channel="2/edge", trust=True)
    # Set up minio and s3-integrator
    juju.deploy(
        charm="minio",
        app="minio-tempo",
        trust=True,
        config={"access-key": minio_user, "secret-key": minio_pass},
    )
    juju.deploy(charm="s3-integrator", app="s3-tempo", channel="edge")
    juju.wait(lambda status: jubilant.all_active(status, "minio-tempo"), delay=5)
    minio_address = juju.status().apps["minio-tempo"].units["minio-tempo/0"].address
    minio_client: Minio = Minio(
        f"{minio_address}:9000",
        access_key=minio_user,
        secret_key=minio_pass,
        secure=False,
    )
    if not minio_client.bucket_exists(minio_bucket):
        minio_client.make_bucket(minio_bucket)
    juju.config("s3-tempo", {"endpoint": f"{minio_address}:9000", "bucket": minio_bucket})
    juju.run(
        unit="s3-tempo/0",
        action="sync-s3-credentials",
        params={"access-key": minio_user, "secret-key": minio_pass},
    )
    juju.integrate("tempo:s3", "s3-tempo")
    juju.integrate("tempo:tempo-cluster", "tempo-worker")
    # WHEN we add relations to send traces to tempo
    juju.integrate("otelcol:receive-traces", "grafana:charm-tracing")
    juju.integrate("otelcol:receive-traces", "grafana:workload-tracing")
    juju.integrate("otelcol:send-traces", "tempo:tracing")
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # AND some traces are produced
    juju.run("grafana/0", "get-admin-password")
    juju.integrate("otelcol:grafana-dashboards-provider", "grafana")

    # THEN traces arrive in tempo
    tempo_ip = juju.status().apps["tempo"].units["tempo/0"].address
    await check_grafana_traces(tempo_ip)
