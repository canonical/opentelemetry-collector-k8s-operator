# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested traces are pushed to Tempo."""

import json
from minio import Minio
from typing import Dict
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
from requests import request
import pytest

import jubilant


@retry(
    stop=stop_after_attempt(24),
    wait=wait_fixed(10),
    retry=retry_if_exception_type((ConnectionError, TimeoutError, KeyError, AssertionError)),
)
async def check_traces_from_app(tempo_ip: str, app: str):
    response = request(
        "GET", f"http://{tempo_ip}:3200/api/search", params={"juju_application": app}
    )
    traces = json.loads(response.text)["traces"]
    assert traces


def _setup_minio_bucket(
    juju: jubilant.Juju,
    minio_app: str,
    s3_app: str,
    bucket: str,
    minio_user: str,
    minio_pass: str,
):
    """Deploy minio + s3-integrator for a Tempo backend and create the bucket."""
    juju.deploy(
        charm="minio",
        app=minio_app,
        trust=True,
        config={"access-key": minio_user, "secret-key": minio_pass},
    )
    juju.deploy(charm="s3-integrator", app=s3_app, channel="edge")
    juju.wait(lambda status: jubilant.all_active(status, minio_app), delay=5)
    minio_address = juju.status().apps[minio_app].units[f"{minio_app}/0"].address
    minio_client: Minio = Minio(
        f"{minio_address}:9000",
        access_key=minio_user,
        secret_key=minio_pass,
        secure=False,
    )
    if not minio_client.bucket_exists(bucket):
        minio_client.make_bucket(bucket)
    juju.config(s3_app, {"endpoint": f"{minio_address}:9000", "bucket": bucket})
    juju.run(
        unit=f"{s3_app}/0",
        action="sync-s3-credentials",
        params={"access-key": minio_user, "secret-key": minio_pass},
    )
    return minio_address


async def test_traces_pipeline(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: traces ingestion and forwarding."""
    minio_user = "accesskey"
    minio_pass = "secretkey"
    minio_bucket = "tempo"

    # GIVEN a model with grafana, otel-collector, and tempo charms
    juju.deploy(
        charm=charm,
        app="otelcol",
        resources=charm_resources,
        trust=True,
    )
    juju.deploy(charm="grafana-k8s", app="grafana", channel="2/edge", trust=True)
    juju.deploy(charm="tempo-coordinator-k8s", app="tempo", channel="2/edge", trust=True)
    juju.deploy(charm="tempo-worker-k8s", app="tempo-worker", channel="2/edge", trust=True)
    _setup_minio_bucket(
        juju,
        minio_app="minio-tempo",
        s3_app="s3-tempo",
        bucket=minio_bucket,
        minio_user=minio_user,
        minio_pass=minio_pass,
    )
    juju.integrate("tempo:s3", "s3-tempo")
    juju.integrate("tempo:tempo-cluster", "tempo-worker")
    # WHEN we add relations to send charm traces to tempo
    juju.integrate("otelcol:send-charm-traces", "tempo:tracing")
    # THEN charm traces arrive in tempo
    juju.wait(jubilant.all_active, delay=10, timeout=900)

    # Tempo unit change its IP
    tempo_ip = juju.status().apps["tempo"].units["tempo/0"].address
    await check_traces_from_app(tempo_ip=tempo_ip, app="otelcol")

    # AND WHEN we add relations to send traces to tempo
    juju.integrate("otelcol:receive-traces", "grafana:charm-tracing")
    juju.integrate("otelcol:receive-traces", "grafana:workload-tracing")
    juju.integrate("otelcol:send-traces", "tempo:tracing")
    juju.wait(jubilant.all_active, delay=10, timeout=900)
    # AND some traces are produced
    juju.integrate("otelcol:grafana-dashboards-provider", "grafana")
    juju.run("grafana/0", "get-admin-password")

    # Tempo unit change its IP
    tempo_ip = juju.status().apps["tempo"].units["tempo/0"].address
    # THEN traces arrive in tempo
    await check_traces_from_app(tempo_ip=tempo_ip, app="grafana")


async def test_traces_multiple_backends(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: traces are forwarded to two Tempo backends simultaneously."""
    minio_user = "accesskey"
    minio_pass = "secretkey"

    # GIVEN a second Tempo stack is deployed
    juju.deploy(charm="tempo-coordinator-k8s", app="tempo2", channel="2/edge", trust=True)
    juju.deploy(charm="tempo-worker-k8s", app="tempo-worker2", channel="2/edge", trust=True)
    _setup_minio_bucket(
        juju,
        minio_app="minio-tempo2",
        s3_app="s3-tempo2",
        bucket="tempo2",
        minio_user=minio_user,
        minio_pass=minio_pass,
    )
    juju.integrate("tempo2:s3", "s3-tempo2")
    juju.integrate("tempo2:tempo-cluster", "tempo-worker2")
    juju.wait(lambda status: jubilant.all_active(status, "tempo2"), delay=10, timeout=900)

    # WHEN both Tempo backends are related to otelcol via send-traces
    # (otelcol:send-traces is already related to tempo from the previous test)
    juju.integrate("otelcol:send-traces", "tempo2:tracing")
    juju.wait(jubilant.all_active, delay=10, timeout=900)

    # THEN traces produced by grafana arrive in both Tempo backends
    tempo_ip = juju.status().apps["tempo"].units["tempo/0"].address
    tempo2_ip = juju.status().apps["tempo2"].units["tempo2/0"].address
    await check_traces_from_app(tempo_ip=tempo_ip, app="grafana")
    await check_traces_from_app(tempo_ip=tempo2_ip, app="grafana")

    # WHEN one send-traces relation is removed
    juju.remove_relation("otelcol:send-traces", "tempo2:tracing")
    juju.wait(jubilant.all_active, delay=10, timeout=600)


# https://github.com/canonical/cos-coordinated-workers/pull/8
# Before removing the 'skip', check the 'uv.lock' in Tempo Coordinator
# to make sure it's actually using the fixed library
@pytest.mark.skip("currently skipping due to tempo bug")
async def test_traces_with_tls(juju: jubilant.Juju):
    """Scenario: TLS is added to the tracing pipeline."""
    # WHEN TLS is added to Tempo and to otelcol
    juju.deploy(charm="grafana-k8s", app="coconut", channel="2/edge", trust=True)
    juju.deploy(charm="self-signed-certificates", app="ssc", channel="edge")
    juju.integrate("tempo:certificates", "ssc")
    juju.integrate("otelcol:receive-ca-cert", "ssc")
    # Make sure tempo and otelcol are using TLS before sending new traces
    juju.wait(jubilant.all_active, delay=10, timeout=900)
    juju.integrate("otelcol:receive-traces", "coconut:charm-tracing")
    juju.integrate("otelcol:receive-traces", "coconut:workload-tracing")
    juju.wait(jubilant.all_active, delay=10, timeout=900)

    # AND some traces are produced
    juju.run("coconut/0", "get-admin-password")
    juju.integrate("otelcol:grafana-dashboards-provider", "coconut")

    # THEN traces arrive in tempo
    tempo_ip = juju.status().apps["tempo"].units["tempo/0"].address
    await check_traces_from_app(tempo_ip=tempo_ip, app="coconut")

