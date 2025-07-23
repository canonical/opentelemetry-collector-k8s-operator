# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested profiles are pushed to Tempo."""

import random

from minio import Minio
from typing import Dict
from tenacity import retry, stop_after_attempt, wait_fixed
import pytest

import jubilant
import requests
import urllib.parse
from datetime import datetime


TESTING_SERVICE_NAME = "profile-testing-service"

def push_profile(host:str):
    now = round(datetime.now().timestamp()) / 10 * 10
    nonce = "nonce-"+str(random.random())
    params = {
        'from': f'{now - 10}',
        'until': f'{now}',
        'name': TESTING_SERVICE_NAME
          }

    # http://$PYRO/ingest?name=curl-test-app2&from=1753276792&until=1753276899
    url = f"http://{host}:4317?{urllib.parse.urlencode(params)}"
    data = "foo;bar 100\nfoo;baz 200"
    requests.post(url, data = data)
    return nonce


@retry(stop=stop_after_attempt(15), wait=wait_fixed(10))
def query_profiles(host:str, nonce:str):
    query = f'process_cpu:cpu:nanoseconds:cpu:nanoseconds{{service_name="{nonce}"}}'
    url = f"http://{host}:4317/pyroscope/render?query={query}&from=now-1h"
    requests.get(url)


def test_profiling_pipeline(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: profiles ingestion and forwarding."""
    minio_user = "accesskey"
    minio_pass = "secretkey"
    minio_bucket = "pyroscope"

    # GIVEN a model with grafana, otel-collector, and pyroscope charms
    juju.deploy(
        charm=charm,
        app="otelcol",
        resources=charm_resources,
        trust=True,
    )
    juju.deploy(charm="grafana-k8s", app="grafana", channel="2/edge", trust=True)
    juju.deploy(charm="pyroscope-coordinator-k8s", app="pyroscope", channel="2/edge", trust=True)
    juju.deploy(charm="pyroscope-worker-k8s", app="pyroscope-worker", channel="2/edge", trust=True)
    # Set up minio and s3-integrator
    juju.deploy(
        charm="minio",
        app="minio-pyroscope",
        trust=True,
        config={"access-key": minio_user, "secret-key": minio_pass},
    )
    juju.deploy(charm="s3-integrator", app="s3-pyroscope", channel="edge")
    juju.wait(lambda status: jubilant.all_active(status, "minio-pyroscope"), delay=5)
    minio_address = juju.status().apps["minio-pyroscope"].units["minio-pyroscope/0"].address
    minio_client: Minio = Minio(
        f"{minio_address}:9000",
        access_key=minio_user,
        secret_key=minio_pass,
        secure=False,
    )
    if not minio_client.bucket_exists(minio_bucket):
        minio_client.make_bucket(minio_bucket)

    juju.config("s3-pyroscope", {"endpoint": f"{minio_address}:9000", "bucket": minio_bucket})
    juju.run(
        unit="s3-pyroscope/0",
        action="sync-s3-credentials",
        params={"access-key": minio_user, "secret-key": minio_pass},
    )
    juju.integrate("pyroscope:s3", "s3-pyroscope")
    juju.integrate("pyroscope:pyroscope-cluster", "pyroscope-worker")
    # WHEN we add relations to send charm profiles to pyroscope
    juju.integrate("otelcol:send-charm-profiles", "pyroscope:tracing")

    # AND WHEN we add relations to send profiles to pyroscope
    juju.integrate("otelcol:receive-profiles", "grafana:charm-tracing")
    juju.integrate("otelcol:receive-profiles", "grafana:workload-tracing")
    juju.integrate("otelcol:send-profiles", "pyroscope:tracing")
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # AND some profiles are pushed to otelcol
    otelcol_ip = juju.status().apps["otelcol"].units["otelcol/0"].address
    nonce = push_profile(otelcol_ip)

    # THEN profiles arrive in pyroscope
    pyroscope_ip = juju.status().apps["pyroscope"].units["pyroscope/0"].address
    assert query_profiles(pyroscope_ip, nonce)


@pytest.mark.skip("skipping due to lacking profiling TLS support")
def test_profiles_with_tls(juju: jubilant.Juju):
    """Scenario: TLS is added to the tracing pipeline."""
    # WHEN TLS is added to Tempo and to otelcol
    juju.deploy(charm="grafana-k8s", app="coconut", channel="2/edge", trust=True)
    juju.deploy(charm="self-signed-certificates", app="ssc", channel="edge")
    juju.integrate("pyroscope:certificates", "ssc")
    juju.integrate("otelcol:receive-ca-cert", "ssc")
    # Make sure pyroscope and otelcol are using TLS before sending new profiles
    juju.wait(jubilant.all_active, delay=10, timeout=600)
    juju.integrate("otelcol:receive-profiles", "coconut:charm-tracing")
    juju.integrate("otelcol:receive-profiles", "coconut:workload-tracing")
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # AND some profiles are pushed to otelcol
    otelcol_ip = juju.status().apps["otelcol"].units["otelcol/0"].address
    nonce = push_profile(otelcol_ip)

    # THEN profiles arrive in pyroscope
    pyroscope_ip = juju.status().apps["pyroscope"].units["pyroscope/0"].address
    assert query_profiles(pyroscope_ip, nonce)
