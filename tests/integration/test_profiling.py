# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested profiles are pushed to Pyroscope."""

from minio import Minio
from typing import Dict
import pytest

import jubilant


async def test_smoke(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: profile ingestion and forwarding."""
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
    # WHEN we add relations to send profiles to pyroscope
    juju.integrate("otelcol:send-profiles", "pyroscope:profiling")
    # THEN otelcol and pyroscope are active
    juju.wait(jubilant.all_active, delay=10, timeout=900)


# https://github.com/canonical/pyroscope-operators/issues/232
@pytest.mark.skip("currently skipping because we don't have a way to generate profiles yet")
async def test_profile_pipeline(juju: jubilant.Juju):
    """Scenario: otelcol can ingest profiles and forward them to pyroscope."""


# https://github.com/canonical/pyroscope-operators/issues/231
@pytest.mark.skip("currently skipping because not implemented in pyroscope")
async def test_profile_pipeline_with_tls(juju: jubilant.Juju):
    """Scenario: TLS is added to the tracing pipeline."""
