# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Shared helpers for integration tests."""

import logging

import jubilant
from tenacity import (
    after_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

# Reusable retry decorator for polling assertions in integration tests.
# Retries only on AssertionError (so real errors surface immediately), with exponential backoff.
RETRY = retry(
    retry=retry_if_exception_type(AssertionError),
    wait=wait_exponential(multiplier=1, min=2, max=45),
    stop=stop_after_attempt(10),
    after=after_log(logger, logging.INFO),
)


@RETRY
def assert_pebble_service_active(
    juju: jubilant.Juju, unit: str, container: str, service: str
) -> None:
    """Assert a Pebble service in a workload container is running (Current == active)."""
    out = juju.ssh(target=unit, command=f"pebble services {service}", container=container)
    # `pebble services <name>` prints a header then one row per service:
    #   Service  Startup  Current  Since
    #   <name>   enabled  active   ...
    for line in out.splitlines():
        cols = line.split()
        if cols and cols[0] == service:
            assert "active" in cols, f"pebble service {service!r} is not active: {out!r}"
            return
    raise AssertionError(
        f"pebble service {service!r} not found in container {container!r}: {out!r}"
    )


def deploy_seaweedfs(juju: jubilant.Juju, app: str, s3_requirer_app: str) -> None:
    """Deploy seaweedfs-k8s and integrate it with the given S3-requiring app.

    Args:
        juju: The jubilant Juju instance.
        app: The name to give the deployed seaweedfs-k8s application.
        s3_requirer_app: The name of the app that requires the S3 relation.
    """
    juju.deploy("seaweedfs-k8s", app, channel="edge")
    juju.wait(lambda status: jubilant.all_active(status, app), delay=5, timeout=600)
    juju.integrate(f"{s3_requirer_app}:s3", f"{app}:s3-credentials")
