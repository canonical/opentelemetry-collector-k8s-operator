# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Shared helpers for integration tests."""

import logging
import time
from typing import Any, Dict, Optional, Sequence

import jubilant
import requests
import yaml
from tenacity import (
    after_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_fixed,
)

from src.config_builder import Port
from src.constants import CONFIG_PATH

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


def wait_settled(
    juju: jubilant.Juju, *apps: str, error_on: Optional[Sequence[str]] = None
) -> None:
    """Wait until the given apps are active AND every agent is idle, at the same time.

    Checking the two conditions one after the other would let a unit that is active but still
    mid-hook end the wait, which scaling makes likely: new pods re-run the resources patch and
    briefly go back to waiting. `successes` requires the condition to hold over several polls.

    `error_on` narrows which apps' error status aborts the wait; by default any app in the model
    does. Narrow it to the apps under test when a dependency is known to thrash on the way up, or
    while another app is being removed, so that only the subject's errors are treated as failures.
    """
    juju.wait(
        lambda status: jubilant.all_active(status, *apps) and jubilant.all_agents_idle(status),
        timeout=900,
        successes=10,
        error=lambda status: jubilant.any_error(status, *(error_on or ())),
    )


@RETRY
def otlp_exporter(juju: jubilant.Juju, sender: str) -> Dict[str, Any]:
    """Return the single OTLP exporter in the sender's rendered collector config.

    One exporter per destination means each payload is sent once; one per receiving unit means
    it is sent N times. Retried because the config is rewritten asynchronously.
    """
    config_raw = juju.ssh(f"{sender}/leader", command=f"cat {CONFIG_PATH}", container="otelcol")
    exporters = yaml.safe_load(config_raw).get("exporters") or {}
    matches = [
        exporter
        for name, exporter in exporters.items()
        if name.startswith(("otlp/", "otlphttp/")) and "endpoint" in exporter
    ]
    endpoints = {exporter["endpoint"] for exporter in matches}
    assert len(endpoints) == 1, (
        f"expected {sender} to target exactly one endpoint, got {sorted(endpoints)}"
    )
    return matches[0]


def otlp_exporter_endpoint(juju: jubilant.Juju, sender: str) -> str:
    """Return the endpoint of the single OTLP exporter in the sender's collector config.

    Not always a URL: gRPC is preferred wherever it is offered and its endpoints are a bare
    `host:port`. Only Traefik, which has no gRPC, yields a scheme to assert on; elsewhere use
    `otlp_exporter` and its `tls.insecure` flag.
    """
    return otlp_exporter(juju, sender)["endpoint"]


@RETRY
def assert_no_tls_verification_errors(juju: jubilant.Juju, sender: str) -> None:
    """Assert the sender's collector logs contain no certificate verification failures.

    Only meaningful when the sender itself speaks TLS to its destination; behind a plaintext
    ingress it passes vacuously. Use `assert_otlp_accepted_through_ingress` there.
    """
    logs = juju.ssh(f"{sender}/leader", command="pebble logs -n 1000", container="otelcol")
    assert "tls: failed to verify certificate" not in logs, (
        f"{sender} could not verify the receiver's certificate for the K8s Service name"
    )


def ingress_url(juju: jubilant.Juju, ingress_app: str) -> str:
    """Return the external URL of an ingress app, read from its unit's status message."""
    ingress_status = juju.status().apps[ingress_app].units[f"{ingress_app}/0"].workload_status
    address = ingress_status.message.split()[-1]
    if not address.startswith("http://"):
        address = f"http://{address}"
    return address


@retry(wait=wait_fixed(15), stop=stop_after_attempt(10))
def request_with_retry(
    url: str,
    expected_status: int,
    method: str = "GET",
    data: Optional[dict] = None,
    headers: Optional[dict] = None,
) -> requests.Response:
    """Make an HTTP request with retry logic."""
    if method == "GET":
        response = requests.get(url, timeout=10, verify=False)
    else:
        response = requests.request(
            method,
            url,
            json=data,
            headers=headers,
            timeout=10,
            verify=False,
        )
    if response.status_code != expected_status:
        raise AssertionError(f"Expected status {expected_status}, got {response.status_code}")
    return response


def otlp_logs_payload(body: str) -> dict:
    """Return an OTLP/HTTP logs request body carrying `body` as its single log record."""
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "test-service"}}
                    ]
                },
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": str(time.time_ns()),
                                "body": {"stringValue": body},
                                "severityText": "INFO",
                            }
                        ]
                    }
                ],
            }
        ]
    }


def assert_otlp_accepted_through_ingress(
    juju: jubilant.Juju, ingress_app: str, attempts: int = 8
) -> None:
    """Assert that repeated OTLP pushes through the ingress are all accepted.

    This is the only check that exercises the ingress -> otelcol hop. The ingress dials the
    Kubernetes Service, so a backend only some units can serve (e.g. a certificate valid for
    one pod) fails a fraction of the pushes; repeating them stops one lucky hit from passing.

    Only the first push is retried, to let the ingress program its routes. After that a
    failure is a verdict, not a warm-up.
    """
    url = f"{ingress_url(juju, ingress_app)}:{Port.otlp_http.value}/v1/logs"
    headers = {"Content-Type": "application/json"}
    request_with_retry(
        url,
        expected_status=200,
        method="POST",
        data=otlp_logs_payload("ingress warm-up"),
        headers=headers,
    )
    for attempt in range(1, attempts + 1):
        response = requests.post(
            url,
            json=otlp_logs_payload(f"ingress push {attempt}"),
            headers=headers,
            timeout=10,
            verify=False,
        )
        assert response.status_code == 200, (
            f"push {attempt}/{attempts} through {ingress_app} was rejected with "
            f"{response.status_code}: {response.text!r}. The ingress could not deliver to the "
            f"unit that answered it."
        )


def assert_health_reachable_through_ingress(juju: jubilant.Juju, ingress_app: str) -> None:
    """Assert otelcol's health endpoint answers through the ingress."""
    health_service = f"{ingress_url(juju, ingress_app)}:{Port.health.value}"
    response = request_with_retry(health_service, expected_status=200)
    assert '{"status":"Server available"' in response.text, (
        f"{health_service} did not return expected health response"
    )


def assert_loki_logs_accepted_through_ingress(juju: jubilant.Juju, ingress_app: str) -> None:
    """Assert a Loki-format push is accepted through the ingress.

    Requires a relation on `otelcol:receive-loki-logs`, else the receiver is not configured.
    """
    push_api_url = f"{ingress_url(juju, ingress_app)}:{Port.loki_http.value}/loki/api/v1/push"
    data = {
        "streams": [
            {
                "stream": {"label": "value"},
                "values": [
                    [str(time.time_ns()), "log line 1"],
                    [str(time.time_ns()), "log line 2"],
                ],
            }
        ]
    }
    request_with_retry(
        push_api_url,
        expected_status=204,
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )


def assert_otlp_logs_reach_pipeline_through_ingress(
    juju: jubilant.Juju, ingress_app: str, unit: str = "otelcol/leader"
) -> None:
    """Assert an OTLP push through the ingress comes out of `unit`'s log pipeline.

    Asserts on content, so it only holds while `unit` is the only one that can answer: once
    scaled, use `assert_otlp_accepted_through_ingress`. Requires otelcol's
    `debug_exporter_for_logs` config, which writes received logs to the workload's own log.
    """
    identifier = f"+++Testing OTLP ingress {time.time_ns()}+++"
    otlp_http_url = f"{ingress_url(juju, ingress_app)}:{Port.otlp_http.value}/v1/logs"
    request_with_retry(
        otlp_http_url,
        expected_status=200,
        method="POST",
        data=otlp_logs_payload(identifier),
        headers={"Content-Type": "application/json"},
    )
    _assert_identifier_in_pipeline(juju, unit, identifier)


@RETRY
def _assert_identifier_in_pipeline(juju: jubilant.Juju, unit: str, identifier: str) -> None:
    """Assert `identifier` shows up in `unit`'s collector log, retried while it propagates."""
    logs_pipeline = juju.ssh(unit, command="pebble logs -n 1000", container="otelcol")
    assert identifier in logs_pipeline, f"{identifier!r} did not come out of {unit}'s pipeline"


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
