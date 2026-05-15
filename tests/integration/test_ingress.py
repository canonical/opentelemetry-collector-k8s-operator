# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can operate behind an ingress."""

import logging
import time
from typing import Dict, Optional

import jubilant
import requests
import sh
import yaml
from tenacity import retry, stop_after_attempt, wait_fixed

from src.config_builder import Port
from src.constants import CONFIG_PATH

# This is needed for sh.kubectl
# pyright: reportAttributeAccessIssue = false

logger = logging.getLogger(__name__)

IDENTIFIER = "+++Testing OTLP ingress+++"


def get_ingress_url(juju: jubilant.Juju, app: str) -> str:
    """Get the ingress URL from the ingress app's workload status message."""
    ingress_status = juju.status().apps[app].units[f"{app}/0"].workload_status
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
    """Make an HTTP request with retry logic.

    This follows the pattern used by grafana-k8s-operator for ingress tests.
    Retries help handle transient network issues and timing problems in CI.
    """
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


def health_check_reachable_via_ingress(juju: jubilant.Juju, ingress_app: str):
    """Check that the health endpoint is reachable through the ingress."""
    health_service = f"{get_ingress_url(juju, ingress_app)}:{Port.health.value}"
    response = request_with_retry(health_service, expected_status=200)
    assert '{"status":"Server available"' in response.text, (
        f"{health_service} did not return expected health response"
    )


def push_logs_through_ingress(juju: jubilant.Juju, ingress_app: str):
    """Push Loki-format logs through the ingress."""
    push_api_url = f"{get_ingress_url(juju, ingress_app)}:{Port.loki_http.value}/loki/api/v1/push"
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
    # THEN the logs arrive in the otelcol pipeline
    request_with_retry(
        push_api_url,
        expected_status=204,
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )


def push_otlp_logs_through_ingress(juju: jubilant.Juju, ingress_app: str):
    """Push OTLP-format logs through the ingress."""
    otlp_http_url = f"{get_ingress_url(juju, ingress_app)}:{Port.otlp_http.value}/v1/logs"
    data = {
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
                                "body": {"stringValue": IDENTIFIER},
                                "severityText": "INFO",
                            }
                        ]
                    }
                ],
            }
        ]
    }
    # THEN the logs arrive in the otelcol pipeline
    request_with_retry(
        otlp_http_url,
        expected_status=200,
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    logs_pipeline = juju.ssh("otelcol/leader", command="pebble logs", container="otelcol")
    assert IDENTIFIER in logs_pipeline


def test_health_through_traefik_ingress(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: log forwarding via the LogProxyConsumer."""
    # GIVEN a model with otel-collector and traefik
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy("traefik-k8s", "traefik", channel="latest/stable", trust=True)

    # WHEN otel-collector is related to an ingress provider
    juju.integrate("otelcol:ingress", "traefik")
    juju.wait(jubilant.all_active, timeout=450, error=jubilant.any_error)
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)

    # THEN the health check is reachable through the ingress
    health_check_reachable_via_ingress(juju, "traefik")


def test_push_logs_through_traefik_ingress(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: receive logs via the LokiPushApiProvider through ingress."""
    # GIVEN a model with otel-collector and traefik
    # AND a receive-loki-logs relation

    juju.deploy("opentelemetry-collector-k8s", "otelcol-push", channel="dev/edge", trust=True)
    juju.integrate("otelcol:receive-loki-logs", "otelcol-push")
    juju.wait(
        lambda status: jubilant.all_active(status, "traefik", "otelcol-push"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)
    push_logs_through_ingress(juju, "traefik")


def test_push_otlp_logs_through_traefik_ingress(juju: jubilant.Juju):
    """Scenario: receive OTLP logs via the otlp_http receiver through ingress."""
    # GIVEN a model with otel-collector and traefik
    # WHEN OTLP logs are sent through ingress
    juju.config("otelcol", {"debug_exporter_for_logs": True})
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)
    push_otlp_logs_through_ingress(juju, "traefik")


def test_remove_traefik_ingress(juju: jubilant.Juju):
    # GIVEN a Traefik application is related to otelcol
    # WHEN the Traefik ingress relation and application are removed
    juju.remove_relation("otelcol:ingress", "traefik")
    juju.remove_application("traefik")
    # THEN all applications are active and the otelcol ingress relation is removed
    juju.wait(
        lambda status: jubilant.all_active(status, "otelcol-push"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        timeout=300,
        error=jubilant.any_error,
    )


def test_integrate_istio_ingress(juju: jubilant.Juju, preset: str):
    # GIVEN otelcol is not ingressed
    # WHEN Istio applications are deployed
    juju.deploy("istio-ingress-k8s", channel="dev/edge", trust=True)
    juju.deploy("istio-k8s", channel="dev/edge", trust=True)

    if preset == "k8s":
        # https://canonical-service-mesh-documentation.readthedocs-hosted.com/latest/how-to/use-charmed-istio-with-canonical-kubernetes/
        juju.config("istio-k8s", {"platform": ""})

    # AND integrated with otelcol
    juju.integrate("otelcol:istio-ingress", "istio-ingress-k8s:istio-ingress-route")
    try:
        juju.wait(
            lambda status: jubilant.all_active(
                status, "istio-k8s", "istio-ingress-k8s", "otelcol-push"
            ),
            timeout=300,
        )
    except TimeoutError:
        status = juju.status()
        for unit in status.apps["istio-k8s"].units.values():
            if "platform mismatch" in unit.workload_status.message.lower():
                raise AssertionError(
                    f"istio-k8s unit reports: '{unit.workload_status.message}'. "
                    "If running on Microk8s, re-run with the following pytest flag: "
                    "--preset microk8s"
                ) from None
        raise

    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        timeout=300,
        error=jubilant.any_error,
    )


def test_istio_ingress(juju: jubilant.Juju):
    # THEN the health check is reachable through the Istio ingress
    health_check_reachable_via_ingress(juju, "istio-ingress-k8s")
    # THEN Loki logs are sent through the Istio ingress
    push_logs_through_ingress(juju, "istio-ingress-k8s")
    # THEN OTLP logs are sent through the Istio ingress
    push_otlp_logs_through_ingress(juju, "istio-ingress-k8s")


def test_istio_ingress_grpc(juju: jubilant.Juju):
    # GIVEN the otelcol-push application is related to otelcol for sending OTLP data
    juju.integrate("otelcol:receive-otlp", "otelcol-push:send-otlp")
    juju.config("otelcol", {"debug_exporter_for_metrics": True})
    juju.wait(lambda status: jubilant.all_active(status, "otelcol-push"), timeout=300)
    juju.wait(lambda status: jubilant.all_agents_idle(status, "otelcol-push"), timeout=300)

    # WHEN the OTLP exporter configured uses the gRPC protocol
    config_raw = juju.ssh("otelcol-push/leader", command=f"cat {CONFIG_PATH}", container="otelcol")
    exporters = yaml.safe_load(config_raw)["exporters"]
    assert exporters, "No exporters found in otelcol-push config"
    otlp_exporters = [e for name, e in exporters.items() if name.startswith("otlp/")]
    assert otlp_exporters, "No OTLP exporters found in otelcol-push config"
    assert ":4317" in otlp_exporters[0].get("endpoint", ""), "gRPC is not being used for OTLP"

    # THEN the metrics from otelcol-push are forwarded to otelcol
    logger.info("Waiting for scrape interval (1 minute) to elapse...")
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)
    otelcol_logs = sh.kubectl.logs(
        "otelcol-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    assert "juju_application=otelcol-push" in otelcol_logs
