# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can operate behind an ingress."""

import json
import logging
import time
from typing import Dict
from urllib.request import Request, urlopen

import jubilant
import sh
import yaml

from src.config_builder import Port
from src.constants import CONFIG_PATH

# This is needed for sh.kubectl
# pyright: reportAttributeAccessIssue = false

logger = logging.getLogger(__name__)

IDENTIFIER = "+++Testing OTLP ingress+++"


def get_ingress_url(juju: jubilant.Juju, app: str) -> str:
    ingress_status = juju.status().apps[app].units[f"{app}/0"].workload_status
    address = ingress_status.message.split()[-1]
    if not address.startswith("http://"):
        address = f"http://{address}"
    return address


def health_check_reachable_via_ingress(juju: jubilant.Juju, ingress_app: str):
    health_service = f"{get_ingress_url(juju, ingress_app)}:{Port.health.value}"
    response = urlopen(health_service, timeout=2.0)
    assert response.code == 200, f"{health_service} was not reachable"
    assert '{"status":"Server available"' in response.read().decode(), (
        f"{health_service} did not return expected metrics"
    )


def push_logs_through_ingress(juju: jubilant.Juju, ingress_app: str):
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
    req = Request(
        push_api_url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    response = urlopen(req, timeout=2.0)

    # THEN the logs arrive in the otelcol pipeline
    assert response.getcode() == 204


def push_otlp_logs_through_ingress(juju: jubilant.Juju, ingress_app: str):
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
    req = Request(
        otlp_http_url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    response = urlopen(req, timeout=2.0)

    # THEN the logs arrive in the otelcol pipeline
    assert response.getcode() == 200
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

    # TODO: Replace this with a CharmHub otelcol
    # juju.deploy("opentelemetry-collector-k8s", "otelcol-push", channel="dev/edge", trust=True)
    juju.deploy(charm, "otelcol-push", resources=charm_resources, trust=True)
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


def test_integrate_istio_ingress(juju: jubilant.Juju):
    # GIVEN otelcol is not ingressed
    # WHEN Istio applications are deployed
    juju.deploy("istio-ingress-k8s", channel="dev/edge", trust=True)
    juju.deploy("istio-k8s", channel="dev/edge", trust=True)

    # For devs using Canonical Kubernetes, set `juju config istio-k8s platform=""`
    # https://canonical-service-mesh-documentation.readthedocs-hosted.com/latest/how-to/use-charmed-istio-with-canonical-kubernetes/

    # AND integrated with otelcol
    juju.integrate("otelcol:istio-ingress", "istio-ingress-k8s:istio-ingress-route")
    juju.wait(
        lambda status: jubilant.all_active(
            status, "istio-k8s", "istio-ingress-k8s", "otelcol-push"
        ),
        timeout=300,
    )
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
