# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can operate behind an ingress."""

import json
import time
from typing import Dict
from urllib.request import urlopen, Request

import jubilant
import yaml

from src.config_builder import Port


def get_ingress_url(juju: jubilant.Juju) -> str:
    traefik_status = juju.status().apps["traefik"].units["traefik/0"].workload_status
    return traefik_status.message.split()[-1]


def test_health_through_ingress(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: log forwarding via the LogProxyConsumer."""
    # GIVEN a model with otel-collector and traefik
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy("traefik-k8s", "traefik", channel="latest/stable", trust=True)

    # WHEN otel-collector is related to an ingress provider
    juju.integrate("otelcol:ingress", "traefik")
    juju.wait(jubilant.all_active, timeout=450, error=jubilant.any_error)
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)

    # THEN the /health check is reachable through the ingress
    health_service = f"{get_ingress_url(juju)}:{Port.health.value}"

    # THEN the health service is reachable through ingress
    response = urlopen(health_service, timeout=2.0)
    assert response.code == 200, f"{health_service} was not reachable"
    assert '{"status":"Server available"' in response.read().decode(), (
        f"{health_service} did not return expected metrics"
    )


def test_logs_received_through_ingress(juju: jubilant.Juju):
    """Scenario: receive logs via the LokiPushApiProvider through ingress."""
    # GIVEN a model with otel-collector and traefik
    juju.deploy("opentelemetry-collector-k8s", "otelcol-push", channel="2/edge", trust=True)

    # WHEN otel-collector is related to an ingress provider
    juju.integrate("otelcol:receive-loki-logs", "otelcol-push")
    juju.wait(lambda status: jubilant.all_active(status, 'traefik', 'otelcol-push'), timeout=300, error=jubilant.any_error)
    juju.wait(lambda status: jubilant.all_blocked(status, 'otelcol'), timeout=300, error=jubilant.any_error)
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)

    # THEN otel-collector is publishing its ingress address in the databag
    push_show_unit = yaml.safe_load(juju.cli("show-unit", "otelcol-push/0"))["otelcol-push/0"]
    logs_relation = next(
        (item for item in push_show_unit["relation-info"] if item["endpoint"] == "send-loki-logs"),
        None,
    )
    assert logs_relation
    push_api_url = json.loads(logs_relation["related-units"]["otelcol/0"]["data"]["endpoint"])[
        "url"
    ]
    assert push_api_url == f"{get_ingress_url(juju)}:{Port.loki_http.value}/loki/api/v1/push"

    # AND THEN the logs arrive in the otelcol pipeline
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
    assert response.getcode() == 204
