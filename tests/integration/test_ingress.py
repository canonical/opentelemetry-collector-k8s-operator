# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can operate behind an ingress."""

import json
from typing import Dict
from urllib.request import urlopen

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
    juju.wait(jubilant.all_active, timeout=300, error=jubilant.any_error)

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
    juju.wait(jubilant.all_active, timeout=300, error=jubilant.any_error)

    # THEN otel-collector is publishing its ingress address in the databag
    # TODO: [1] is brittle, we could access list by object key search
    push_show_unit = yaml.safe_load(juju.cli("show-unit", "otelcol-push/0"))
    logs_relation = push_show_unit["otelcol-push/0"]["relation-info"][1]
    push_api_url = json.loads(logs_relation["related-units"]["otelcol/0"]["data"]["endpoint"])[
        "url"
    ]
    assert push_api_url == f"{get_ingress_url(juju)}/loki/api/v1/push"

    # AND THEN the logs arrive in the otelcol pipeline
    # TODO: add this
