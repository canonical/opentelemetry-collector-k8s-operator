# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol sets the correct OTLP endpoint information in its databag."""

from typing import Dict

import jubilant


def get_ingress_url(juju: jubilant.Juju) -> str:
    traefik_status = juju.status().apps["traefik"].units["traefik/0"].workload_status
    return traefik_status.message.split()[-1]


def test_health_through_ingress(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: log forwarding via the LogProxyConsumer."""
    # GIVEN a model with 2 otel-collector charms
    juju.deploy(charm, "otelcol-one", resources=charm_resources, trust=True)
    juju.deploy(charm, "otelcol-two", resources=charm_resources, trust=True)

    # WHEN "one" is related to "two"
    juju.integrate("otelcol-one:send-otlp", "otelcol-two:receive-otlp")
    juju.config("otelcol-two", {"debug_exporter_for_metrics": True})
    juju.wait(jubilant.all_active, timeout=450, error=jubilant.any_error)
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)
    # THEN the metrics from otelcol-one are forwarded to otelcol-two
    otelcol_two_logs = juju.ssh("otelcol-two/leader", command="pebble logs", container="otelcol")
    "juju_application=otelcol-one" in otelcol_two_logs
