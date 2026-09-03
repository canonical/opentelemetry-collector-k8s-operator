# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: A scaled up otelcol shares incoming telemetry."""

import logging
from typing import Dict

import jubilant
import yaml
from helpers import RETRY

from src.constants import CONFIG_PATH

logger = logging.getLogger(__name__)

# pyright: reportAttributeAccessIssue = false


@RETRY
def otlp_exporter_endpoint(juju: jubilant.Juju, sender: str) -> str:
    """Return the single OTLP exporter endpoint in the sender's rendered collector config.

    This is the ground truth for the duplication bug: one exporter per destination means
    each payload is sent once, whereas one exporter per receiving unit means the same
    payload is sent N times. Retried because the config is rewritten asynchronously.
    """
    config_raw = juju.ssh(f"{sender}/leader", command=f"cat {CONFIG_PATH}", container="otelcol")
    exporters = yaml.safe_load(config_raw).get("exporters") or {}
    # Behind Traefik (no gRPC support) only the "otlphttp/..." exporter is configured, so
    # both prefixes must be matched, otherwise an ingressed sender looks like it has none.
    endpoints = {
        exporter["endpoint"]
        for name, exporter in exporters.items()
        if name.startswith(("otlp/", "otlphttp/")) and "endpoint" in exporter
    }
    assert len(endpoints) == 1, (
        f"expected {sender} to target exactly one endpoint, got {sorted(endpoints)}"
    )
    return endpoints.pop()


def wait_settled(juju: jubilant.Juju, *apps: str) -> None:
    """Wait until the given apps are active AND every agent is idle, at the same time.

    Waiting for the two conditions one after the other is not the same thing: a unit can be
    active while an agent is still mid-hook that will take it out of active again, so the
    first wait returns on a state the second never rechecks. Scaling makes that window wide,
    because the new pods re-run the resources patch and briefly put the application back into
    waiting.

    `successes` requires the combined condition to hold over that many consecutive polls, so a
    deployment that is still churning does not end the wait early.
    """
    juju.wait(
        lambda status: jubilant.all_active(status, *apps) and jubilant.all_agents_idle(status),
        timeout=900,
        successes=10,
        error=jubilant.any_error,
    )


@RETRY
def assert_no_tls_verification_errors(juju: jubilant.Juju, sender: str) -> None:
    """Assert the sender's collector logs contain no certificate verification failures."""
    logs = juju.ssh(f"{sender}/leader", command="pebble logs -n 1000", container="otelcol")
    assert "tls: failed to verify certificate" not in logs, (
        f"{sender} could not verify the receiver's certificate for the K8s Service name"
    )


def test_scaling_without_ingress_does_not_duplicate_telemetry(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: scaling the receiver must not multiply what the sender transmits."""
    # GIVEN a single-unit otelcol receiving OTLP from another otelcol
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy(charm, "sender", resources=charm_resources, trust=True)
    # `sink` is a stand-in backend and is not part of what we assert on. It exists only
    # because an incoming relation must be paired with an outgoing one, otherwise otelcol
    # blocks on missing mandatory relations and never reaches an active status.
    juju.deploy(charm, "sink", resources=charm_resources, trust=True)
    juju.integrate("sender:send-otlp", "otelcol:receive-otlp")
    juju.integrate("otelcol:send-otlp", "sink:receive-otlp")
    wait_settled(juju, "otelcol", "sender")

    # THEN the sender targets otelcol's Kubernetes Service
    service_fqdn = f"otelcol.{juju.model}.svc.cluster.local"
    endpoint_at_one_unit = otlp_exporter_endpoint(juju, "sender")
    assert service_fqdn in endpoint_at_one_unit, (
        f"expected the K8s Service name in {endpoint_at_one_unit!r}, got a per-unit address"
    )
    # A per-pod headless address (`<app>-0.<app>-endpoints...`) is published once per unit,
    # which is exactly what made a scaled otelcol receive every payload N times.
    assert "-endpoints." not in endpoint_at_one_unit, (
        f"{endpoint_at_one_unit!r} is a per-pod headless address, expected the K8s Service"
    )

    # AND WHEN otelcol is scaled out
    juju.add_unit("otelcol", num_units=2)
    # THEN scaling without ingress leaves the charm active, and it stays that way: settling
    # only to drop out of active again would be just as much of a bug as never settling.
    wait_settled(juju, "otelcol")

    # AND the sender's config is unchanged: still that one endpoint, so each payload is
    # sent once and Kubernetes spreads it over the units instead of it being duplicated
    assert otlp_exporter_endpoint(juju, "sender") == endpoint_at_one_unit


def test_every_unit_serves_tls_for_the_shared_address(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: any unit may terminate a connection made to the K8s Service.

    Requests to the Service land on an arbitrary unit, so each unit's certificate must
    cover the Service name or verification fails intermittently once scaled.
    """
    # GIVEN the scaled otelcol from the previous test, now serving TLS
    juju.deploy("self-signed-certificates", "ssc")
    juju.integrate("otelcol:receive-server-cert", "ssc:certificates")
    juju.integrate("sender:receive-ca-cert", "ssc:send-ca-cert")
    wait_settled(juju, "otelcol", "ssc", "sender")

    # THEN the sender still targets the Service name, now over TLS
    endpoint = otlp_exporter_endpoint(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" in endpoint

    # AND the sender reaches it without certificate errors, whichever unit it lands on.
    # Without the widened SANs this fails hostname verification, since the certificate
    # would only be valid for the pod that happened to serve the request.
    assert_no_tls_verification_errors(juju, "sender")
