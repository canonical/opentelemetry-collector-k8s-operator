# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: A scaled otelcol shares incoming telemetry instead of duplicating it."""

import logging
from typing import Dict, List

import jubilant
import yaml
from helpers import RETRY

from src.constants import CONFIG_PATH

logger = logging.getLogger(__name__)

# pyright: reportAttributeAccessIssue = false


def _otlp_exporter_endpoints(juju: jubilant.Juju, sender: str) -> List[str]:
    """Return the OTLP exporter endpoints in the sender's rendered collector config.

    This is the ground truth for the duplication bug: one exporter per destination means
    each payload is sent once, whereas one exporter per receiving unit means the same
    payload is sent N times.
    """
    config_raw = juju.ssh(f"{sender}/leader", command=f"cat {CONFIG_PATH}", container="otelcol")
    exporters = yaml.safe_load(config_raw).get("exporters") or {}
    return [
        exporter["endpoint"]
        for name, exporter in exporters.items()
        if name.startswith("otlp/") and "endpoint" in exporter
    ]


@RETRY
def _assert_single_load_balanced_exporter(
    juju: jubilant.Juju, receiver: str, sender: str
) -> None:
    """Assert the sender targets the receiver's K8s Service exactly once."""
    endpoints = _otlp_exporter_endpoints(juju, sender)
    assert endpoints, f"{sender} configured no OTLP exporters"

    service_fqdn = f"{receiver}.{juju.model}.svc.cluster.local"
    assert len(set(endpoints)) == 1, (
        f"{sender} targets {len(set(endpoints))} distinct endpoints, so telemetry is "
        f"duplicated rather than load-balanced: {sorted(set(endpoints))}"
    )
    # A per-pod headless address (`<app>-0.<app>-endpoints...`) is published once per unit,
    # which is exactly what made a scaled otelcol receive every payload N times.
    assert service_fqdn in endpoints[0], (
        f"expected the K8s Service name in {endpoints[0]!r}, got a per-unit address"
    )
    assert "-endpoints." not in endpoints[0], (
        f"{endpoints[0]!r} is a per-pod headless address, not the K8s Service"
    )


def test_scaling_does_not_duplicate_telemetry(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: scaling the receiver must not multiply what the sender transmits."""
    # GIVEN a single-unit otelcol receiving OTLP from another otelcol
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy(charm, "sender", resources=charm_resources, trust=True)
    juju.deploy(charm, "sink", resources=charm_resources, trust=True)
    juju.integrate("sender:send-otlp", "otelcol:receive-otlp")
    # An incoming relation must be paired with an outgoing one, or the charm blocks on
    # missing mandatory relations; give otelcol somewhere to forward what it receives.
    juju.integrate("otelcol:send-otlp", "sink:receive-otlp")
    juju.wait(
        lambda status: jubilant.all_active(status, "otelcol", "sender"),
        timeout=900,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=600, error=jubilant.any_error)

    # THEN the sender targets the Kubernetes Service
    _assert_single_load_balanced_exporter(juju, receiver="otelcol", sender="sender")
    endpoints_at_one_unit = set(_otlp_exporter_endpoints(juju, "sender"))

    # AND WHEN otelcol is scaled out
    juju.add_unit("otelcol", num_units=2)
    juju.wait(
        lambda status: jubilant.all_active(status, "otelcol"),
        timeout=900,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=600, error=jubilant.any_error)

    # THEN the sender's config is unchanged: still one endpoint, so each payload is sent
    # once and Kubernetes spreads it over the units instead of it being duplicated
    _assert_single_load_balanced_exporter(juju, receiver="otelcol", sender="sender")
    assert set(_otlp_exporter_endpoints(juju, "sender")) == endpoints_at_one_unit

    # AND scaling without ingress no longer blocks the charm
    assert jubilant.all_active(juju.status(), "otelcol")


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
    juju.wait(
        lambda status: jubilant.all_active(status, "otelcol", "ssc", "sender"),
        timeout=900,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=600, error=jubilant.any_error)

    # THEN the sender still targets the Service name, now over TLS
    _assert_single_load_balanced_exporter(juju, receiver="otelcol", sender="sender")

    # AND the sender reaches it without certificate errors, whichever unit it lands on.
    # Without the widened SANs this fails hostname verification, since the certificate
    # would only be valid for the pod that happened to serve the request.
    _assert_no_tls_verification_errors(juju, "sender")


@RETRY
def _assert_no_tls_verification_errors(juju: jubilant.Juju, sender: str) -> None:
    logs = juju.ssh(f"{sender}/leader", command="pebble logs -n 1000", container="otelcol")
    assert "tls: failed to verify certificate" not in logs, (
        f"{sender} could not verify the receiver's certificate for the K8s Service name"
    )
