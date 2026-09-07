# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: otelcol advertises a reachable, load-balanced address when nothing fronts it.

The tests below are one progressive scenario over a single model, in order.
"""

import logging

import jubilant
import pytest
from helpers import (
    assert_no_tls_verification_errors,
    otlp_exporter,
    otlp_exporter_endpoint,
    wait_settled,
)

logger = logging.getLogger(__name__)

# pyright: reportAttributeAccessIssue = false


@pytest.mark.usefixtures("sender_and_sink")
def test_scaling_does_not_duplicate_telemetry(juju: jubilant.Juju):
    """Scenario: scaling the receiver must not multiply what the sender transmits."""
    # GIVEN a single-unit otelcol receiving OTLP from another otelcol
    # THEN the sender targets otelcol's Kubernetes Service
    service_fqdn = f"otelcol.{juju.model}.svc.cluster.local"
    endpoint_at_one_unit = otlp_exporter_endpoint(juju, "sender")
    assert service_fqdn in endpoint_at_one_unit, (
        f"expected the K8s Service name in {endpoint_at_one_unit!r}, got a per-unit address"
    )
    # A per-pod headless address (`<app>-0.<app>-endpoints...`) is published once per unit,
    # which is what made a scaled otelcol receive every payload N times.
    assert "-endpoints." not in endpoint_at_one_unit, (
        f"{endpoint_at_one_unit!r} is a per-pod headless address, expected the K8s Service"
    )

    # AND WHEN otelcol is scaled out
    juju.add_unit("otelcol", num_units=2)
    wait_settled(juju, "otelcol")

    # THEN the sender's config is unchanged: still one endpoint, so each payload is sent once
    # and Kubernetes spreads it over the units instead of it being duplicated
    assert otlp_exporter_endpoint(juju, "sender") == endpoint_at_one_unit


@pytest.mark.usefixtures("sender_and_sink")
def test_every_unit_serves_tls_for_the_shared_address(juju: jubilant.Juju):
    """Scenario: any unit may terminate a connection made to the K8s Service.

    Requests to the Service land on an arbitrary unit, so each unit's certificate must
    cover the Service name or verification fails intermittently once scaled.
    """
    # GIVEN the scaled otelcol from the previous test, now serving TLS
    juju.deploy("self-signed-certificates", "ssc")
    juju.integrate("otelcol:receive-server-cert", "ssc:certificates")
    juju.integrate("sender:receive-ca-cert", "ssc:send-ca-cert")
    wait_settled(juju, "otelcol", "ssc", "sender")

    # THEN the sender still targets the Service name, now over TLS. gRPC wins without an
    # ingress, and gRPC endpoints carry no scheme, hence the `insecure` check.
    exporter = otlp_exporter(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" in exporter["endpoint"]
    assert exporter["tls"]["insecure"] is False, (
        f"expected {exporter['endpoint']!r} to be reached over TLS, got {exporter['tls']}"
    )

    # AND the sender reaches it without certificate errors, whichever unit it lands on
    assert_no_tls_verification_errors(juju, "sender")
