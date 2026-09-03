# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: A scaled up, ingressed otelcol advertises a reachable, load-balanced address.

This complements test_scaling.py (no ingress) by covering the same duplication and
certificate-verification concerns once Traefik or Istio sit in front of otelcol. The
receiving otelcol's advertised address must switch to the ingress's external host,
still resolve to a single endpoint once scaled, and (when TLS is enabled) be verifiable
regardless of which unit answers the request.
"""

import logging
from typing import Dict

import jubilant
import pytest

from test_scaling import (
    assert_no_tls_verification_errors,
    otlp_exporter_endpoint,
    wait_settled,
)

logger = logging.getLogger(__name__)

# pyright: reportAttributeAccessIssue = false


def deploy_traefik_ingress(juju: jubilant.Juju) -> None:
    """Deploy Traefik and integrate it with otelcol's ingress endpoint."""
    juju.deploy("traefik-k8s", "traefik", channel="latest/stable", trust=True)
    juju.integrate("otelcol:ingress", "traefik")
    wait_settled(juju, "otelcol", "traefik")


def deploy_istio_ingress(juju: jubilant.Juju, preset: str) -> None:
    """Deploy Istio and integrate it with otelcol's istio-ingress endpoint."""
    juju.deploy("istio-ingress-k8s", "istio-ingress", channel="dev/edge", trust=True)
    juju.deploy("istio-k8s", channel="dev/edge", trust=True)
    if preset == "k8s":
        # https://canonical-service-mesh-documentation.readthedocs-hosted.com/latest/how-to/use-charmed-istio-with-canonical-kubernetes/
        juju.config("istio-k8s", {"platform": ""})
    juju.integrate("otelcol:istio-ingress", "istio-ingress:istio-ingress-route")
    wait_settled(juju, "otelcol", "istio-k8s", "istio-ingress")


@pytest.fixture
def sender_and_sink(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Deploy otelcol plus a sender and a sink, and wire sender -> otelcol -> sink.

    `sink` is a stand-in backend and is not part of what tests assert on. It exists only
    because an incoming relation must be paired with an outgoing one, otherwise otelcol
    blocks on missing mandatory relations and never reaches an active status.
    """
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy(charm, "sender", resources=charm_resources, trust=True)
    juju.deploy(charm, "sink", resources=charm_resources, trust=True)
    juju.integrate("sender:send-otlp", "otelcol:receive-otlp")
    juju.integrate("otelcol:send-otlp", "sink:receive-otlp")
    # `sink` stays blocked forever: it is a bare otelcol whose own receive-otlp relation
    # (from the collector it fronts) has no outgoing relation to pair with. That is
    # expected and mirrors test_scaling.py, which does not wait on it either.
    wait_settled(juju, "otelcol", "sender")


@pytest.mark.usefixtures("sender_and_sink")
def test_scaling_behind_traefik_ingress_without_tls(juju: jubilant.Juju):
    """Scenario: an ingressed, scaled otelcol still targets one, reachable address."""
    # GIVEN otelcol is fronted by Traefik
    deploy_traefik_ingress(juju)

    # THEN the sender targets Traefik's external host, not the in-cluster Service
    endpoint_before_scaling = otlp_exporter_endpoint(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" not in endpoint_before_scaling, (
        f"expected the ingress host in {endpoint_before_scaling!r}, got the in-cluster Service"
    )

    # AND WHEN otelcol is scaled out
    juju.add_unit("otelcol", num_units=2)
    # THEN scaling behind Traefik leaves the charm active, and it stays that way
    wait_settled(juju, "otelcol", "traefik")

    # AND the sender's config is unchanged: still that one endpoint, so scaling out does
    # not multiply what is sent, and Traefik keeps load-balancing across the new units
    assert otlp_exporter_endpoint(juju, "sender") == endpoint_before_scaling


def test_scaling_behind_traefik_ingress_with_tls(juju: jubilant.Juju):
    """Scenario: any otelcol unit behind Traefik must serve TLS for the ingress host.

    Traefik verifies the hostname of the backend it connects to, and connects to an
    arbitrary unit, so every unit's certificate must be valid for the address Traefik
    was given.
    """
    # GIVEN the scaled, Traefik-ingressed otelcol from the previous test, now serving TLS
    juju.deploy("self-signed-certificates", "ssc")
    juju.integrate("otelcol:receive-server-cert", "ssc:certificates")
    juju.integrate("sender:receive-ca-cert", "ssc:send-ca-cert")
    wait_settled(juju, "otelcol", "traefik", "ssc", "sender")

    # THEN the sender still targets Traefik's external host, now over TLS
    endpoint = otlp_exporter_endpoint(juju, "sender")
    assert "https://" in endpoint or ":443" not in endpoint

    # AND the sender reaches it without certificate errors, whichever unit answers
    assert_no_tls_verification_errors(juju, "sender")

    # AND WHEN Traefik and its ingress relation are removed
    juju.remove_relation("otelcol:ingress", "traefik")
    juju.remove_application("traefik")
    wait_settled(juju, "otelcol", "sender")

    # THEN the sender falls back to the in-cluster Service, still over TLS and without
    # certificate errors, since every unit's certificate also covers the Service name
    endpoint = otlp_exporter_endpoint(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" in endpoint
    assert_no_tls_verification_errors(juju, "sender")


@pytest.mark.usefixtures("sender_and_sink")
def test_scaling_behind_istio_ingress_without_tls(juju: jubilant.Juju, preset: str):
    """Scenario: an Istio-ingressed, scaled otelcol still targets one, reachable address."""
    # GIVEN otelcol is fronted by Istio
    deploy_istio_ingress(juju, preset)

    # THEN the sender targets Istio's external host, not the in-cluster Service
    endpoint_before_scaling = otlp_exporter_endpoint(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" not in endpoint_before_scaling, (
        f"expected the ingress host in {endpoint_before_scaling!r}, got the in-cluster Service"
    )

    # AND WHEN otelcol is scaled out
    juju.add_unit("otelcol", num_units=2)
    # THEN scaling behind Istio leaves the charm active, and it stays that way
    wait_settled(juju, "otelcol", "istio-ingress")

    # AND the sender's config is unchanged: still that one endpoint, so scaling out does
    # not multiply what is sent, and Istio keeps load-balancing across the new units
    assert otlp_exporter_endpoint(juju, "sender") == endpoint_before_scaling


def test_scaling_behind_istio_ingress_with_tls(juju: jubilant.Juju):
    """Scenario: any otelcol unit behind Istio must serve TLS for the ingress host.

    Istio, like Traefik, may route a request to an arbitrary unit, so every unit's
    certificate must be valid for the address advertised to senders.
    """
    # GIVEN the scaled, Istio-ingressed otelcol from the previous test, now serving TLS
    juju.deploy("self-signed-certificates", "ssc")
    juju.integrate("otelcol:receive-server-cert", "ssc:certificates")
    juju.integrate("sender:receive-ca-cert", "ssc:send-ca-cert")
    wait_settled(juju, "otelcol", "istio-ingress", "ssc", "sender")

    # THEN the sender still targets Istio's external host, now over TLS
    endpoint = otlp_exporter_endpoint(juju, "sender")
    assert "https://" in endpoint or ":443" not in endpoint

    # AND the sender reaches it without certificate errors, whichever unit answers
    assert_no_tls_verification_errors(juju, "sender")

    # AND WHEN Istio's ingress relation and applications are removed
    juju.remove_relation("otelcol:istio-ingress", "istio-ingress:istio-ingress-route")
    juju.remove_application("istio-ingress")
    juju.remove_application("istio-k8s")
    wait_settled(juju, "otelcol", "sender")

    # THEN the sender falls back to the in-cluster Service, still over TLS and without
    # certificate errors, since every unit's certificate also covers the Service name
    endpoint = otlp_exporter_endpoint(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" in endpoint
    assert_no_tls_verification_errors(juju, "sender")
