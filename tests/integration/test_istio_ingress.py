# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: otelcol advertises a reachable, load-balanced address when Istio fronts it.

The tests below are one progressive scenario over a single model, in order.
"""

import logging
import time

import jubilant
import pytest
import sh
from helpers import (
    assert_health_reachable_through_ingress,
    assert_loki_logs_accepted_through_ingress,
    assert_no_tls_verification_errors,
    assert_otlp_accepted_through_ingress,
    assert_otlp_logs_reach_pipeline_through_ingress,
    otlp_exporter,
    otlp_exporter_endpoint,
    wait_settled,
)

logger = logging.getLogger(__name__)

# Istio needs a platform override where CNI files are in non-standard locations. MicroK8s is such
# a platform; Canonical K8s is not, hence the charm's default of "".
# https://istio.io/latest/docs/ambient/install/platform-prerequisites/
ISTIO_PLATFORM = {"microk8s": "microk8s", "k8s": ""}

# This is needed for sh.kubectl
# pyright: reportAttributeAccessIssue = false


@pytest.mark.usefixtures("sender_and_sink")
def test_istio_ingress_advertises_the_external_host(juju: jubilant.Juju, preset: str):
    """Scenario: an ingressed otelcol advertises the gateway's host, not the Service."""
    # GIVEN otelcol is fronted by Istio
    juju.deploy("istio-ingress-k8s", "istio-ingress", channel="dev/edge", trust=True)
    platform = ISTIO_PLATFORM[preset]
    juju.deploy(
        "istio-k8s",
        channel="dev/edge",
        trust=True,
        config={"platform": platform} if platform else None,
    )
    juju.integrate("otelcol:istio-ingress", "istio-ingress:istio-ingress-route")
    try:
        wait_settled(juju, "otelcol", "istio-k8s", "istio-ingress", error_on=("otelcol", "sender"))
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

    # THEN the sender targets the gateway's external host, not the in-cluster Service
    endpoint = otlp_exporter_endpoint(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" not in endpoint, (
        f"expected the ingress host in {endpoint!r}, got the in-cluster Service"
    )
    # AND over gRPC, which the gateway routes and the requirer prefers, unlike behind Traefik
    assert endpoint.endswith(":4317"), f"expected gRPC through the gateway, got {endpoint!r}"


@pytest.mark.usefixtures("sender_and_sink")
def test_receivers_are_reachable_through_istio_ingress(juju: jubilant.Juju):
    """Scenario: every receiver otelcol exposes answers through the gateway."""
    # GIVEN otelcol ingests Loki logs, and writes what it receives to its own log
    juju.integrate("sender:send-loki-logs", "otelcol:receive-loki-logs")
    juju.config("otelcol", {"debug_exporter_for_logs": True, "debug_exporter_for_metrics": True})
    wait_settled(juju, "otelcol", "istio-ingress", "sender")

    # THEN the health endpoint answers through the gateway
    assert_health_reachable_through_ingress(juju, "istio-ingress")
    # AND a Loki-format push is accepted through the gateway
    assert_loki_logs_accepted_through_ingress(juju, "istio-ingress")
    # AND an OTLP push comes out of otelcol's pipeline. Asserting on content requires a single
    # unit, so this must run before the scaling test.
    assert_otlp_logs_reach_pipeline_through_ingress(juju, "istio-ingress")

    # AND the sender's own telemetry, sent over gRPC through the gateway, arrives
    logger.info("Waiting for scrape interval (1 minute) to elapse...")
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)
    otelcol_logs = sh.kubectl.logs(
        "otelcol-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    assert "juju_application=sender" in otelcol_logs, (
        "the sender's metrics did not arrive over gRPC through the gateway"
    )


@pytest.mark.usefixtures("sender_and_sink")
def test_scaling_behind_istio_ingress(juju: jubilant.Juju):
    """Scenario: a scaled, ingressed otelcol still targets one, reachable address."""
    # GIVEN the ingressed otelcol from the previous tests
    endpoint_before_scaling = otlp_exporter_endpoint(juju, "sender")

    # WHEN otelcol is scaled out
    juju.add_unit("otelcol", num_units=2)
    wait_settled(juju, "otelcol", "istio-ingress")

    # THEN the sender's config is unchanged: still one endpoint, so scaling out does not
    # multiply what is sent
    assert otlp_exporter_endpoint(juju, "sender") == endpoint_before_scaling

    # AND telemetry pushed at that endpoint is accepted by every unit that answers it
    assert_otlp_accepted_through_ingress(juju, "istio-ingress")


@pytest.mark.usefixtures("sender_and_sink")
def test_scaling_behind_istio_ingress_with_tls(juju: jubilant.Juju):
    """Scenario: a TLS otelcol behind Istio still advertises the gateway, in the gateway's scheme.

    The gateway serves plaintext until it has a certificate of its own, so what otelcol serves
    must not leak into the address senders are given.
    """
    # GIVEN the scaled, Istio-ingressed otelcol from the previous test, now serving TLS
    juju.deploy("self-signed-certificates", "ssc")
    juju.integrate("otelcol:receive-server-cert", "ssc:certificates")
    juju.integrate("sender:receive-ca-cert", "ssc:send-ca-cert")
    wait_settled(juju, "otelcol", "istio-ingress", "ssc", "sender")

    # THEN the sender still targets the gateway, and still in plaintext
    exporter = otlp_exporter(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" not in exporter["endpoint"], (
        f"expected the ingress host in {exporter['endpoint']!r}, got the in-cluster Service"
    )
    assert exporter["tls"]["insecure"] is True, (
        f"expected the sender to reach the gateway in plaintext, got {exporter['tls']}"
    )


@pytest.mark.usefixtures("sender_and_sink")
def test_removing_istio_ingress_falls_back_to_the_service(juju: jubilant.Juju):
    """Scenario: un-ingressing a TLS otelcol falls back to the in-cluster Service."""
    # GIVEN the scaled, TLS otelcol from the previous test
    # WHEN Istio's ingress relation and applications are removed
    juju.remove_relation("otelcol:istio-ingress", "istio-ingress:istio-ingress-route")
    juju.remove_application("istio-ingress")
    juju.remove_application("istio-k8s")
    # An app on its way out can report error, which says nothing about otelcol
    wait_settled(juju, "otelcol", "sender", error_on=("otelcol", "sender"))

    # THEN the sender falls back to the in-cluster Service, over TLS and without certificate
    # errors, since every unit's certificate also covers the Service name
    exporter = otlp_exporter(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" in exporter["endpoint"]
    assert exporter["tls"]["insecure"] is False, (
        f"expected {exporter['endpoint']!r} to be reached over TLS, got {exporter['tls']}"
    )
    assert_no_tls_verification_errors(juju, "sender")
