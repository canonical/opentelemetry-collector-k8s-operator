# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol forwards OTLP data."""

import logging
import time
from typing import Dict

import jubilant
import sh

# This is needed for sh.juju
# pyright: reportAttributeAccessIssue = false

logger = logging.getLogger(__name__)


def get_ingress_url(juju: jubilant.Juju) -> str:
    traefik_status = juju.status().apps["traefik"].units["traefik/0"].workload_status
    return traefik_status.message.split()[-1]


def test_otlp_forwarding_insecure(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: OTLP forwarding via the OtlpProvider and OtlpConsumer classes."""
    # GIVEN a model with 2 local otel-collector charms
    # TODO: Add a test: one packed and one from charmhub to test different versions of the OTLP lib
    juju.deploy(charm, "otelcol-one", resources=charm_resources, trust=True)
    juju.deploy(charm, "otelcol-two", resources=charm_resources, trust=True)
    juju.config("otelcol-two", {"debug_exporter_for_metrics": True})

    # WHEN "one" is related to "two" over the OTLP endpoints
    juju.integrate("otelcol-one:send-otlp", "otelcol-two:receive-otlp")
    juju.wait(
        lambda status: jubilant.all_active(status, "otelcol-one"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol-two"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)

    logger.info("Waiting for scrape interval (1 minute) to elapse...")
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)

    # THEN the metrics from otelcol-one are forwarded to otelcol-two
    otelcol_two_logs = sh.kubectl.logs(
        "otelcol-two-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    assert "juju_application=otelcol-one" in otelcol_two_logs


def test_otlp_forwarding_secure(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: OTLP forwarding with TLS."""
    # GIVEN a model with 2 local otel-collector charms
    # WHEN "one" is related to "two" over the OTLP endpoints
    juju.deploy("self-signed-certificates", "ssc")
    juju.integrate("otelcol-two:receive-server-cert", "ssc:certificates")
    juju.wait(
        lambda status: jubilant.all_active(status, "ssc", "otelcol-one"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol-two"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)

    logger.info("Waiting for scrape interval (1 minute) to elapse...")
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)

    # THEN OTLP forwarding fails since otelcol-one does not trust otelcol-two's cert
    otelcol_one_logs = sh.kubectl.logs(
        "otelcol-one-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    otelcol_two_logs = sh.kubectl.logs(
        "otelcol-two-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    assert "tls: failed to verify certificate" in otelcol_one_logs
    assert "juju_application=otelcol-one" not in otelcol_two_logs

    # AND WHEN otelcol-one is related to the certificate authority
    juju.integrate("otelcol-one:receive-ca-cert", "ssc:send-ca-cert")
    juju.wait(
        lambda status: jubilant.all_active(status, "ssc", "otelcol-one"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol-two"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)

    logger.info("Waiting for scrape interval (1 minute) to elapse...")
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)

    # THEN OTLP forwarding succeeds since otelcol-one trusts otelcol-two's cert
    otelcol_one_logs = sh.kubectl.logs(
        "otelcol-one-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    otelcol_two_logs = sh.kubectl.logs(
        "otelcol-two-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    assert "tls: failed to verify certificate" not in otelcol_one_logs
    assert "juju_application=otelcol-one" in otelcol_two_logs
