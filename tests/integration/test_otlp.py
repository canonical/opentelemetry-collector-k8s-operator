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


def test_otlp_forwarding(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: OTLP forwarding via the OtlpProvider and OtlpConsumer classes."""
    # GIVEN a model with 2 local otel-collector charms
    # TODO: Add a test: one packed and one from charmhub to test different versions of the OTLP lib
    juju.deploy(charm, "otelcol-one", resources=charm_resources, trust=True)
    juju.deploy(charm, "otelcol-two", resources=charm_resources, trust=True)

    # WHEN "one" is related to "two" over the OTLP endpoints
    juju.integrate("otelcol-one:send-otlp", "otelcol-two:receive-otlp")
    juju.config("otelcol-two", {"debug_exporter_for_metrics": True})
    juju.wait(jubilant.all_active, timeout=450, error=jubilant.any_error)
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
