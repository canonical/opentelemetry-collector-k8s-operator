# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol forwards OTLP data."""

import logging
import time
from typing import Dict

import jubilant

# This is needed for sh.juju
# pyright: reportAttributeAccessIssue = false

logger = logging.getLogger(__name__)


def get_ingress_url(juju: jubilant.Juju) -> str:
    traefik_status = juju.status().apps["traefik"].units["traefik/0"].workload_status
    return traefik_status.message.split()[-1]


def test_otlp_forwarding_insecure(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: OTLP forwarding via the OtlpProvider and OtlpRequirer classes."""
    # GIVEN a model with 2 local otel-collector charms
    juju.deploy(charm, "requirer", resources=charm_resources, trust=True)
    juju.deploy(charm, "provider", resources=charm_resources, trust=True)

    # AND the provider is configured to export metrics, logs, and traces for debugging purposes
    juju.config("provider",
        {"debug_exporter_for_metrics": True})

    # AND a `flog` which generates fake logs and sends them to the `requirer`
    juju.deploy("flog-k8s", "flog", channel="latest/edge", trust=True)
    juju.integrate("flog", "requirer")

    # AND a Grafana which sends its traces to the `requirer`
    juju.deploy("grafana-k8s", "grafana", channel="dev/edge", trust=True)
    juju.integrate("grafana:charm-tracing", "requirer")

    # WHEN "one" is related to "two" over the OTLP endpoints
    juju.integrate("requirer:send-otlp", "provider:receive-otlp")
    juju.wait(
        lambda status: jubilant.all_active(status, "requirer"),
        timeout=300,
        error=jubilant.any_error,
    )
    # The provider will be blocked because it's not forwarding the telemetry it receives to any backends in this itest.
    juju.wait(
        lambda status: jubilant.all_blocked(status, "provider"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)

    logger.info("Waiting for scrape interval (1 minute) to elapse...")
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)

    # AND WHEN we check the provider logs for forwarded OTLP data from requirer
    provider_logs = juju.ssh(
        target="provider/0", container="otelcol", command="pebble logs -n 250"
    )

    # THEN the metrics from requirer are forwarded to provider
    # These metrics are coming from the requirer, and Otelcol's self metrics are guaranteed to have the strings below
    assert any(
        "juju_application=requirer" in line
        and "otelcol_" in line
        and "service.version=" in line
        for line in provider_logs.splitlines()
    ), "Expected at least one forwarded `requirer` metric entry in provider logs"
    logger.info("Successfully found forwarded `requirer` metrics in provider logs")

    juju.config("provider",
        {"debug_exporter_for_metrics": False,
        "debug_exporter_for_logs": True})
    time.sleep(20)  # wait for config to propagate and logs to be forwarded
    # AND there must be one log whose Juju Topology belongs to Flog
    # Flog always has these strings in the fake logs it generates
    provider_logs = juju.ssh(
        target="provider/0", container="otelcol", command="pebble logs"
    )

    assert any(
        "juju_application=flog" in line
        and "filename=/bin/fake.log" in line
        and '"method":' in line
        and '"request":' in line
        and '"status":' in line
        for line in provider_logs.splitlines()
    ), "Expected at least one forwarded `flog` log entry in provider logs"
    logger.info("Successfully found forwarded `flog` logs in provider logs")

    # We integrate `grafana` with the `provider` to elicit some trace data that we can verify in the provider logs
    juju.integrate("grafana", "requirer:grafana-dashboards-provider")

    juju.config("provider",
        {"debug_exporter_for_logs": False,
        "debug_exporter_for_traces": True})
    time.sleep(60)  # wait for config to propagate and logs to be forwarded

    # AND there must be one trace whose Juju Topology belongs to Grafana
    provider_logs = juju.ssh(
        target="provider/0", container="otelcol", command="pebble logs -n 250"
    )
    assert any(
        "juju_application=graf" in line
        and "charm_type=GrafanaCharm" in line
        and "ResourceTraces" in line
        for line in provider_logs.splitlines()
    ), "Expected at least one forwarded `grafana` trace entry in provider logs"
    logger.info("Successfully found forwarded `grafana` trace in provider logs")

