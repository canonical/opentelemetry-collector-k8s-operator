# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol forwards OTLP data."""

import logging
from typing import Dict

from tenacity import (
    after_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

import jubilant


logger = logging.getLogger(__name__)

RETRY = retry(
    retry=retry_if_exception_type(AssertionError),
    wait=wait_exponential(multiplier=1, min=2, max=45),
    stop=stop_after_attempt(10),
    after=after_log(logger, logging.INFO),
)


def test_otlp_setup(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Common setup for OTLP forwarding tests."""
    # GIVEN a model with 2 local otel-collector charms
    juju.deploy(charm, "requirer", resources=charm_resources, trust=True)
    juju.deploy(charm, "provider", resources=charm_resources, trust=True)

    # AND a `flog` which generates fake logs and sends them to the `requirer`
    juju.deploy("flog-k8s", "flog", channel="latest/edge", trust=True)
    juju.integrate("flog:log-proxy", "requirer")

    # AND a Grafana which sends its traces to the `requirer`
    juju.deploy("grafana-k8s", "grafana", channel="dev/edge", trust=True)
    juju.integrate("grafana:charm-tracing", "requirer")

    # WHEN the requirer is related to the provider over the OTLP endpoints
    juju.integrate("requirer:send-otlp", "provider:receive-otlp")
    juju.wait(
        lambda status: jubilant.all_active(status, "requirer"),
        timeout=300,
        error=jubilant.any_error,
    )
    # THEN the provider is blocked because it's not forwarding the telemetry it receives to any backends
    juju.wait(
        lambda status: jubilant.all_blocked(status, "provider"),
        timeout=300,
        error=jubilant.any_error,
    )
    juju.wait(jubilant.all_agents_idle, timeout=300, error=jubilant.any_error)


def test_otlp_forwarding_metrics(juju: jubilant.Juju):
    """Scenario: OTLP metrics are forwarded from requirer to provider."""
    # GIVEN the provider is configured to export metrics for debugging
    juju.config("provider", {"debug_exporter_for_metrics": True})

    # WHEN we check the provider logs for forwarded metrics
    @RETRY
    def check_metrics():
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

    check_metrics()


def test_otlp_forwarding_logs(juju: jubilant.Juju):
    """Scenario: OTLP logs are forwarded from flog to provider."""
    # GIVEN the provider is configured to export logs for debugging
    juju.config("provider", {"debug_exporter_for_metrics": False, "debug_exporter_for_logs": True})

    # WHEN we check the provider logs for forwarded flog logs
    @RETRY
    def check_logs():
        provider_logs = juju.ssh(
            target="provider/0", container="otelcol", command="pebble logs -n 250"
        )
        # THEN there must be one log whose Juju Topology belongs to Flog
        # Flog always has these strings in the fake logs it generates
        assert any(
            "juju_application=flog" in line
            and "filename=/bin/fake.log" in line
            for line in provider_logs.splitlines()
        ), "Expected at least one forwarded `flog` log entry in provider logs"

    check_logs()


def test_otlp_forwarding_traces(juju: jubilant.Juju):
    """Scenario: OTLP traces are forwarded from grafana to provider."""
    # GIVEN grafana is integrated with requirer to elicit trace data
    juju.integrate("grafana", "requirer:grafana-dashboards-provider")

    # AND the provider is configured to export traces for debugging
    juju.config("provider", {"debug_exporter_for_logs": False, "debug_exporter_for_traces": True})

    # WHEN we check the provider logs for forwarded traces
    @RETRY
    def check_traces():
        provider_logs = juju.ssh(
            target="provider/0", container="otelcol", command="pebble logs -n 250"
        )
        # THEN there must be one trace whose Juju Topology belongs to Grafana
        assert any(
            "juju_application=graf" in line
            and "charm_type=GrafanaCharm" in line
            and "ResourceTraces" in line
            for line in provider_logs.splitlines()
        ), "Expected at least one forwarded `grafana` trace entry in provider logs"

    check_traces()

