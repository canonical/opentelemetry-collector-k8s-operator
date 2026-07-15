# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

import pathlib
from typing import Dict

import jubilant
import tenacity

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def test_logs_pipeline_promtail(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: log forwarding via the LogProxyConsumer."""
    # GIVEN a model with flog, otel-collector, and loki
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy("flog-k8s", "flog", channel="latest/stable")
    juju.deploy("loki-k8s", "loki", channel="2/edge", trust=True)

    # WHEN they are related to over the loki_push_api interface
    juju.integrate("otelcol:receive-loki-logs", "flog:log-proxy")
    juju.integrate("otelcol:send-loki-logs", "loki")
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # THEN logs arrive in loki with juju topology labels preserved
    # Ref: https://github.com/canonical/opentelemetry-collector-k8s-operator/issues/172
    labels = juju.ssh(
        target="loki/leader",
        command="/usr/bin/logcli labels",
        container="loki",
    )
    topology = {"juju_application", "juju_charm", "juju_unit", "juju_model", "juju_model_uuid"}

    for label in topology:
        assert label in labels, f"Expected '{label}' label in Loki, got: {labels}"


def test_internal_logs_loop_breaker_drops_on_outage(juju: jubilant.Juju):
    """Scenario: when the Loki exporter is down, the loop-breaker filter drops its own failure logs.

    Checks that the OTTL condition
    (instrumentation_scope.attributes["otelcol.component.id"] + otelcol.signal) actually matches
    the collector's self-ingested internal logs.
    """
    # GIVEN the send-loki-logs exporter is failing (Loki workload stopped)
    juju.ssh(target="loki/leader", command="pebble stop loki", container="loki")

    # THEN the loop-breaker filter drops the looping exporter's own internal logs
    @tenacity.retry(stop=tenacity.stop_after_attempt(12), wait=tenacity.wait_fixed(10))
    def _filter_dropped_logs() -> None:
        metrics = juju.ssh(
            target="otelcol/leader",
            command="curl -s localhost:8888/metrics",
            container="otelcol",
        )
        for line in metrics.splitlines():
            if line.startswith("otelcol_processor_filter_logs_filtered") and "loop-breaker" in line:
                assert float(line.rsplit(" ", 1)[-1]) > 0, f"filter not dropping: {line}"
                return
        raise AssertionError("otelcol_processor_filter_logs_filtered metric not found")

    _filter_dropped_logs()

    # cleanup: bring Loki back so later tests aren't affected
    juju.ssh(target="loki/leader", command="pebble start loki", container="loki")


def test_logs_pipeline_pebble(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: log forwarding via Pebble log forwarding."""
    # GIVEN a model with flog, blackbox-exporter, otel-collector, and loki charms
    juju.deploy(charm, "otelcol-pebble", resources=charm_resources, trust=True)
    juju.deploy("blackbox-exporter-k8s", "blackbox", channel="2/edge", trust=True)
    juju.deploy("loki-k8s", "loki-pebble", channel="2/edge", trust=True)

    # WHEN they are related to over the loki_push_api interface
    juju.integrate("otelcol-pebble:receive-loki-logs", "blackbox")
    juju.integrate("otelcol-pebble:send-loki-logs", "loki-pebble")
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # THEN logs arrive in loki
    labels = juju.ssh(
        target="loki-pebble/leader",
        command="/usr/bin/logcli labels",
        container="loki",
    )
    # FIXME: The Pebble log forwarding library sets different label names
    # Once they match, change this to `juju_application`
    assert "application" in labels
    # TODO: Assert that internal logs reach loki
