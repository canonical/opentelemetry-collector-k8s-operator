# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

import pathlib
from typing import Dict

import jubilant
from helpers import RETRY

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


@RETRY
def assert_internal_logs_in_loki(juju: jubilant.Juju, loki_app: str) -> None:
    """Assert the collector's own internal telemetry logs (job=otelcol-internal) reach Loki.

    Ref: https://github.com/canonical/opentelemetry-collector-k8s-operator/pull/323
    """
    result = juju.ssh(
        target=f"{loki_app}/leader",
        command='/usr/bin/logcli query --limit=1 --output=jsonl \'{job="otelcol-internal"}\'',
        container="loki",
    )
    assert result.strip(), f"No internal logs (job=otelcol-internal) found in Loki: {result!r}"


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
    topology = {"juju_application", "juju_charm", "juju_unit", "juju_model", "juju_model_uuid"}

    @RETRY
    def _assert_topology_labels() -> None:
        labels = juju.ssh(
            target="loki/leader",
            command="/usr/bin/logcli labels",
            container="loki",
        )
        for label in topology:
            assert label in labels, f"Expected '{label}' label in Loki, got: {labels}"

    _assert_topology_labels()

    # AND the collector's own internal telemetry logs (tagged job=otelcol-internal) reach loki
    assert_internal_logs_in_loki(juju, "loki")


def test_internal_logs_loop_breaker_drops_on_outage(juju: jubilant.Juju):
    """Scenario: when the Loki exporter is down, the loop-breaker filter drops its own failure logs."""
    # GIVEN the metrics debug exporter is on, so internal metrics are printed to the Pebble logs
    juju.config("otelcol", {"debug_exporter_for_metrics": True})
    juju.wait(lambda status: jubilant.all_active(status, "otelcol"), delay=5, timeout=300)

    # AND the send-loki-logs exporter is failing (Loki workload stopped), which makes it emit
    # "Exporting failed" internal logs that recurse into the logs pipeline and must be dropped.
    juju.ssh(target="loki/leader", command="pebble stop loki", container="loki")

    try:
        # THEN the loop-breaker filter drops the looping exporter's own internal logs, visible as a
        # positive `otelcol_processor_filter_logs.filtered` counter for the loop-breaker filter.
        @RETRY
        def _assert_filter_dropped_logs() -> None:
            logs = juju.ssh(
                target="otelcol/leader",
                command="pebble logs -n 1000",
                container="otelcol",
            )
            for line in logs.splitlines():
                if "otelcol_processor_filter_logs.filtered" in line and "loop-breaker" in line:
                    value = float(line.rsplit(" ", 1)[-1])
                    if value > 0:
                        return
                    raise AssertionError(f"filter counter not > 0: {line}")
            raise AssertionError(
                "otelcol_processor_filter_logs.filtered (loop-breaker) not found in Pebble logs"
            )

        _assert_filter_dropped_logs()
    finally:
        # cleanup: bring Loki back and disable the debug exporter so later tests aren't affected
        juju.ssh(target="loki/leader", command="pebble start loki", container="loki")
        juju.config("otelcol", {"debug_exporter_for_metrics": False})


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

    # AND the collector's own internal telemetry logs (tagged job=otelcol-internal) reach loki
    assert_internal_logs_in_loki(juju, "loki-pebble")
