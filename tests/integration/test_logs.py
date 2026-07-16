# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

import json
import logging
import pathlib
import time
from typing import Dict, Optional

import jubilant
from helpers import RETRY, assert_pebble_service_active

logger = logging.getLogger(__name__)

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def _jsonl_has_entries(result: str) -> bool:
    """Assert `logcli query --output=jsonl` returned at least one real log entry.

    Each line is a JSON object like `{"labels": {...}, "line": "...", "timestamp": "..."}`. We parse
    it (rather than a bare truthiness check on stdout) and require at least one entry with a
    non-empty `line`. The caller's stream selector (e.g. `{job="otelcol-internal"}`) is what
    guarantees the labels on the returned entries -- `logcli` strips labels common to all returned
    streams from the per-line `labels` field (so it is often `{}`), which is why we do NOT assert on
    that field here. Use `logcli series` when you need to assert the label set explicitly.
    """
    entries = [line for line in result.splitlines() if line.strip()]
    assert entries, f"logcli returned no log entries: {result!r}"
    for line in entries:
        if json.loads(line).get("line", "").strip():
            return True
    logger.error("logcli returned entries but none had a log line: %s", result)
    return False


def _loop_breaker_filtered_count(juju: jubilant.Juju) -> Optional[float]:
    """Return the latest loop-breaker `filtered` counter from otelcol's Pebble logs, else None.

    Requires `debug_exporter_for_metrics=True` so the collector's internal metrics are printed to
    the Pebble logs.

    Note: the Pebble log ring buffer persists across the collector restarts triggered by config
    changes, so callers that compare values over time should sample late (after enough fresh logs
    have scrolled older, pre-restart samples out of the `-n 1000` window).

    Sample:
        2026-07-16T17:52:13.115Z [otelcol] otelcol_processor_filter_logs.filtered{
            filter=filter/internal-telemetry-loop-breaker/otelcol/0,
            juju_application=otelcol,
            juju_charm=opentelemetry-collector-k8s,
            juju_model=jubilant-14697ea3,
            juju_model_uuid=35054976-38b2-4f7c-8c50-a793733187e2,
            juju_unit=otelcol/0,
            otel_scope_name=github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor,
            service.instance.id=aaa3c609-a192-4bee-9b48-641cb2e92dcf,
            service.name=otelcol-internal,
            service.version=0.130.1
        } 14
    """
    logs = juju.ssh(target="otelcol/leader", command="pebble logs -n 1000", container="otelcol")
    value: Optional[float] = None
    for line in logs.splitlines():
        if "otelcol_processor_filter_logs.filtered" in line and "loop-breaker" in line:
            value = float(line.rsplit(" ", 1)[-1])  # keep the most recent sample
    return value


@RETRY
def _filter_dropped_logs(juju: jubilant.Juju) -> bool:
    value = _loop_breaker_filtered_count(juju)
    if value is None:
        logger.warning("loop-breaker filter dropped logs counter not found in Pebble logs")
        return False
    logger.info("loop-breaker filter dropped logs counter: %s", value)
    return value > 0


@RETRY
def _assert_internal_logs_in_loki(juju: jubilant.Juju, loki_app: str) -> None:
    """Assert the collector's own internal telemetry logs (job=otelcol-internal) reach Loki."""
    result = juju.ssh(
        target=f"{loki_app}/leader",
        command="/usr/bin/logcli series --quiet '{job=\"otelcol-internal\"}'",
        container="loki",
    )
    # {instance="59c126fd-e67f-49c6-8008-5994b6d501b1", job="otelcol-internal", level="INFO", service_name="otelcol-internal"}
    assert "otelcol-internal" in result, (
        f"No `job=otelcol-internal` stream found in Loki: {result!r}"
    )


def test_logs_pipeline_promtail(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: log forwarding via the LogProxyConsumer."""
    # GIVEN a model with flog, otel-collector, and loki
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy("flog-k8s", "flog", channel="latest/stable")
    juju.deploy("loki-k8s", "loki", channel="dev/edge", trust=True)

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
    _assert_internal_logs_in_loki(juju, "loki")


def test_logs_pipeline_pebble(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: log forwarding via Pebble log forwarding."""
    # GIVEN a model with flog, blackbox-exporter, otel-collector, and loki charms
    juju.deploy(charm, "otelcol-pebble", resources=charm_resources, trust=True)
    juju.deploy("blackbox-exporter-k8s", "blackbox", channel="dev/edge", trust=True)
    juju.deploy("loki-k8s", "loki-pebble", channel="dev/edge", trust=True)

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
    _assert_internal_logs_in_loki(juju, "loki-pebble")


def test_internal_logs_loop_breaker_drops_on_outage(juju: jubilant.Juju):
    """Scenario: when the Loki exporter is down, the loop-breaker filter drops its own failure logs."""
    # GIVEN the metrics debug exporter is on, so internal metrics are printed to the Pebble logs
    juju.config("otelcol", {"debug_exporter_for_metrics": True})
    juju.wait(lambda status: jubilant.all_active(status, "otelcol"), delay=5, timeout=300)

    # AND the loop-breaker filter has not dropped any logs yet (Loki is healthy)
    assert not _filter_dropped_logs(juju)

    # WHEN the send-loki-logs exporter is failing (Loki workload stopped), which makes it emit
    # "Exporting failed" internal logs that recurse into the logs pipeline and must be dropped.
    juju.ssh(target="loki/leader", command="pebble stop loki", container="loki")

    # THEN the loop-breaker filter drops the looping exporter's own internal logs, visible as a
    # positive `otelcol_processor_filter_logs.filtered` counter for the loop-breaker filter.
    assert _filter_dropped_logs(juju)
    juju.ssh(target="loki/leader", command="pebble start loki", container="loki")
    assert_pebble_service_active(juju, "loki/leader", "loki", "loki")


def test_internal_logs_cross_signal_preserved_on_metrics_outage(juju: jubilant.Juju):
    """Scenario: a metrics exporter's failure logs still reach Loki (they are NOT loop-dropped).

    The loop-breaker filter drops ONLY logs emitted by exporters on the LOGS pipeline (matched on
    `otelcol.component.id` AND `otelcol.signal == "logs"`). Failure logs from exporters on other
    pipelines (here: `prometheusremotewrite/0` on the metrics pipeline, which emits
    `otelcol.signal: metrics`) must be preserved and forwarded to Loki.
    """

    @RETRY
    def _metrics_exporter_failure_logs_in_loki() -> bool:
        # We match on the log BODY (`|= "Exporting failed"`): `send-loki-logs` stores logs with
        # `loki.format: raw`, so the line is only the record body -- the `otelcol.component.id`
        # lives on the instrumentation scope and is neither in the line nor a label. Since Loki is
        # up (so `send-loki-logs` is healthy) and `prometheusremotewrite` is the only failing
        # exporter.
        result = juju.ssh(
            target="loki/leader",
            command=(
                "/usr/bin/logcli query --quiet --limit=5 "
                "--output=jsonl '{job=\"otelcol-internal\"} |= `Exporting failed`'"
            ),
            container="loki",
        )
        # {"labels":{},"line":"Exporting failed. Dropping data.","timestamp":"2026-07-16T17:58:18.118744382Z"}
        return _jsonl_has_entries(result)

    # GIVEN Loki is up and otelcol is related to a Prometheus over send-remote-write, with the
    # metrics debug exporter on so the loop-breaker filter counter is printed to otelcol Pebble logs
    juju.deploy("prometheus-k8s", "prometheus", channel="dev/edge", trust=True)
    juju.integrate("otelcol:send-remote-write", "prometheus")
    juju.config("otelcol", {"debug_exporter_for_metrics": True})
    juju.wait(jubilant.all_active, delay=10, timeout=600)
    assert not _metrics_exporter_failure_logs_in_loki()

    # WHEN the remote-write target is down, the metrics exporter (`prometheusremotewrite/0`) emits
    # "Exporting failed" internal logs carrying `otelcol.signal: metrics`.
    juju.ssh(target="prometheus/leader", command="pebble stop prometheus", container="prometheus")

    try:
        # THEN those metrics-signal failure logs still arrive in Loki under {job="otelcol-internal"}.
        breakpoint()
        assert _metrics_exporter_failure_logs_in_loki()

        # AND the loop-breaker did NOT drop them: with Loki healthy there are no logs-pipeline
        # failures to legitimately drop, so the filter's drop counter must stay flat even while the
        # metrics exporter keeps failing. Sampled twice, late (after the Loki check above), so
        # pre-restart samples have scrolled out of the log window.
        filtered = _loop_breaker_filtered_count(juju) or 0.0
        time.sleep(30)  # let more metrics-signal failures flow through the filter
        filtered_later = _loop_breaker_filtered_count(juju) or 0.0
        assert filtered_later == filtered, (
            "loop-breaker filter dropped logs during a metrics-only outage (over-dropping "
            f"cross-signal logs?): {filtered} -> {filtered_later}"
        )
    finally:
        juju.ssh(
            target="prometheus/leader", command="pebble start prometheus", container="prometheus"
        )
        assert_pebble_service_active(juju, "prometheus/leader", "prometheus", "prometheus")
        juju.remove_relation("otelcol:send-remote-write", "prometheus")
        juju.config("otelcol", {"debug_exporter_for_metrics": False})
