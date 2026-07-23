# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

import json
import logging
import pathlib
from typing import Dict, Optional

import jubilant
from helpers import RETRY, assert_pebble_service_active

logger = logging.getLogger(__name__)

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def _jsonl_has_entries(result: str) -> bool:
    """Return True if `logcli query --output=jsonl` output has at least one real log entry.

    Each line is a JSON object like `{"labels": {...}, "line": "...", "timestamp": "..."}`. We parse
    it (rather than a bare truthiness check on stdout, which would also match `logcli` metadata) and
    require at least one entry with a non-empty `line`. This is a pure predicate; callers wrap it in
    an assertion (typically under `@RETRY`). The caller's stream selector (e.g.
    `{job="otelcol-internal"}`) is what guarantees the labels on the returned entries -- `logcli`
    strips labels common to all returned streams from the per-line `labels` field (so it is often
    `{}`), which is why we do NOT assert on that field here; use `logcli series` for that.
    """
    for line in result.splitlines():
        if line.strip() and json.loads(line).get("line", "").strip():
            return True
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
def _assert_loop_breaker_dropped_more(juju: jubilant.Juju, baseline: float) -> None:
    """Assert otelcol's loop-breaker `filtered` counter has climbed above `baseline`.

    Requires `debug_exporter_for_metrics=True` so the counter is printed to the Pebble logs (see
    `_loop_breaker_filtered_count`). We assert on the DELTA rather than an absolute value because
    the counter can already be > 0 due to transient logs-signal failures (e.g. Loki "not ready"
    windows) that the loop-breaker legitimately drops.
    """
    current = _loop_breaker_filtered_count(juju) or 0.0
    assert current > baseline, (
        f"loop-breaker filter drop counter did not increase: {baseline} -> {current}"
    )


@RETRY
def _assert_internal_logs_in_loki(juju: jubilant.Juju, loki_app: str, otelcol_app: str) -> None:
    """Assert the collector's own internal telemetry logs reach Loki with Juju topology labels.

    The internal logs are tagged with this collector's own Juju topology so that, when multiple
    otelcol apps ship to the same Loki, their `job=otelcol-internal` streams stay distinguishable.
    We also pin `service.instance.id` to the Juju unit, so the `instance` label is the unit (stable
    and correlatable) rather than a random per-process UUID that churns on every restart.
    """
    result = juju.ssh(
        target=f"{loki_app}/leader",
        command="/usr/bin/logcli series --quiet '{job=\"otelcol-internal\"}'",
        container="loki",
    )
    # {instance="otelcol/0", job="otelcol-internal", juju_application="otelcol", juju_charm="...",
    #  juju_model="...", juju_model_uuid="...", juju_unit="otelcol/0", level="INFO", ...}
    assert "otelcol-internal" in result, (
        f"No `job=otelcol-internal` stream found in Loki: {result!r}"
    )
    # Topology labels are present and identify the emitting app/unit ...
    for label in (
        f'juju_application="{otelcol_app}"',
        f'juju_unit="{otelcol_app}/0"',
        "juju_model=",
        "juju_model_uuid=",
        "juju_charm=",
    ):
        assert label in result, f"Expected topology label {label!r} on internal logs: {result!r}"
    # ... and the `instance` label is the Juju unit, not a random UUID.
    assert f'instance="{otelcol_app}/0"' in result, (
        f"Expected `instance` label pinned to the Juju unit: {result!r}"
    )


def test_logs_pipeline_promtail(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: log forwarding via the LogProxyConsumer."""
    # GIVEN a model with flog, otel-collector, and loki
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy("flog-k8s", "flog", channel="latest/stable")
    juju.deploy("loki-k8s", "loki", channel="3.7/edge", trust=True)

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
    _assert_internal_logs_in_loki(juju, "loki", "otelcol")


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
    _assert_internal_logs_in_loki(juju, "loki-pebble", "otelcol-pebble")


def test_internal_logs_loop_breaker_drops_on_outage(juju: jubilant.Juju):
    """Scenario: when the Loki exporter is down, the loop-breaker filter drops its own failure logs."""
    # GIVEN the metrics debug exporter is on, so internal metrics are printed to the Pebble logs
    juju.config("otelcol", {"debug_exporter_for_metrics": True})
    juju.wait(lambda status: jubilant.all_active(status, "otelcol"), delay=5, timeout=300)

    # Baseline the loop-breaker drop counter. It may already be > 0: Loki can have transient
    # "not ready" windows (e.g. ingester warmup) during which send-loki-logs fails and the
    # loop-breaker correctly drops those recursive logs-signal failures. So we assert on the DELTA
    # once we stop Loki, never on an absolute zero.
    baseline = _loop_breaker_filtered_count(juju) or 0.0

    # WHEN the send-loki-logs exporter is failing (Loki workload stopped), which makes it emit
    # "Exporting failed" internal logs that recurse into the logs pipeline and must be dropped.
    juju.ssh(target="loki/leader", command="pebble stop loki", container="loki")

    try:
        # THEN the loop-breaker drop counter climbs above the baseline as it drops the looping
        # exporter's own internal logs.
        _assert_loop_breaker_dropped_more(juju, baseline)
    finally:
        juju.ssh(target="loki/leader", command="pebble start loki", container="loki")
        assert_pebble_service_active(juju, "loki/leader", "loki", "loki")


def test_internal_logs_cross_signal_preserved_on_metrics_outage(juju: jubilant.Juju):
    """Scenario: a metrics exporter's failure logs still reach Loki (they are NOT loop-dropped).

    The loop-breaker filter drops ONLY logs emitted by exporters on the LOGS pipeline (matched on
    `otelcol.component.id` AND `otelcol.signal == "logs"`). Failure logs from exporters on other
    pipelines (here: `prometheusremotewrite/0` on the metrics pipeline, which emits
    `otelcol.signal: metrics`) must be preserved and forwarded to Loki.
    """
    # GIVEN Loki is up and otelcol is related to a Prometheus over send-remote-write
    juju.deploy("prometheus-k8s", "prometheus", channel="3.11/edge", trust=True)
    juju.integrate("otelcol:send-remote-write", "prometheus")
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # AND the metrics debug exporter is on, so internal metrics are printed to the Pebble logs.
    juju.config("otelcol", {"debug_exporter_for_metrics": True})
    juju.wait(lambda status: jubilant.all_active(status, "otelcol"), delay=5, timeout=300)

    # WHEN the remote-write target is down, the metrics exporter (`prometheusremotewrite/0`) emits
    # "Exporting failed" internal logs carrying `otelcol.signal: metrics`.
    juju.ssh(target="prometheus/leader", command="pebble stop prometheus", container="prometheus")

    try:
        # THEN the metrics-exporter's logs reach Loki, proving they were not over-dropped.
        #
        # `loki.format: logfmt` mangles the body text (`Exporting failed` is no longer a contiguous
        # substring), so we match the scope attributes instead, which logfmt emits verbatim as
        # `instrumentation_scope_attribute_<key>=<value>`.
        @RETRY
        def _assert_metrics_exporter_failure_logs_in_loki() -> None:
            result = juju.ssh(
                target="loki/leader",
                command=(
                    "/usr/bin/logcli query --quiet --limit=5 --output=jsonl "
                    '\'{job="otelcol-internal"} '
                    "|= `otelcol.component.id=prometheusremotewrite` "
                    "|= `otelcol.signal=metrics`'"
                ),
                container="loki",
            )
            assert _jsonl_has_entries(result), (
                "Metrics-exporter failure logs were not forwarded to Loki (over-dropped by the "
                f"loop-breaker?): {result!r}"
            )

        _assert_metrics_exporter_failure_logs_in_loki()
    finally:
        juju.ssh(
            target="prometheus/leader", command="pebble start prometheus", container="prometheus"
        )
        assert_pebble_service_active(juju, "prometheus/leader", "prometheus", "prometheus")
        juju.config("otelcol", {"debug_exporter_for_metrics": False})
        juju.remove_relation("otelcol:send-remote-write", "prometheus")
