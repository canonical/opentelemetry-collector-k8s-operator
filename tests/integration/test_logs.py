# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

import logging
import pathlib
from typing import Dict

import jubilant
from helpers import RETRY

logger = logging.getLogger(__name__)

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def _dump_internal_logs_diagnostics(juju: jubilant.Juju, otelcol_app: str, loki_app: str) -> None:
    """Log diagnostics to disambiguate why internal logs didn't reach Loki (CI-vs-local).

    Distinguishes the two possible failure boundaries:
      * self-ingest boundary: the collector exports its own logs to its OWN OTLP receiver
        (http://localhost:4318). If this fails, `otelcol_receiver_accepted_log_records` for the
        otlp receiver stays at 0 and the otelcol logs show connection/TLS errors to :4318.
      * Loki boundary: logs are ingested locally but never forwarded (send-loki-logs failing) or
        arrive under a different label than `job=otelcol-internal`.
    """

    def _ssh(target: str, container: str, command: str) -> str:
        try:
            return juju.ssh(target=target, command=command, container=container)
        except Exception as exc:  # noqa: BLE001 - diagnostics must never mask the real failure
            return f"<ssh failed: {exc}>"

    # 1) Self-export boundary: the collector exports its OWN logs to http://localhost:4318.
    #    If that connection fails, the otelcol log tail shows connection/TLS errors to :4318, and
    #    the internal logs never enter the pipeline (so they can't reach Loki). `curl` is NOT in
    #    the rock, so we rely on the Pebble log tail, which is always available.
    otelcol_logs = _ssh(f"{otelcol_app}/leader", "otelcol", "pebble logs -n 300")
    suspicious = "\n".join(
        line
        for line in otelcol_logs.splitlines()
        if any(
            token in line.lower()
            for token in ("4318", "x509", "certificate", "refused", "otelcol-internal", "error")
        )
    )
    # 2) Loki boundary: what labels/streams actually exist? If ingestion works but the `job` label
    #    differs in CI, `job` will list values other than (or missing) `otelcol-internal`.
    loki_labels = _ssh(f"{loki_app}/leader", "loki", "/usr/bin/logcli labels")
    loki_jobs = _ssh(f"{loki_app}/leader", "loki", "/usr/bin/logcli labels job")

    logger.error(
        "INTERNAL-LOGS DIAGNOSTICS\n"
        "=== otelcol suspicious log lines (self-export to :4318 / errors) ===\n%s\n"
        "=== loki labels ===\n%s\n"
        "=== loki `job` label values ===\n%s\n"
        "=== otelcol log tail (last 300) ===\n%s",
        suspicious or "<no suspicious lines>",
        loki_labels,
        loki_jobs,
        otelcol_logs,
    )


@RETRY
def assert_internal_logs_in_loki(juju: jubilant.Juju, loki_app: str) -> None:
    """Assert the collector's own internal telemetry logs (job=otelcol-internal) reach Loki.

    Ref: https://github.com/canonical/opentelemetry-collector-k8s-operator/pull/323
    """
    result = juju.ssh(
        target=f"{loki_app}/leader",
        command="/usr/bin/logcli query --quiet --limit=1 --output=jsonl '{job=\"otelcol-internal\"}'",
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
    try:
        assert_internal_logs_in_loki(juju, "loki")
    except Exception:
        # RETRY re-raises as tenacity.RetryError (not AssertionError), so catch broadly.
        # Dump otelcol/loki diagnostics once (after RETRY is exhausted) to root-cause CI failures.
        _dump_internal_logs_diagnostics(juju, "otelcol", "loki")
        raise


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


def test_internal_logs_cross_signal_preserved_on_metrics_outage(juju: jubilant.Juju):
    """Scenario: a metrics exporter's failure logs still reach Loki (they are NOT loop-dropped).

    The loop-breaker filter drops ONLY logs emitted by exporters on the LOGS pipeline (matched on
    `otelcol.component.id` AND `otelcol.signal == "logs"`). Failure logs from exporters on other
    pipelines (here: `prometheusremotewrite/0` on the metrics pipeline, which emits
    `otelcol.signal: metrics`) must be preserved and forwarded to Loki, proving the fix is not
    Loki-specific and does not over-drop cross-signal visibility.
    """
    # GIVEN Loki is up and otelcol is related to a Prometheus over send-remote-write
    juju.deploy("prometheus-k8s", "prometheus", channel="2/edge", trust=True)
    juju.integrate("otelcol:send-remote-write", "prometheus")
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # WHEN the remote-write target is down, the metrics exporter (`prometheusremotewrite/0`) emits
    # "Exporting failed" internal logs carrying `otelcol.signal: metrics`.
    juju.ssh(target="prometheus/leader", command="pebble stop prometheus", container="prometheus")

    try:
        # THEN those metrics-signal failure logs are NOT dropped by the loop-breaker filter and
        # still arrive in Loki under {job="otelcol-internal"}, tagged with the metrics exporter id.
        @RETRY
        def _assert_metrics_exporter_failure_logs_in_loki() -> None:
            result = juju.ssh(
                target="loki/leader",
                command=(
                    "/usr/bin/logcli query --quiet --limit=5 --output=jsonl "
                    "'{job=\"otelcol-internal\"} |= `prometheusremotewrite`'"
                ),
                container="loki",
            )
            assert result.strip(), (
                "Metrics-exporter failure logs were not forwarded to Loki (over-dropped by the "
                f"loop-breaker?): {result!r}"
            )

        _assert_metrics_exporter_failure_logs_in_loki()
    finally:
        # cleanup: bring Prometheus back and remove the relation so later tests aren't affected
        juju.ssh(
            target="prometheus/leader", command="pebble start prometheus", container="prometheus"
        )
        juju.remove_relation("otelcol:send-remote-write", "prometheus")
