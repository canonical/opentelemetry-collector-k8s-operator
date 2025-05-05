"""Feature: Otelcol can form TLS connections with HTTPS servers."""

import logging
import pathlib
import tempfile
import textwrap
import time

import jubilant
import sh

# This is needed for sh.juju
# pyright: reportAttributeAccessIssue = false

logger = logging.getLogger(__name__)


# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def logs_contain_errors(logs):
    # TODO make assertions less brittle
    # Receiver failure; otelcol is the client scraping Alertmanager
    #   This is an edge case since otelcol
    assert "Failed to scrape" in logs
    assert "unknown authority" in logs
    # Exporter failure; otelcol is the client remote-writing to Prometheus
    assert "Exporting failed. Dropping data." in logs
    assert "context deadline exceeded" in logs


def logs_contain_no_errors(logs):
    # TODO make assertions less brittle
    # Receiver failure
    assert "Failed to scrape" not in logs
    assert "unknown authority" not in logs
    # Exporter failure
    assert "Exporting failed. Dropping data." not in logs
    assert "context deadline exceeded" not in logs


def test_unknown_authority(juju: jubilant.Juju, charm, charm_resources):
    """Scenario: Otelcol fails to scrape metrics from a server signed by unknown authority."""
    sh.juju.switch(juju.model)

    # GIVEN a scrape target signed by a self-signed certificate
    # WHEN related to otelcol
    bundle = textwrap.dedent(f"""
        bundle: kubernetes
        applications:
          am:
            charm: alertmanager-k8s
            channel: latest/stable
            revision: 158
            base: ubuntu@20.04/stable
            resources:
              alertmanager-image: 99
            scale: 1
            constraints: arch=amd64
            trust: true
          otelcol:
            charm: ../../{charm}
            scale: 1
            constraints: arch=amd64
            resources:
                opentelemetry-collector-image: {charm_resources["opentelemetry-collector-image"]}
          prom:
            charm: prometheus-k8s
            channel: latest/stable
            revision: 234
            base: ubuntu@20.04/stable
            resources:
              prometheus-image: 151
            scale: 1
            constraints: arch=amd64
            trust: true
          ssc:
            charm: self-signed-certificates
            channel: 1/stable
            revision: 263
            scale: 1
            constraints: arch=amd64
        relations:
        - - am:self-metrics-endpoint
          - otelcol:metrics-endpoint
        - - am:certificates
          - ssc:certificates
        - - ssc:certificates
          - prom:certificates
        - - prom:receive-remote-write
          - otelcol:send-remote-write
    """)
    with tempfile.NamedTemporaryFile(dir=TEMP_DIR, suffix=".yaml") as f:
        f.write(bundle.encode())
        f.flush()
        juju.deploy(f.name, trust=True)
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    logger.info("Waiting for scrape interval (1 minute) to elapse...")
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)

    # THEN scrape fails
    logs = sh.kubectl.logs(
        "otelcol-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    logs_contain_errors(logs)

    # Sample otelcol logs:
    # 2025-04-07T20:46:23.468Z [otelcol] 2025-04-07T20:46:23.468Z	debug	Scrape failed	{"otelcol.component.id": "prometheus", "otelcol.component.kind": "Receiver", "otelcol.signal": "metrics", "scrape_pool": "juju_welcome-k8s_39de1be4_am_prometheus_scrape", "target": "https://am-0.am-endpoints.welcome-k8s.svc.cluster.local:9093/metrics", "err": "Get \"https://am-0.am-endpoints.welcome-k8s.svc.cluster.local:9093/metrics\": tls: failed to verify certificate: x509: certificate signed by unknown authority"}
    # 2025-04-07T20:46:23.468Z [otelcol] 2025-04-07T20:46:23.468Z	warn	internal/transaction.go:129	Failed to scrape Prometheus endpoint	{"otelcol.component.id": "prometheus", "otelcol.component.kind": "Receiver", "otelcol.signal": "metrics", "scrape_timestamp": 1744058783465, "target_labels": "{__name__=\"up\", instance=\"welcome-k8s_39de1be4-832a-4e93-8f5f-c19abd31ebd2_am\", job=\"juju_welcome-k8s_39de1be4_am_prometheus_scrape\", juju_application=\"am\", juju_charm=\"alertmanager-k8s\", juju_model=\"welcome-k8s\", juju_model_uuid=\"39de1be4-832a-4e93-8f5f-c19abd31ebd2\"}"}
    # 2025-04-17T20:58:53.728Z [otelcol] 2025-04-07T20:46:23.468Z error internal/queue_sender.go:128 Exporting failed. Dropping data.   {"otelcol.component.id": "prometheusremotewrite/0", "otelcol.component.kind": "Exporter", "otelcol.signal": "metrics", "error": "Permanent error: Permanent error: context deadline exceeded", "dropped_items": 5}


def test_insecure_skip_verify(juju: jubilant.Juju):
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!

    # WHEN we skip server certificate validation; Alertmanager for scraping and Prom for remote writing
    juju.config("otelcol", {"tls_insecure_skip_verify": True})
    time.sleep(lookback_window)  # Wait for scrape interval (1 minute) to elapse
    logs = sh.kubectl.logs(
        "otelcol-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    # THEN scrape succeeds
    logs_contain_no_errors(logs)

    # WHEN we validate server certificates; Alertmanager for scraping and Prom for remote writing
    juju.config("otelcol", {"tls_insecure_skip_verify": False})
    time.sleep(lookback_window)  # Wait for scrape interval (1 minute) to elapse
    logs = sh.kubectl.logs(
        "otelcol-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    # THEN scrape fails
    logs_contain_errors(logs)


def test_with_ca_cert_forwarded(juju: jubilant.Juju):
    """Scenario: Otelcol succeeds to scrape metrics from a server signed by a CA that otelcol trusts."""
    # WHEN otelcol trusts the CA that signed the scrape target
    sh.juju.relate("ssc", "otelcol:receive-ca-cert", m=juju.model)
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # Wait for scrape interval (1 minute) to elapse
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)

    # THEN scrape succeeds
    logs = sh.kubectl.logs(
        "otelcol-0", container="otelcol", n=juju.model, since=f"{lookback_window}s"
    )
    logs_contain_no_errors(logs)

    # Sample otelcol log:
    # 2025-04-07T21:32:23.468Z [otelcol] 2025-04-07T21:32:23.468Z	info	Metrics	{"otelcol.component.id": "debug", "otelcol.component.kind": "Exporter", "otelcol.signal": "metrics", "resource metrics": 1, "metrics": 83, "data points": 206}
