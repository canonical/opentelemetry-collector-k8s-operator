"""Feature: Otelcol can form TLS connections with HTTPS servers."""

import textwrap
import sh
from typing import Dict
import tempfile
import time
import pathlib
import logging
import jubilant

# This is needed for sh.juju
# pyright: reportAttributeAccessIssue = false

logger = logging.getLogger(__name__)


# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


async def test_unknown_authority(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: Otelcol fails to scrape metrics from a server signed by unknown authority."""
    sh.juju.switch(juju.model)

    # GIVEN a scrape target signed by a self-signed certificate
    # WHEN related to otelcol
    bundle = textwrap.dedent(f"""
        bundle: kubernetes
        applications:
          am:
            charm: alertmanager-k8s
            channel: latest/edge
            revision: 158
            base: ubuntu@20.04/stable
            resources:
              alertmanager-image: 99
            scale: 1
            constraints: arch=amd64
            trust: true
          otelcol:
            charm: {charm}
            scale: 1
            constraints: arch=amd64
            resources:
                opentelemetry-collector-image: {charm_resources["opentelemetry-collector-image"]}
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
    """)
    with tempfile.NamedTemporaryFile(dir=TEMP_DIR, suffix=".yaml") as f:
        f.write(bundle.encode())
        f.flush()
        juju.deploy(f.name, trust=True)
    juju.wait(jubilant.all_active, timeout=600)

    logger.info("Waiting for scrape interval (1 minute) to elapse...")
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)

    # THEN scrape fails
    # TODO make assertions less brittle
    logs = sh.kubectl.logs("otelcol-0", container="otelcol", n=juju.model, since=f"{lookback_window}s")
    assert "Failed to scrape" in logs
    assert "unknown authority" in logs

    # Sample otelcol logs:
    # 2025-04-07T20:46:23.468Z [otelcol] 2025-04-07T20:46:23.468Z	debug	Scrape failed	{"otelcol.component.id": "prometheus", "otelcol.component.kind": "Receiver", "otelcol.signal": "metrics", "scrape_pool": "juju_welcome-k8s_39de1be4_am_prometheus_scrape", "target": "https://am-0.am-endpoints.welcome-k8s.svc.cluster.local:9093/metrics", "err": "Get \"https://am-0.am-endpoints.welcome-k8s.svc.cluster.local:9093/metrics\": tls: failed to verify certificate: x509: certificate signed by unknown authority"}
    # 2025-04-07T20:46:23.468Z [otelcol] 2025-04-07T20:46:23.468Z	warn	internal/transaction.go:129	Failed to scrape Prometheus endpoint	{"otelcol.component.id": "prometheus", "otelcol.component.kind": "Receiver", "otelcol.signal": "metrics", "scrape_timestamp": 1744058783465, "target_labels": "{__name__=\"up\", instance=\"welcome-k8s_39de1be4-832a-4e93-8f5f-c19abd31ebd2_am\", job=\"juju_welcome-k8s_39de1be4_am_prometheus_scrape\", juju_application=\"am\", juju_charm=\"alertmanager-k8s\", juju_model=\"welcome-k8s\", juju_model_uuid=\"39de1be4-832a-4e93-8f5f-c19abd31ebd2\"}"}


def test_with_ca_cert_forwarded(juju: jubilant.Juju):
    """Scenario: Otelcol succeeds to scrape metrics from a server signed by a CA that otelcol trusts."""
    # WHEN otelcol trusts the CA that signed the scrape target
    sh.juju.relate("ssc", "otelcol:receive-ca-cert", m=juju.model)
    juju.wait(jubilant.all_active, timeout=600)

    # Wait for scrape interval (1 minute) to elapse
    scrape_interval = 60  # seconds!
    lookback_window = scrape_interval + 10  # seconds!
    time.sleep(lookback_window)

    # THEN scrape succeeds
    # TODO make assertions less brittle
    logs = sh.kubectl.logs("otelcol-0", container="otelcol", n=juju.model, since=f"{lookback_window}s")
    assert "Failed to scrape" not in logs
    assert "unknown authority" not in logs

    # Sample otelcol log:
    # 2025-04-07T21:32:23.468Z [otelcol] 2025-04-07T21:32:23.468Z	info	Metrics	{"otelcol.component.id": "debug", "otelcol.component.kind": "Exporter", "otelcol.signal": "metrics", "resource metrics": 1, "metrics": 83, "data points": 206}
