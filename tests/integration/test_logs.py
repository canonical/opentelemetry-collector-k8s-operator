# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

import pathlib
import tempfile
import textwrap

import jubilant
import sh
from pytest_jubilant import Juju

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def test_logs_pipeline(juju: Juju, charm, charm_resources):
    """Scenario: loki-to-loki formatted log forwarding."""
    sh.juju.switch(juju.model)
    # GIVEN a model with flog, otel-collector, and loki charms
    bundle = textwrap.dedent(f"""
        bundle: kubernetes
        applications:
          flog:
            charm: flog-k8s
            channel: latest/stable
            resources:
              workload-image: 2
            scale: 1
          otelcol:
            charm: {charm}
            scale: 1
            resources:
              opentelemetry-collector-image: {charm_resources["opentelemetry-collector-image"]}
          loki:
            charm: loki-k8s
            channel: latest/stable
            resources:
              loki-image: 100
              node-exporter-image: 3
            scale: 1
            trust: true
        relations:
        - - flog:log-proxy
          - otelcol:receive-loki-logs
        - - otelcol:send-loki-logs
          - loki:logging
    """)
    # WHEN they are related to over the loki_push_api interface
    with tempfile.NamedTemporaryFile(dir=TEMP_DIR, suffix=".yaml") as f:
        f.write(bundle.encode())
        f.flush()
        juju.deploy(f.name, trust=True)
    juju.wait(jubilant.all_active, delay=10, timeout=600)
    # THEN logs arrive in loki
    labels = sh.juju.ssh(
        "--container=loki",
        "loki/leader",
        "/usr/bin/logcli labels",
    )
    assert "juju_application" in labels
