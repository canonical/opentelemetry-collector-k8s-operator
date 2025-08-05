# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

import pathlib
from typing import Dict

import jubilant

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


async def test_logs_pipeline_promtail(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
    """Scenario: log forwarding via the LogProxyConsumer."""
    # GIVEN a model with flog, otel-collector, and loki
    juju.deploy(charm, "otelcol", resources=charm_resources, trust=True)
    juju.deploy("flog-k8s", "flog", channel="latest/stable")
    juju.deploy("loki-k8s", "loki", channel="2/edge", trust=True)

    # WHEN they are related to over the loki_push_api interface
    juju.integrate("otelcol:receive-loki-logs", "flog:log-proxy")
    juju.integrate("otelcol:send-loki-logs", "loki")
    juju.wait(jubilant.all_active, delay=10, timeout=600)

    # THEN logs arrive in loki
    labels = juju.ssh(
        target="loki/leader",
        command="/usr/bin/logcli labels",
        container="loki",
    )
    assert "juju_application" in labels


async def test_logs_pipeline_pebble(
    juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]
):
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
    assert "juju_application" in labels
