# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested logs are forwarded."""

import pathlib
from typing import Dict

import jubilant

# pyright: reportAttributeAccessIssue = false

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


async def test_logs_pipeline(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: loki-to-loki formatted log forwarding."""
    # GIVEN a model with flog, otel-collector, and loki charms
    juju.deploy("flog-k8s", app="flog", channel="latest/stable", trust=True)
    juju.deploy("loki-k8s", app="loki", channel="2/edge", trust=True)
    juju.deploy(charm, app="otelcol", resources=charm_resources, trust=True)
    juju.wait(jubilant.all_active, delay=10, timeout=600)
    # WHEN only a source relation is established with otelcol
    juju.integrate("flog", "otelcol:receive-loki-logs")
    # THEN otelcol goes to Blocked
    juju.wait(lambda status: jubilant.all_active(status, "flog"), delay=10, timeout=600)
    juju.wait(lambda status: jubilant.all_blocked(status, "otelcol"), delay=10, timeout=600)
    # AND WHEN we add a sink relation
    juju.integrate("otelcol:send-loki-logs", "loki")
    # THEN otelcol goes to Active
    juju.wait(jubilant.all_active, delay=10, timeout=600)
