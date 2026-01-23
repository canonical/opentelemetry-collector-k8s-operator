# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can receive metrics via receive-remote-write."""

import json
from unittest.mock import patch

from ops.testing import Relation, State

from src.config_builder import Port


@patch("socket.getfqdn", new=lambda *args: "fqdn")
def test_url_in_databag(ctx, otelcol_container):
    # WHEN traefik ingress is related to otelcol
    receive_rw_endpoint = Relation("receive-remote-write", remote_app_data={"alert_rules": "{}"})
    state = State(
        relations=[receive_rw_endpoint], containers=otelcol_container, leader=True
    )

    out_1 = ctx.run(ctx.on.relation_created(receive_rw_endpoint), state)

    # THEN ingress URL is present in receive-loki-logs relation databag
    receive_rw_out = out_1.get_relations(receive_rw_endpoint.endpoint)[0]
    # TODO: Shouldn't this be v2?
    expected_data = {"url": f"http://fqdn:{Port.prometheus_http.value}/api/v1/write"}
    # TODO: test alert rules, likely in an itest or by mocking the remote_databag with alertrules and metadata
    assert json.loads(receive_rw_out.local_unit_data["remote_write"]) == expected_data
