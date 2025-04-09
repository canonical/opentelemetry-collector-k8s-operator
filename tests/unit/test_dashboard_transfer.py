# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Dashboard forwarding to Grafana."""

import json

from cosl import LZMABase64
from ops.testing import Container, Relation, State
from src.charm import dashboards


def encode_as_dashboard(dct: dict):
    return LZMABase64.compress(json.dumps(dct))


def test_dashboard_propagation(ctx, execs):
    """Scenario: Dashboards are forwarded when a dashboard provider is related."""
    # GIVEN a remote charm with dashboards
    content_in = encode_as_dashboard({"hello": "world"})
    expected = {
        "charm": "some-test-charm",
        "title": "file:some-mock-dashboard",
        "content": content_in,
    }
    data = {
        "templates": {
            "file:some-mock-dashboard": {"charm": "some-test-charm", "content": content_in}
        }
    }
    # WHEN related to grafana-dashboards-consumer endpoint
    consumer = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={"dashboards": json.dumps(data)},
    )
    provider = Relation("grafana-dashboards-provider")

    state = State(
        relations=[consumer, provider],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    # THEN the dashboards are correctly transferred to the provider databag
    with ctx(ctx.on.relation_changed(consumer), state=state) as mgr:
        dash = dashboards(mgr.charm)[0]
        assert dash["charm"] == expected["charm"]
        assert dash["title"] == expected["title"]
        assert dash["content"] == json.loads(LZMABase64.decompress(expected["content"]))
