# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Dashboard forwarding to Grafana."""

import json

from cosl import LZMABase64
from ops.testing import Container, Relation, State

from src.charm import get_dashboards


def encode_as_dashboard(dct: dict):
    return LZMABase64.compress(json.dumps(dct))


def test_dashboard_propagation(ctx, execs):
    """Scenario: Dashboards are forwarded when a dashboard provider is related."""
    # GIVEN remote charms with dashboards
    content_in = {
        0: encode_as_dashboard({"whoami": "0"}),
        1: encode_as_dashboard({"whoami": "1"}),
    }
    expected = {
        0: {"charm": "some-charm", "title": "dashboard-0", "content": content_in[0]},
        1: {"charm": "some-charm", "title": "dashboard-1", "content": content_in[1]},
    }
    data = {
        idx: {
            "templates": {f"dashboard-{idx}": {"charm": "some-charm", "content": content_in[idx]}}
        }
        for idx, value in content_in.items()
    }
    # WHEN related to grafana-dashboards-consumer endpoint
    consumer0 = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={"dashboards": json.dumps(data[0])},
    )
    consumer1 = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={"dashboards": json.dumps(data[1])},
    )
    # AND related to a dashboard destination
    provider0 = Relation("grafana-dashboards-provider")
    provider1 = Relation("grafana-dashboards-provider")

    state = State(
        relations=[consumer0, consumer1, provider0, provider1],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    # WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        dashboards = get_dashboards(mgr.charm.model.relations["grafana-dashboards-consumer"])
        for idx in range(len(dashboards)):
            # THEN the dashboards are correctly transferred to otelcol via databag
            assert dashboards[idx]["charm"] == list(expected.values())[idx]["charm"]
            assert dashboards[idx]["title"] == list(expected.values())[idx]["title"]
            assert dashboards[idx]["content"] == json.loads(
                LZMABase64.decompress(list(expected.values())[idx]["content"])
            )

        # WHEN ops.main proceeds and emits the "start" event on the charm
        state_out = mgr.run()
        for rel in state_out.relations:
            if "-provider" in rel.endpoint:
                dashboard = rel.local_app_data["dashboards"]
                # THEN otelcol's bundled dashboard is provided to each dashboard destination via databag
                all(
                    dash["charm"] == "opentelemetry-collector-k8s"
                    for dash in json.loads(dashboard)["templates"].values()
                )
