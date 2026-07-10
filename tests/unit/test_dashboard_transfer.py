# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Dashboard forwarding to Grafana."""

import json
from unittest.mock import patch

from cosl import LZMABase64
from ops.testing import Container, Relation, State


def encode_as_dashboard(dct: dict):
    return LZMABase64.compress(json.dumps(dct))


def _published_templates(state_out):
    """Return the merged templates published to all grafana-dashboards-provider relations."""
    merged = {}
    for rel in state_out.relations:
        if "-provider" in rel.endpoint and "dashboards" in rel.local_app_data:
            merged.update(json.loads(rel.local_app_data["dashboards"])["templates"])
    return merged


def test_dashboard_propagation(ctx, execs):
    """Scenario: received dashboards are forwarded, keyed per relation, alongside bundled ones."""
    # GIVEN multiple remote charms with dashboards
    content_in = {
        0: encode_as_dashboard({"whoami": "0"}),
        1: encode_as_dashboard({"whoami": "1"}),
    }
    data = {
        idx: {
            "templates": {
                f"file:dashboard-{idx}": {"charm": "some-charm", "content": content_in[idx]}
            }
        }
        for idx in content_in
    }
    # WHEN they are related to the grafana-dashboards-consumer endpoint
    consumer0 = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={"dashboards": json.dumps(data[0])},
        id=100,
    )
    consumer1 = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={"dashboards": json.dumps(data[1])},
        id=101,
    )
    # AND otelcol is related to multiple Grafana instances
    provider0 = Relation("grafana-dashboards-provider")
    provider1 = Relation("grafana-dashboards-provider")

    state = State(
        relations=[consumer0, consumer1, provider0, provider1],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    # WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    templates = _published_templates(state_out)
    # THEN each received dashboard is published under a per-relation pass-through key ...
    assert "prog:rel_100__file:dashboard-0" in templates
    assert "prog:rel_101__file:dashboard-1" in templates
    # ... and otelcol's own bundled dashboard is published too.
    assert "file:overview-dashboard" in templates


def test_received_content_is_forwarded_verbatim(ctx, execs):
    """Scenario: the compressed content received is published byte-for-byte (no re-compress)."""
    # GIVEN a remote charm providing an already-compressed dashboard
    original = {"title": "my-dashboard", "panels": []}
    encoded = encode_as_dashboard(original)
    consumer = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={
            "dashboards": json.dumps(
                {"templates": {"file:my-dash": {"charm": "some-charm", "content": encoded}}}
            )
        },
        id=42,
    )
    provider = Relation("grafana-dashboards-provider")
    state = State(
        relations=[consumer, provider],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )

    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    entry = _published_templates(state_out)["prog:rel_42__file:my-dash"]
    # THEN the published content is byte-identical to what was received ...
    assert entry["content"] == encoded
    # ... and it still decompresses back to the original dashboard.
    assert json.loads(LZMABase64.decompress(entry["content"])) == original


def test_forwarding_does_not_decompress_received_dashboards(ctx, execs):
    """Scenario: the pass-through path never decompresses received content (the O(N) win)."""
    encoded = encode_as_dashboard({"title": "x", "panels": []})
    consumer = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={
            "dashboards": json.dumps(
                {"templates": {"file:x": {"charm": "some-charm", "content": encoded}}}
            )
        },
        id=7,
    )
    provider = Relation("grafana-dashboards-provider")
    state = State(
        relations=[consumer, provider],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )

    with patch.object(LZMABase64, "decompress", wraps=LZMABase64.decompress) as mock_decompress:
        with ctx(ctx.on.update_status(), state=state) as mgr:
            mgr.run()

    # Received dashboards are forwarded verbatim, so nothing is decompressed on the send path.
    mock_decompress.assert_not_called()


def test_departed_consumer_dashboards_are_dropped(ctx, execs):
    """Scenario: dashboards from a removed consumer relation are not republished."""
    encoded = encode_as_dashboard({"title": "gone", "panels": []})
    # GIVEN a consumer relation is present in one reconcile ...
    consumer = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={
            "dashboards": json.dumps(
                {"templates": {"file:gone": {"charm": "some-charm", "content": encoded}}}
            )
        },
        id=55,
    )
    provider = Relation("grafana-dashboards-provider")
    state_with = State(
        relations=[consumer, provider],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    with ctx(ctx.on.update_status(), state=state_with) as mgr:
        out_with = mgr.run()
    assert "prog:rel_55__file:gone" in _published_templates(out_with)

    # WHEN the consumer relation is gone on a later reconcile (no consumer in state) ...
    state_without = State(
        relations=[Relation("grafana-dashboards-provider")],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    with ctx(ctx.on.update_status(), state=state_without) as mgr:
        out_without = mgr.run()

    # THEN the departed relation's dashboard is no longer published, but bundled ones remain.
    templates = _published_templates(out_without)
    assert "prog:rel_55__file:gone" not in templates
    assert "file:overview-dashboard" in templates


def test_reconcile_action_reports_success(ctx, execs):
    """Scenario: the reconcile action rebuilds the world and reports success."""
    state = State(
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    ctx.run(ctx.on.action("reconcile"), state)
    assert ctx.action_results == {"result": "Reconcile complete; world state rebuilt."}
