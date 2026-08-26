# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Dashboard forwarding to Grafana."""

import json
from unittest.mock import MagicMock, patch

import pytest
from cosl import LZMABase64
from ops.model import ModelError
from ops.testing import Container, Relation, State
from scenario.errors import UncaughtCharmError
from scenario.mocking import _MockModelBackend

from src.integrations import _get_dashboards


def encode_as_dashboard(dct: dict):
    return LZMABase64.compress(json.dumps(dct))


def test_dashboard_propagation(ctx, execs):
    """Scenario: Dashboards are forwarded when a dashboard provider is related."""
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
        for rel in state_out.relations:
            # THEN each Grafana instance receives otelcol's bundled dashboard and aggregated dashboards
            if "-provider" in rel.endpoint:
                dashboard_str = rel.local_app_data["dashboards"]
                assert "file:juju_file:dashboard-0-some-charm-100" in dashboard_str
                assert "file:juju_file:dashboard-1-some-charm-101" in dashboard_str
                assert "file:overview-dashboard" in dashboard_str


DANGLING_RELATION_ID = 453

# Captured at import time, before any patching, so the patched method can delegate
# healthy reads to the original implementation.
_original_relation_get = _MockModelBackend.relation_get


def _good_relation(rel_id: int) -> MagicMock:
    content = encode_as_dashboard({"whoami": str(rel_id)})
    rel = MagicMock()
    rel.id = rel_id
    rel.app.name = "some-charm"
    rel.data = {rel.app: {"dashboards": json.dumps(
        {"templates": {f"file:dashboard-{rel_id}": {"charm": "some-charm", "content": content}}}
    )}}
    return rel

def _unreadable_remote_databag(error: Exception):
    """Build a _MockModelBackend.relation_get patch simulating a dangling relation.

    In Juju, reading the remote application databag of a relation that is gone
    (e.g. a removed cross-model relation) fails with "permission denied" instead
    of returning the (stale) data.
    """

    def relation_get(
        self: _MockModelBackend,
        relation_id: int,
        member_name: str,
        is_app: bool,
        *,
        relation_name: str | None = None,
    ):
        if relation_id == DANGLING_RELATION_ID and is_app:
            raise error
        return _original_relation_get(
            self, relation_id, member_name, is_app, relation_name=relation_name
        )

    return relation_get


@pytest.mark.parametrize(
    "error",
    [
        ModelError("ERROR permission denied "),
        ModelError(b"ERROR permission denied\n"),
    ],
)
def test_dashboard_propagation_with_dangling_relation(ctx, execs, error):
    """Scenario: Dashboards are forwarded even if a dangling relation's remote databag is unreadable."""
    # GIVEN a healthy remote charm with a dashboard
    data = {
        idx: {
            "templates": {
                f"file:dashboard-{idx}": {
                    "charm": "some-charm",
                    "content": encode_as_dashboard({"whoami": str(idx)}),
                }
            }
        }
        for idx in (0, 1)
    }
    consumer_healthy = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={"dashboards": json.dumps(data[0])},
        id=100,
    )
    # AND a dangling cross-model relation: still listed by Juju, but its remote
    # application databag cannot be read (e.g. it was removed while this unit
    # was running a hook)
    consumer_dangling = Relation(
        "grafana-dashboards-consumer",
        remote_app_name="remote-8cdadb5a13d943d9868d3ed7ccc330ad",
        remote_app_data={"dashboards": json.dumps(data[1])},
        id=DANGLING_RELATION_ID,
    )
    # AND otelcol is related to a Grafana instance
    provider = Relation("grafana-dashboards-provider")

    state = State(
        relations=[consumer_healthy, consumer_dangling, provider],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    # WHEN any event executes the reconciler
    with patch.object(_MockModelBackend, "relation_get", _unreadable_remote_databag(error)):
        with ctx(ctx.on.update_status(), state=state) as mgr:
            state_out = mgr.run()
    # THEN Grafana receives otelcol's bundled dashboard and the healthy relation's dashboard
    for rel in state_out.relations:
        if "-provider" in rel.endpoint:
            dashboard_str = rel.local_app_data["dashboards"]
            assert "file:juju_file:dashboard-0-some-charm-100" in dashboard_str
            assert "file:overview-dashboard" in dashboard_str
            # AND the dangling relation's dashboard is not forwarded
            assert "dashboard-1" not in dashboard_str


def test_unexpected_model_error_fails_the_hook(ctx, execs):
    """Scenario: Unexpected ModelErrors while reading dashboards fail the hook."""
    # GIVEN a dangling relation whose remote application databag read fails
    # with an unexpected error (not "permission denied")
    consumer_dangling = Relation(
        "grafana-dashboards-consumer",
        remote_app_name="remote-8cdadb5a13d943d9868d3ed7ccc330ad",
        id=DANGLING_RELATION_ID,
    )

    state = State(
        relations=[consumer_dangling, Relation("grafana-dashboards-provider")],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    # WHEN any event executes the reconciler
    with patch.object(
        _MockModelBackend,
        "relation_get",
        _unreadable_remote_databag(ModelError("something else")),
    ):
        # THEN the hook fails with an uncaught charm error
        # (this charm reconciles in __init__, so the error surfaces on context entry)
        with pytest.raises(UncaughtCharmError):
            with ctx(ctx.on.update_status(), state=state) as mgr:
                mgr.run()


def test_unreadable_remote_databag_without_app_is_skipped():
    """A relation without a remote app (e.g. breaking) is skipped, not fatal.

    Kept as a direct test because Scenario cannot represent a relation whose
    remote application is unknown.
    """
    # GIVEN a relation whose remote app is gone (e.g. while breaking)
    gone = MagicMock()
    gone.app = None
    # AND a healthy relation with a dashboard
    healthy = _good_relation(100)
    # WHEN the dashboards are collected
    dashboards = _get_dashboards([gone, healthy])
    # THEN the app-less relation is skipped and the healthy dashboard is returned
    assert [dash["title"] for dash in dashboards] == ["file:dashboard-100"]

