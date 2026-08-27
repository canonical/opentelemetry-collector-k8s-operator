# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Dashboard forwarding to Grafana."""

import json
from unittest.mock import MagicMock, patch

import pytest
from cosl import LZMABase64
from ops.model import ModelError
from ops.testing import Container, Exec, Relation, State
from scenario.errors import UncaughtCharmError
from scenario.mocking import _MockModelBackend

from src.integrations import _get_dashboards

DANGLING_RELATION_ID = 453

# The error Juju returns for hook commands on a relation that is gone from state.
PERMISSION_DENIED_ERROR = ModelError("ERROR permission denied ")

# Captured at import time, before any patching, so the patched methods can
# delegate healthy calls to the original implementation.
_original_relation_get = _MockModelBackend.relation_get
_original_relation_list = _MockModelBackend.relation_list


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


def _good_relation(rel_id: int) -> MagicMock:
    content = encode_as_dashboard({"whoami": str(rel_id)})
    rel = MagicMock()
    rel.id = rel_id
    rel.app.name = "some-charm"
    rel.data = {rel.app: {"dashboards": json.dumps(
        {"templates": {f"file:dashboard-{rel_id}": {"charm": "some-charm", "content": content}}}
    )}}
    return rel


def _permission_denied_relation_get(
    self: _MockModelBackend,
    relation_id: int,
    member_name: str,
    is_app: bool,
    *,
    relation_name: str | None = None,
):
    """Simulate a dangling relation whose remote application databag is unreadable.

    In Juju, reading the remote application databag of a relation that is gone
    (e.g. a removed cross-model relation) fails with "permission denied" instead
    of returning the (stale) data.
    """
    if relation_id == DANGLING_RELATION_ID and is_app:
        raise PERMISSION_DENIED_ERROR
    return _original_relation_get(self, relation_id, member_name, is_app, relation_name=relation_name)


def _permission_denied_relation_list(
    self: _MockModelBackend,
    relation_id: int,
    *,
    relation_name: str | None = None,
):
    """Simulate a dangling relation whose units cannot even be listed.

    In Juju, listing the units of a relation that is gone can also fail with
    "permission denied", which makes the construction of the Relation object
    itself fail: ops calls `relation-list` from `Relation.__init__` when the
    charm first accesses `model.relations` for the endpoint.
    """
    if relation_id == DANGLING_RELATION_ID:
        raise PERMISSION_DENIED_ERROR
    return _original_relation_list(self, relation_id, relation_name=relation_name)


def _unexpected_error_relation_get(
    self: _MockModelBackend,
    relation_id: int,
    member_name: str,
    is_app: bool,
    *,
    relation_name: str | None = None,
):
    """Simulate a dangling relation whose databag read fails unexpectedly.

    The error is a ModelError, but not the "permission denied" flavor.
    """
    if relation_id == DANGLING_RELATION_ID and is_app:
        raise ModelError("something else")
    return _original_relation_get(self, relation_id, member_name, is_app, relation_name=relation_name)


def _state_with_dangling_relation(execs: set[Exec]) -> State:
    """Return a state with a healthy and a dangling dashboard relation.

    A leader unit receiving a dashboard over a healthy relation and a dangling
    cross-model relation, related to a Grafana instance. The dangling relation
    carries a dashboard too, to prove that it is never forwarded.
    """
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
    consumer_dangling = Relation(
        "grafana-dashboards-consumer",
        remote_app_name="remote-8cdadb5a13d943d9868d3ed7ccc330ad",
        remote_app_data={"dashboards": json.dumps(data[1])},
        id=DANGLING_RELATION_ID,
    )
    provider = Relation("grafana-dashboards-provider")
    return State(
        relations=[consumer_healthy, consumer_dangling, provider],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )


def test_dashboard_propagation_with_dangling_relation(ctx, execs):
    """Scenario: Dashboards are forwarded even if a dangling relation's remote databag is unreadable."""
    # GIVEN a healthy relation with a dashboard, a dangling cross-model relation
    # (which also carries a dashboard), and a Grafana instance to forward them to
    state = _state_with_dangling_relation(execs)
    # WHEN any event executes the reconciler while the dangling relation's remote
    # application databag cannot be read (e.g. it was removed while this unit
    # was running a hook)
    with patch.object(_MockModelBackend, "relation_get", _permission_denied_relation_get):
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


def test_hook_survives_when_listing_the_dangling_relation_fails(ctx, execs):
    """Scenario: The hook survives even if listing a dangling relation's units fails.

    A dangling relation can be in a state where even `relation-list` is
    denied ("permission denied"), so the construction of the endpoint's
    Relation objects fails when the charm first accesses `model.relations`.
    The endpoint is then treated as empty for this run; dashboards flow
    again on the next event, once the relation is fully removed.
    """
    # GIVEN a healthy relation with a dashboard, a dangling cross-model relation
    # (which also carries a dashboard), and a Grafana instance to forward them to
    state = _state_with_dangling_relation(execs)
    # WHEN any event executes the reconciler while the dangling relation's units
    # cannot even be listed (e.g. `relation-list` denied during its teardown)
    with patch.object(_MockModelBackend, "relation_list", _permission_denied_relation_list):
        with ctx(ctx.on.update_status(), state=state) as mgr:
            state_out = mgr.run()
    # THEN the hook does not fail and Grafana receives otelcol's bundled dashboard
    for rel in state_out.relations:
        if "-provider" in rel.endpoint:
            dashboard_str = rel.local_app_data["dashboards"]
            assert "file:overview-dashboard" in dashboard_str
            # AND no dashboard from this endpoint is forwarded until the next event
            assert "dashboard-0" not in dashboard_str
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
    with patch.object(_MockModelBackend, "relation_get", _unexpected_error_relation_get):
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

