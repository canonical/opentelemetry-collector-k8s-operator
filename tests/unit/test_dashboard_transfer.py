# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Dashboard forwarding to Grafana."""

import json
from typing import Dict, Optional, Sequence, Tuple
from unittest.mock import MagicMock, patch

import pytest
from cosl import LZMABase64
from ops.model import ModelError
from ops.testing import Container, Exec, Relation, State
from scenario.errors import UncaughtCharmError
from scenario.mocking import _MockModelBackend

from src.integrations import _get_dashboards

DANGLING_RELATION_ID = 453

# The charm name an upstream otelcol stamps on the templates it forwards, i.e. its
# own `meta.name`, not the name of the charm the dashboard originally came from.
UPSTREAM_CHARM = "opentelemetry-collector"

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


def _state_with_dangling_relation(
    execs: set[Exec], provider_app_data: Optional[Dict[str, str]] = None
) -> State:
    """Return a state with a healthy and a dangling dashboard relation.

    A leader unit receiving a dashboard over a healthy relation and a dangling
    cross-model relation, related to a Grafana instance. The dangling relation
    carries a dashboard too, to prove that it is never forwarded.

    Args:
        execs: the container execs the charm is allowed to run.
        provider_app_data: the dashboards already published to Grafana, if any.
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
    provider = Relation("grafana-dashboards-provider", local_app_data=provider_app_data or {})
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


def test_already_forwarded_dashboards_survive_when_listing_relations_fails(ctx, execs):
    """Scenario: A dangling relation does not delete the dashboards already sent to Grafana.

    A dangling relation can be in a state where even `relation-list` is denied
    ("permission denied"), so the construction of the endpoint's Relation
    objects fails when the charm first accesses `model.relations`. Since ops
    builds the whole endpoint at once, the received dashboards are unknown for
    this run, which is not the same as "there are no dashboards": republishing
    an empty set would delete from Grafana the dashboards of the healthy
    relations, which are still valid. The previously published dashboards are
    left untouched instead.
    """
    # GIVEN dashboards already published to Grafana
    already_published = {
        "templates": {
            "file:juju_file:dashboard-0-some-charm-100": {
                "charm": "some-charm",
                "content": encode_as_dashboard({"whoami": "0"}),
            },
            "file:overview-dashboard": {
                "charm": "opentelemetry-collector-k8s",
                "content": encode_as_dashboard({"whoami": "overview"}),
            },
        },
        "uuid": "some-uuid",
    }
    provider_app_data = {"dashboards": json.dumps(already_published)}
    # AND a healthy relation with a dashboard and a dangling cross-model relation
    state = _state_with_dangling_relation(execs, provider_app_data=provider_app_data)
    # WHEN any event executes the reconciler while the dangling relation's units
    # cannot even be listed (e.g. `relation-list` denied during its teardown)
    with patch.object(_MockModelBackend, "relation_list", _permission_denied_relation_list):
        with ctx(ctx.on.update_status(), state=state) as mgr:
            state_out = mgr.run()
    # THEN the hook does not fail and the published dashboards are left untouched
    for rel in state_out.relations:
        if "-provider" in rel.endpoint:
            assert rel.local_app_data == provider_app_data


def test_hook_survives_when_listing_the_dangling_relation_fails(ctx, execs):
    """Scenario: The hook survives even if listing a dangling relation's units fails."""
    # GIVEN nothing has been forwarded to Grafana yet
    state = _state_with_dangling_relation(execs)
    # WHEN any event executes the reconciler while the dangling relation's units
    # cannot even be listed (e.g. `relation-list` denied during its teardown)
    with patch.object(_MockModelBackend, "relation_list", _permission_denied_relation_list):
        with ctx(ctx.on.update_status(), state=state) as mgr:
            state_out = mgr.run()
    # THEN the hook does not fail and nothing is published for this endpoint,
    # not even otelcol's bundled dashboards: they are forwarded on the next
    # event, once the dangling relation is fully removed
    for rel in state_out.relations:
        if "-provider" in rel.endpoint:
            assert "dashboards" not in rel.local_app_data


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


def _cos_agent_id(title: str, uid: str, app: str, cos_agent_rel_id: int) -> str:
    """Return the template id an upstream otelcol publishes for a cos-agent dashboard.

    The id embeds the *originating application*, because `cos_agent` sets `charm`
    to f"{relation_name}-{app_name}", so two applications of the same charm never
    share an id even when the dashboard is identical. Shape copied verbatim from a
    real deployment databag.
    """
    return f"file:juju_{title.lower()}-cos-agent-{app}-{cos_agent_rel_id}-{uid}"


def _cos_agent_templates(
    title: str, uid: str, apps_and_relids: Sequence[Tuple[str, int]]
) -> Dict[str, Dict[str, str]]:
    """Templates for one dashboard forwarded on behalf of several applications.

    Every entry is byte-identical except for its id.
    """
    content = encode_as_dashboard({"title": title, "uid": uid, "panels": []})
    return {
        _cos_agent_id(title, uid, app, relid): {
            "charm": UPSTREAM_CHARM,
            "content": content,
        }
        for app, relid in apps_and_relids
    }


def _consumer(templates: Dict[str, Dict[str, str]], rel_id: int) -> Relation:
    """A consumer relation whose remote app is another aggregator (e.g. a machine otelcol)."""
    return Relation(
        "grafana-dashboards-consumer",
        remote_app_name="otelcol",
        remote_app_data={"dashboards": json.dumps({"templates": templates})},
        id=rel_id,
    )


def _mock_relation(rel_id: int, templates: Dict[str, Dict[str, str]]) -> MagicMock:
    """A mocked consumer relation, for the cases Scenario cannot express."""
    rel = MagicMock()
    rel.id = rel_id
    rel.app.name = "otelcol"
    rel.data = {rel.app: {"dashboards": json.dumps({"templates": templates})}}
    return rel


def _state_with(*consumers: Relation, execs: set, provider_id: int = 199) -> State:
    """A leader otelcol related to the given consumers and to one Grafana."""
    return State(
        relations=[*consumers, Relation("grafana-dashboards-provider", id=provider_id)],
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )


def _published_templates(state_out: State) -> Dict[str, Dict[str, str]]:
    """Return the templates published on the provider relation.

    Asserts the relation was found, so callers cannot pass vacuously.
    """
    providers = [
        rel for rel in state_out.relations if rel.endpoint == "grafana-dashboards-provider"
    ]
    assert len(providers) == 1, f"expected exactly one provider relation, got {providers}"
    databag = providers[0].local_app_data
    assert "dashboards" in databag, f"nothing was published to Grafana: {databag}"
    return json.loads(databag["dashboards"])["templates"]


# One dashboard, forwarded on behalf of three applications of the same charm, each
# with its own cos-agent relation id upstream. Copied from a real deployment databag.
DASHBOARD_TITLE = "pgBackRest"
DASHBOARD_UID = "4b5991b44a703b4e3b89a60b70bb531c3a1ba8f7"
PG_APPS = [("pg", 24), ("pgsql", 25), ("postgresql", 10)]


def _copies(*apps_and_relids: Tuple[str, int], on_relation: int) -> Relation:
    """A consumer relation carrying one identical copy of the dashboard per application."""
    templates = _cos_agent_templates(DASHBOARD_TITLE, DASHBOARD_UID, apps_and_relids)
    return _consumer(templates, on_relation)


def _survivor(app: str, cos_agent_rel_id: int, *, on_relation: int) -> str:
    """The id Grafana must receive for the copy that survives deduplication.

    otelcol republishes a received template as `juju_{id}-{charm}-{rel_id}`, see
    `_add_dashboards`.
    """
    received = _cos_agent_id(DASHBOARD_TITLE, DASHBOARD_UID, app, cos_agent_rel_id)
    return f"file:juju_{received}-{UPSTREAM_CHARM}-{on_relation}"


@pytest.mark.parametrize(
    "consumers",
    [
        [_copies(("pg", 24), ("pgsql", 25), ("postgresql", 10), on_relation=107)],
        [_copies(("postgresql", 10), ("pgsql", 25), ("pg", 24), on_relation=107)],
        [_copies(("pg", 24), on_relation=107), _copies(("pgsql", 25), on_relation=108)],
    ],
    ids=["all-three-on-one-relation", "same-three-reversed", "one-each-on-two-relations"],
)
def test_identical_dashboards_are_published_once(ctx, execs, consumers):
    """Scenario: the same dashboard forwarded once per originating application.

    The shape otelcol sees when its client is itself an aggregator. Grafana
    discards these copies by their `.uid` anyway, so forwarding each of them only
    inflates the databag and Grafana's rendering work.

    Every case below sends the very same copies, only spread and ordered
    differently, and expects the very same survivor: the published id embeds the
    `charm` and `relation_id` of the winner, so a winner that depended on iteration
    order would rewrite the databag - and churn Grafana - with no semantic change.
    """
    # GIVEN consumer relations carrying byte-identical copies of one dashboard
    received = [
        template
        for consumer in consumers
        for template in json.loads(consumer.remote_app_data["dashboards"])["templates"]
    ]
    # (guard: without duplicates to collapse, the case proves nothing)
    assert len(received) > 1
    # WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=_state_with(*consumers, execs=execs)) as mgr:
        state_out = mgr.run()
    # THEN however the copies arrived, the same one survives - the lowest
    # (charm, title), which every case places on relation 107 - next to otelcol's
    # own bundled dashboard
    assert sorted(_published_templates(state_out)) == sorted(
        [_survivor("pg", 24, on_relation=107), "file:overview-dashboard"]
    )


def test_deduplication_ties_are_broken_by_relation_id():
    """Scenario: two aggregators forward the exact same dashboard under the same id.

    `(charm, title)` does not order these apart, so without the relation id as a
    final tiebreaker the published id would depend on iteration order.

    Kept as a direct test because Scenario cannot represent an ordering of
    relations: `State.relations` is a frozenset, so both orders below are the same
    state to Scenario.
    """
    # GIVEN two relations carrying the same dashboard under the very same id
    templates = _cos_agent_templates(DASHBOARD_TITLE, DASHBOARD_UID, [("pg", 24)])
    lower = _mock_relation(107, templates)
    higher = _mock_relation(108, templates)
    # WHEN the dashboards are collected in either order
    forward = _get_dashboards([lower, higher])
    backward = _get_dashboards([higher, lower])
    # THEN one copy is kept, and it is always the one from the lowest relation id
    assert len(forward) == len(backward) == 1
    assert forward[0]["relation_id"] == backward[0]["relation_id"] == 107


def test_duplicates_are_not_decompressed(ctx, execs):
    """Scenario: the copies that are dropped never get decompressed.

    Deduplicating on the compressed blob keeps the per-hook LZMA work proportional
    to the number of distinct dashboards rather than of applications.
    `_get_dashboards` is the only decompression in this charm's reconcile path, so
    the spy cannot be polluted by other integrations.
    """
    # GIVEN one dashboard forwarded on behalf of 3 applications
    templates = _cos_agent_templates(DASHBOARD_TITLE, DASHBOARD_UID, PG_APPS)
    # WHEN any event executes the reconciler
    with patch(
        "src.integrations.LZMABase64.decompress", wraps=LZMABase64.decompress
    ) as decompress:
        with ctx(
            ctx.on.update_status(), state=_state_with(_consumer(templates, 107), execs=execs)
        ) as mgr:
            state_out = mgr.run()
    # THEN only the surviving dashboard was decompressed
    assert len(_published_templates(state_out)) == 2  # the survivor + otelcol's own
    assert decompress.call_count == 1


def test_distinct_dashboards_sharing_a_template_id_are_both_forwarded(ctx, execs):
    """Scenario: two charms ship a dashboard under the same file name.

    Regression test: deduplicating by template id collapsed these into one and
    silently dropped a dashboard Grafana would have displayed. They must also land
    on disk under different file names to survive all the way to Grafana.
    """
    # GIVEN two consumer relations whose dashboards share a template id but differ
    state = _state_with(
        *(
            _consumer(
                {
                    "file:overview": {
                        "charm": f"charm-{suffix}",
                        "content": encode_as_dashboard({"whoami": suffix}),
                    }
                },
                rel_id,
            )
            for suffix, rel_id in (("a", 110), ("b", 111))
        ),
        execs=execs,
    )
    # WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()
    # THEN both reach Grafana, distinguished by charm and relation id
    published = _published_templates(state_out)
    assert sorted(published) == [
        "file:juju_file:overview-charm-a-110",
        "file:juju_file:overview-charm-b-111",
        "file:overview-dashboard",
    ]


@pytest.mark.parametrize(
    "broken",
    [
        {"charm": "charm-a"},
        {"charm": "charm-a", "content": ""},
        {"charm": "charm-a", "content": 12345},
        {"charm": "charm-a", "content": "bm90IGx6bWEgYXQgYWxs"},
        {"charm": "charm-a", "content": encode_as_dashboard({"whoami": "truncated"})[:-4]},
    ],
    ids=["no-content", "empty-content", "non-string-content", "not-lzma", "truncated"],
)
def test_unusable_dashboards_are_skipped(ctx, execs, broken):
    """Scenario: a template arrives with content otelcol cannot decode.

    Every case below used to reach the decompressor and take the whole hook down
    with it, dropping the dashboards of every healthy relation too.
    """
    # GIVEN an undecodable template, next to a healthy one
    templates = {
        "file:broken": broken,
        "file:healthy": {"charm": "charm-a", "content": encode_as_dashboard({"whoami": "ok"})},
    }
    # WHEN any event executes the reconciler
    with ctx(
        ctx.on.update_status(), state=_state_with(_consumer(templates, 107), execs=execs)
    ) as mgr:
        state_out = mgr.run()
    # THEN the broken one is skipped and the healthy one still reaches Grafana
    published = _published_templates(state_out)
    assert sorted(published) == [
        "file:juju_file:healthy-charm-a-107",
        "file:overview-dashboard",
    ]
