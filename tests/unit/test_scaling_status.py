# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: otelcol reports when scaling brings no benefit yet."""

from typing import Optional
from unittest.mock import patch

import pytest
from helpers import IssuedCertificate, issued_certificate
from ops.model import ModelError
from ops.testing import PeerRelation, Relation, State
from scenario.mocking import _MockModelBackend

FQDN = "otelcol-0.otelcol-endpoints.otel.svc.cluster.local"
WAITING_FOR_WIDENED_CERT = "Waiting for a certificate valid for the Kubernetes Service name"

# The error Juju returns for every hook command that aggregates model state once an
# unclean cross-model teardown leaves a dangling SAAS reference behind.
# See https://github.com/juju/juju/issues/23212.
SAAS_NOT_FOUND = ModelError(
    'ERROR saas application "remote-ae5b8839c0ca426c88d4c99c326d54" not found'
)


def _pod_only_certificate() -> IssuedCertificate:
    """A certificate that covers this pod but not the Kubernetes Service name."""
    return IssuedCertificate("otelcol-0", frozenset({FQDN}))


def _state(otelcol_container, peers_data: Optional[dict] = None) -> State:
    """A TLS-enabled otelcol. `peers_data=None` leaves the peer relation out entirely."""
    peers = [PeerRelation("peers", peers_data=peers_data)] if peers_data is not None else []
    return State(
        relations=[Relation(endpoint="receive-server-cert", interface="tls-certificate"), *peers],
        containers=otelcol_container,
        leader=True,
    )


def _reports_scaling_caveat(state_out: State) -> bool:
    return state_out.unit_status.message == WAITING_FOR_WIDENED_CERT


@pytest.mark.parametrize(
    "peers_data, expected",
    [(None, False), ({}, False), ({1: {}}, True)],
    ids=["no-peer-relation", "one-unit", "two-units"],
)
def test_scaling_caveat_is_reported_only_above_one_unit(
    ctx, otelcol_container, peers_data, expected
):
    """Scenario: the certificate does not cover the Service name, at several scales.

    While the certificate only covers this pod, every sender is pinned to it, so scaling
    buys nothing and the charm says so. With a single unit there is no traffic to spread
    and nothing to report. The unit count comes from the peer relation, which may also be
    absent altogether.
    """
    # GIVEN otelcol at some scale, with a certificate that only covers the pod name
    state = _state(otelcol_container, peers_data)
    # WHEN any event executes the reconciler
    with issued_certificate(_pod_only_certificate()):
        state_out = ctx.run(ctx.on.update_status(), state=state)
    # THEN the caveat is reported only when there is more than one unit
    assert _reports_scaling_caveat(state_out) is expected


def test_scaling_status_survives_a_broken_goal_state(ctx, otelcol_container):
    """Scenario: the model holds a dangling SAAS reference, so `goal-state` hard-fails.

    Regression test for https://github.com/juju/juju/issues/23212: an unclean cross-model
    teardown makes `goal-state` exit non-zero for every hook in the model. The scaling
    caveat is only a status message, so it must not be worth taking the whole charm to
    error state: the unit count comes from the peer relation instead.
    """
    # GIVEN a scaled otelcol whose certificate only covers the pod name
    state = _state(otelcol_container, {1: {}})
    # WHEN any event executes the reconciler while `goal-state` is failing
    with (
        patch.object(_MockModelBackend, "planned_units", side_effect=SAAS_NOT_FOUND),
        issued_certificate(_pod_only_certificate()),
    ):
        state_out = ctx.run(ctx.on.update_status(), state=state)
    # THEN the hook does not fail, and the caveat is still reported
    assert _reports_scaling_caveat(state_out)


def test_reconcile_never_calls_goal_state(ctx, otelcol_container):
    """Scenario: no code path in the reconciler may reach `goal-state`.

    Pins the workaround: a future caller of `planned_units()` would reintroduce the
    error state, and a spy is the only way to notice before it reaches production.
    """
    # GIVEN a scaled otelcol
    state = _state(otelcol_container, {1: {}})
    # WHEN any event executes the reconciler
    with patch.object(_MockModelBackend, "planned_units", return_value=2) as planned_units:
        ctx.run(ctx.on.update_status(), state=state)
    # THEN `goal-state` was never invoked
    assert planned_units.call_count == 0
