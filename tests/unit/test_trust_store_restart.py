# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: otelcol picks up a rebuilt system trust store.

Go loads the system cert pool once per process, so whenever the charm rebuilds the trust
store (``update-ca-certificates``) a running otelcol must be restarted to use it.

Restarts are observed at the Pebble client boundary (``restart_services``). Scenario does
not model the implicit restart ``replan()`` performs when a layer changes, so these tests
only see explicit restarts.
"""

import json
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterator, List, Set, Tuple
from unittest.mock import patch

import ops
import pytest
from ops.testing import Container, Context, Mount, Relation, State
from scenario.mocking import _MockPebbleClient

from constants import CA_TRUST_STAMP_PATH, SERVICE_NAME

CA_CERT = "-----BEGIN CERTIFICATE-----\n ... cos-ca ... \n-----END CERTIFICATE-----"
ROTATED_CA_CERT = "-----BEGIN CERTIFICATE-----\n ... rotated-ca ... \n-----END CERTIFICATE-----"
UPDATE_CA_CERTS = ["update-ca-certificates", "--fresh"]
ETC_OTELCOL = str(Path(CA_TRUST_STAMP_PATH).parent)


@dataclass
class RunResult:
    """What a single charm run did to the workload."""

    state: State
    commands: List[List[str]]
    restarted: Set[str]


@pytest.fixture(autouse=True)
def _no_alert_rendering():
    with patch("integrations._add_alerts"):
        yield


@contextmanager
def _record_restarts() -> Iterator[Set[str]]:
    """Collect the services restarted through Pebble, keeping the real behaviour."""
    restarted: Set[str] = set()
    original = _MockPebbleClient.restart_services

    def spy(self, services, *args, **kwargs):
        restarted.update(services)
        return original(self, services, *args, **kwargs)

    with patch.object(_MockPebbleClient, "restart_services", spy):
        yield restarted


def _run(ctx: Context, event, state: State) -> RunResult:
    """Run one event and report the commands executed and the services restarted."""
    ctx.exec_history.clear()
    with _record_restarts() as restarted:
        state_out = ctx.run(event, state)
    commands = [e.command for e in ctx.exec_history.get("otelcol", [])]
    return RunResult(state=state_out, commands=commands, restarted=restarted)


@pytest.fixture
def etc_otelcol(tmp_path) -> Path:
    """Backing dir for /etc/otelcol, so the trust stamp survives across runs.

    Scenario wipes the container filesystem between runs; mounting /etc/otelcol (where
    the stamp lives) lets each test decide whether the filesystem was reset or not.
    """
    path = tmp_path / "etc-otelcol"
    path.mkdir()
    return path


@pytest.fixture
def stamp_file(etc_otelcol) -> Path:
    return etc_otelcol / Path(CA_TRUST_STAMP_PATH).name


@pytest.fixture
def initial_state(execs, etc_otelcol) -> State:
    """A freshly deployed unit: otelcol not started yet, related to a CA."""
    return State(
        leader=True,
        containers=[
            Container(
                name="otelcol",
                can_connect=True,
                execs=execs,
                mounts={"etc-otelcol": Mount(location=ETC_OTELCOL, source=etc_otelcol)},
            )
        ],
        relations=[
            Relation("receive-ca-cert", remote_app_data={"certificates": json.dumps([CA_CERT])})
        ],
    )


@pytest.fixture
def running_state(ctx, initial_state, stamp_file) -> State:
    """A unit whose otelcol is already running with the layer the charm renders."""
    state_out = ctx.run(ctx.on.update_status(), initial_state)

    container = state_out.get_container("otelcol")
    assert container.service_statuses[SERVICE_NAME] == ops.pebble.ServiceStatus.ACTIVE
    assert stamp_file.exists()
    return state_out


def _container_restarted(ctx: Context, state: State, stamp_file: Path) -> Tuple:
    """Container restarted (e.g. OOMKilled): the stamp is gone, then pebble-ready fires."""
    stamp_file.unlink()
    return ctx.on.pebble_ready(state.get_container("otelcol")), state


def _ca_rotated(ctx: Context, state: State, stamp_file: Path) -> Tuple:
    """The CA sent over `receive-ca-cert` changes."""
    relation = state.get_relations("receive-ca-cert")[0]
    rotated = replace(
        relation, remote_app_data={"certificates": json.dumps([ROTATED_CA_CERT])}
    )
    return ctx.on.relation_changed(rotated), replace(state, relations=[rotated])


@pytest.mark.parametrize(
    "trigger",
    [
        pytest.param(_container_restarted, id="container-restarted"),
        pytest.param(_ca_rotated, id="ca-rotated"),
    ],
)
def test_running_otelcol_restarted_when_trust_store_rebuilt(
    ctx, running_state, stamp_file, trigger: Callable
):
    """Scenario: the trust store is rebuilt while otelcol is running.

    `container-restarted` reproduces the incident: the container restarts while a hook is
    in flight, the hook replans otelcol on the fresh filesystem (image CA bundle), and
    `pebble-ready` then rebuilds the trust store with an unchanged layer, so `replan()`
    alone would not restart otelcol.
    """
    # GIVEN otelcol is running
    # AND something invalidates the trust store
    event, state = trigger(ctx, running_state, stamp_file)

    # WHEN the charm reconciles
    result = _run(ctx, event, state)

    # THEN the trust store is rebuilt
    assert UPDATE_CA_CERTS in result.commands
    # AND otelcol is restarted so it loads the rebuilt cert pool
    assert SERVICE_NAME in result.restarted


def test_otelcol_not_restarted_when_trust_store_unchanged(ctx, running_state):
    """Scenario: a regular reconcile with no certificate changes."""
    # GIVEN otelcol is running and the trust store is up to date
    # WHEN any event is emitted
    result = _run(ctx, ctx.on.update_status(), running_state)

    # THEN the trust store is not rebuilt
    assert UPDATE_CA_CERTS not in result.commands
    # AND otelcol is not restarted
    assert SERVICE_NAME not in result.restarted


def test_otelcol_not_restarted_on_first_start(ctx, initial_state):
    """Scenario: first deployment, otelcol has never been started."""
    # GIVEN otelcol is not running yet
    # WHEN any event is emitted
    result = _run(ctx, ctx.on.update_status(), initial_state)

    # THEN the trust store is built
    assert UPDATE_CA_CERTS in result.commands
    # AND otelcol is started by replan, without an extra restart
    container = result.state.get_container("otelcol")
    assert container.service_statuses[SERVICE_NAME] == ops.pebble.ServiceStatus.ACTIVE
    assert SERVICE_NAME not in result.restarted
