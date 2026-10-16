# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: otelcol picks up a rebuilt system trust store."""

import json
from dataclasses import dataclass, replace
from functools import partialmethod
from pathlib import Path
from typing import Callable, List, Optional, Tuple
from unittest.mock import patch

import ops
import pytest
from helpers import recorded_pebble_restarts
from ops.testing import Container, Context, Mount, Relation, State
from scenario.errors import UncaughtCharmError
from scenario.mocking import _MockPebbleClient

from constants import CA_TRUST_RESTART_PENDING, CA_TRUST_STAMP_PATH, SERVICE_NAME

CA_CERT = "-----BEGIN CERTIFICATE-----\n ... cos-ca ... \n-----END CERTIFICATE-----"
ROTATED_CA_CERT = "-----BEGIN CERTIFICATE-----\n ... rotated-ca ... \n-----END CERTIFICATE-----"
UPDATE_CA_CERTS = ["update-ca-certificates", "--fresh"]
ETC_OTELCOL = str(Path(CA_TRUST_STAMP_PATH).parent)
OTHER_HASH = "0" * 64


@dataclass
class RunResult:
    """What a single charm run did to the workload."""

    state: State
    commands: List[List[str]]
    restarted: List[str]
    implicitly_restarted: bool

    @property
    def restarts(self) -> int:
        """How many times a running otelcol was restarted, explicitly or by `replan()`."""
        return self.restarted.count(SERVICE_NAME) + int(self.implicitly_restarted)


@pytest.fixture(autouse=True)
def _no_alert_rendering():
    with patch("integrations._add_alerts"):
        yield


def _otelcol_service(state: State):
    service = state.get_container("otelcol").plan.services.get(SERVICE_NAME)
    return service.to_dict() if service else None


def _otelcol_running(state: State) -> bool:
    statuses = state.get_container("otelcol").service_statuses
    return statuses.get(SERVICE_NAME) == ops.pebble.ServiceStatus.ACTIVE


def _run(ctx: Context, event, state: State) -> RunResult:
    """Run one event and report the commands executed and the services restarted."""
    ctx.exec_history.clear()
    with recorded_pebble_restarts() as restarted:
        state_out = ctx.run(event, state)
    commands = [e.command for e in ctx.exec_history.get("otelcol", [])]
    # Scenario doesn't model `replan()` restarting a running service whose definition changed.
    implicitly_restarted = (
        _otelcol_running(state)
        and _otelcol_running(state_out)
        and _otelcol_service(state) != _otelcol_service(state_out)
    )
    return RunResult(
        state=state_out,
        commands=commands,
        restarted=restarted,
        implicitly_restarted=implicitly_restarted,
    )


@pytest.fixture
def etc_otelcol(tmp_path) -> Path:
    """Backing dir for /etc/otelcol, so the trust stamp survives across runs."""
    path = tmp_path / "etc-otelcol"
    path.mkdir()
    return path


@pytest.fixture
def stamp_file(etc_otelcol) -> Path:
    return etc_otelcol / Path(CA_TRUST_STAMP_PATH).name


def _pending(trust_hash: str) -> str:
    """Return the stamp of a trust store otelcol has not loaded yet."""
    return f"{trust_hash}\n{CA_TRUST_RESTART_PENDING}"


def _read_stamp(stamp_file: Path) -> Tuple[str, bool]:
    """Return the stamp's hash, and whether a restart is pending."""
    content = stamp_file.read_text()
    if content.endswith(f"\n{CA_TRUST_RESTART_PENDING}"):
        return content.removesuffix(f"\n{CA_TRUST_RESTART_PENDING}"), True
    return content, False


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
    """A unit whose otelcol is running with the layer the charm renders."""
    state_out = ctx.run(ctx.on.update_status(), initial_state)

    container = state_out.get_container("otelcol")
    assert container.service_statuses[SERVICE_NAME] == ops.pebble.ServiceStatus.ACTIVE
    assert stamp_file.exists()
    return state_out


@pytest.fixture
def trust_hash(running_state, stamp_file) -> str:
    """The hash of the trust store loaded by otelcol in `running_state`."""
    trust_hash, pending = _read_stamp(stamp_file)
    assert not pending
    assert len(trust_hash) == 64 and all(c in "0123456789abcdef" for c in trust_hash)
    return trust_hash


def _container_restarted(ctx: Context, state: State, stamp_file: Path) -> Tuple:
    """The container restarted (e.g. OOMKilled): stamp wiped, then pebble-ready."""
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
    ctx, running_state, stamp_file, trust_hash, trigger: Callable
):
    """Scenario: the trust store is rebuilt while otelcol is running."""
    # GIVEN otelcol is running
    # AND something invalidates the trust store (`container-restarted` is issue #415)
    event, state = trigger(ctx, running_state, stamp_file)

    # WHEN the charm reconciles
    result = _run(ctx, event, state)

    # THEN the trust store is rebuilt
    assert UPDATE_CA_CERTS in result.commands
    # AND otelcol is restarted so it loads the rebuilt cert pool
    assert result.restarts >= 1
    # AND the stamp records the rebuilt trust store as loaded
    new_hash, pending = _read_stamp(stamp_file)
    assert not pending
    assert (new_hash == trust_hash) == (trigger is _container_restarted)


@pytest.mark.parametrize(
    "trigger",
    [
        pytest.param(_container_restarted, id="container-restarted"),
        pytest.param(
            _ca_rotated,
            id="ca-rotated",
            marks=pytest.mark.xfail(
                strict=True,
                reason="Tolerated: replan() restarts on the layer change, then the trust store "
                "logic restarts again.",
            ),
        ),
    ],
)
def test_running_otelcol_restarted_only_once_when_trust_store_rebuilt(
    ctx, running_state, stamp_file, trigger: Callable
):
    """Scenario: a trust store rebuild restarts otelcol exactly once."""
    # GIVEN otelcol is running
    # AND something invalidates the trust store
    event, state = trigger(ctx, running_state, stamp_file)

    # WHEN the charm reconciles
    result = _run(ctx, event, state)

    # THEN otelcol is restarted exactly once
    assert result.restarts == 1


def test_otelcol_not_restarted_when_trust_store_unchanged(
    ctx, running_state, stamp_file, trust_hash
):
    """Scenario: a regular reconcile with no certificate changes."""
    # GIVEN otelcol is running and the trust store is up to date
    # WHEN any event is emitted
    result = _run(ctx, ctx.on.update_status(), running_state)

    # THEN the trust store is not rebuilt
    assert UPDATE_CA_CERTS not in result.commands
    # AND otelcol is not restarted
    assert result.restarts == 0
    # AND the stamp is left as is
    assert stamp_file.read_text() == trust_hash


def test_otelcol_not_restarted_on_first_start(ctx, initial_state, stamp_file):
    """Scenario: first deployment, otelcol has never been started."""
    # GIVEN otelcol is not running yet
    # WHEN any event is emitted
    result = _run(ctx, ctx.on.update_status(), initial_state)

    # THEN the trust store is built
    assert UPDATE_CA_CERTS in result.commands
    # AND otelcol is started by replan, without an extra restart
    assert _otelcol_running(result.state)
    assert result.restarts == 0
    # AND the stamp records the trust store as loaded
    _, pending = _read_stamp(stamp_file)
    assert not pending


def test_restart_survives_a_reconcile_that_returns_early(
    ctx, running_state, stamp_file, trust_hash
):
    """Scenario: the trust store is rebuilt by a reconcile that stops before `replan()`."""
    # GIVEN otelcol is running
    # AND the container restarted, so the trust store has to be rebuilt
    event, state = _container_restarted(ctx, running_state, stamp_file)
    # AND an invalid config blocks the charm before it reaches `replan()`
    blocked = replace(state, config={"global_scrape_interval": "bogus"})

    # WHEN the charm reconciles
    result = _run(ctx, event, blocked)

    # THEN the trust store is rebuilt, but otelcol is left untouched while blocked
    assert UPDATE_CA_CERTS in result.commands
    assert isinstance(result.state.unit_status, ops.BlockedStatus)
    assert result.restarts == 0
    # AND the stamp records the restart as pending
    assert stamp_file.read_text() == _pending(trust_hash)

    # WHEN the config is fixed (back to the value otelcol runs with, so the layer is unchanged)
    fixed = replace(result.state, config={})
    result = _run(ctx, ctx.on.config_changed(), fixed)

    # THEN otelcol is restarted, without rebuilding the trust store again
    assert UPDATE_CA_CERTS not in result.commands
    assert result.restarts >= 1
    # AND the stamp records the trust store as loaded
    assert stamp_file.read_text() == trust_hash

    # AND later reconciles do not restart it again
    result = _run(ctx, ctx.on.update_status(), result.state)
    assert result.restarts == 0


class _HookFailed(Exception):
    pass


def _fail_before_replan():
    """An error between the trust store rebuild and `replan()`."""
    return patch("integrations.receive_otlp", side_effect=_HookFailed)


def _fail_on_restart():
    """The explicit restart itself fails (e.g. a Pebble error)."""
    return patch.object(_MockPebbleClient, "restart_services", side_effect=_HookFailed)


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(_fail_before_replan, id="fails-before-replan"),
        pytest.param(_fail_on_restart, id="fails-on-restart"),
    ],
)
def test_restart_survives_a_failed_hook(
    ctx, running_state, stamp_file, trust_hash, failure: Callable
):
    """Scenario: the hook that rebuilt the trust store fails before otelcol is restarted."""
    # GIVEN otelcol is running
    # AND the container restarted, so the trust store has to be rebuilt
    event, state = _container_restarted(ctx, running_state, stamp_file)

    # WHEN the hook fails after the trust store was rebuilt
    with failure(), pytest.raises(UncaughtCharmError):
        ctx.run(event, state)
    # THEN the stamp records the restart as pending
    assert stamp_file.read_text() == _pending(trust_hash)

    # WHEN Juju retries the hook
    result = _run(ctx, event, state)

    # THEN otelcol is restarted, without rebuilding the trust store again (only the stamp
    # tells it a restart is due)
    assert UPDATE_CA_CERTS not in result.commands
    assert result.restarts >= 1
    # AND the stamp records the trust store as loaded
    assert stamp_file.read_text() == trust_hash

    # AND later reconciles do not restart it again
    result = _run(ctx, ctx.on.update_status(), result.state)
    assert result.restarts == 0


def _wipe_stamp_then_call(client, original: Callable, stamp_file: Path, *args, **kwargs):
    """Wipe the stamp, as a container restart would, then call `original`."""
    stamp_file.unlink(missing_ok=True)
    return original(client, *args, **kwargs)


def _container_restarts_on(pebble_call: str, stamp_file: Path):
    """Restart the container (wipe its filesystem) just before the hook makes `pebble_call`."""
    original = getattr(_MockPebbleClient, pebble_call)
    return patch.object(
        _MockPebbleClient,
        pebble_call,
        partialmethod(_wipe_stamp_then_call, original, stamp_file),
    )


@pytest.mark.parametrize(
    "pebble_call",
    [
        pytest.param("replan_services", id="before-replan"),
        pytest.param("restart_services", id="before-restart"),
    ],
)
def test_container_restart_mid_hook_does_not_mark_trust_store_loaded(
    ctx, running_state, stamp_file, trust_hash, pebble_call: str
):
    """Scenario: the container restarts during a hook that rebuilt the trust store."""
    # GIVEN otelcol is running
    # AND the container restarted, so pebble-ready rebuilds the trust store
    event, state = _container_restarted(ctx, running_state, stamp_file)

    # WHEN the container restarts again while that hook is still running
    with _container_restarts_on(pebble_call, stamp_file):
        _run(ctx, event, state)

    # THEN the new container has no stamp, as its trust store was never rebuilt
    assert not stamp_file.exists()

    # WHEN pebble-ready fires for the new container
    result = _run(ctx, event, state)

    # THEN the trust store is rebuilt
    assert UPDATE_CA_CERTS in result.commands
    # AND otelcol is restarted to load it
    assert result.restarts >= 1
    # AND the stamp records the trust store as loaded
    assert stamp_file.read_text() == trust_hash


@pytest.mark.parametrize(
    "stamp, rebuilt, restarts",
    [
        # `{hash}`: hash of the current certs; `{HASH}`: the same, upper-cased.
        # Also the stamp format of older revisions.
        pytest.param("{hash}", False, 0, id="loaded"),
        pytest.param(_pending("{hash}"), False, 1, id="restart-pending"),
        # Anything else: rebuild, then restart to load it.
        pytest.param(None, True, 1, id="missing"),
        pytest.param("", True, 1, id="empty"),
        pytest.param("{hash}\n", True, 1, id="trailing-newline"),
        pytest.param("{HASH}", True, 1, id="different-case"),
        pytest.param(CA_TRUST_RESTART_PENDING, True, 1, id="suffix-only"),
        pytest.param("{hash}\nsomething-else", True, 1, id="unknown-suffix"),
        pytest.param(_pending("{hash}") + "\n", True, 1, id="pending+newline"),
        pytest.param(OTHER_HASH, True, 1, id="other-hash"),
        pytest.param(_pending(OTHER_HASH), True, 1, id="other-hash-pending"),
    ],
)
def test_trust_stamp_is_interpreted_strictly(
    ctx,
    running_state,
    stamp_file,
    trust_hash,
    stamp: Optional[str],
    rebuilt: bool,
    restarts: int,
):
    """Scenario: a reconcile finds the trust stamp in a given state."""
    # GIVEN otelcol is running, with the certs it was started with unchanged
    # AND the stamp in the given state
    if stamp is None:
        stamp_file.unlink()
    else:
        stamp_file.write_text(stamp.format(hash=trust_hash, HASH=trust_hash.upper()))

    # WHEN the charm reconciles
    result = _run(ctx, ctx.on.update_status(), running_state)

    # THEN the trust store is rebuilt only if the stamp is not a known state for these certs
    assert (UPDATE_CA_CERTS in result.commands) == rebuilt
    # AND otelcol is restarted only if it has not loaded the trust store yet
    assert result.restarts == restarts
    # AND the stamp ends up recording the trust store as loaded
    assert stamp_file.read_text() == trust_hash


def test_ca_rotated_while_restart_pending(ctx, running_state, stamp_file, trust_hash):
    """Scenario: the CA rotates before a pending restart has happened."""
    # GIVEN otelcol is running, but has not loaded the trust store built for its certs
    stamp_file.write_text(_pending(trust_hash))
    # AND the CA rotates, so the pending stamp is for outdated certs
    event, state = _ca_rotated(ctx, running_state, stamp_file)

    # WHEN the charm reconciles
    result = _run(ctx, event, state)

    # THEN the trust store is rebuilt for the rotated CA
    assert UPDATE_CA_CERTS in result.commands
    # AND otelcol is restarted to load it
    assert result.restarts >= 1
    # AND the stamp records the new trust store as loaded
    new_hash, pending = _read_stamp(stamp_file)
    assert not pending
    assert new_hash != trust_hash


def test_pending_restart_while_otelcol_stopped(ctx, running_state, stamp_file, trust_hash):
    """Scenario: otelcol is stopped while a restart is pending, then started again."""
    # GIVEN otelcol is running
    # AND the container restarted, so the trust store has to be rebuilt
    event, state = _container_restarted(ctx, running_state, stamp_file)
    # AND a server cert is requested, but not issued yet
    server_cert = Relation("receive-server-cert")
    waiting = replace(state, relations=[*state.relations, server_cert])

    # WHEN the charm reconciles
    result = _run(ctx, event, waiting)

    # THEN the trust store is rebuilt
    assert UPDATE_CA_CERTS in result.commands
    # AND otelcol is stopped while waiting for the cert
    assert isinstance(result.state.unit_status, ops.WaitingStatus)
    assert not _otelcol_running(result.state)
    # AND the stamp records the restart as pending
    assert stamp_file.read_text() == _pending(trust_hash)

    # WHEN the server cert relation is removed, so otelcol can run without TLS
    no_tls = replace(
        result.state,
        relations=[r for r in result.state.relations if r.endpoint != "receive-server-cert"],
    )
    result = _run(ctx, ctx.on.update_status(), no_tls)

    # THEN otelcol is started, without rebuilding the trust store or an extra restart
    assert UPDATE_CA_CERTS not in result.commands
    assert _otelcol_running(result.state)
    assert result.restarted == []
    # AND the stamp records the trust store as loaded
    assert stamp_file.read_text() == trust_hash
