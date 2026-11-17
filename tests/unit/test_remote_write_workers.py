# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: parallel workers for the send-remote-write exporter.

In the collector this charm ships (0.130.x) the prometheusremotewrite exporter sends one
request at a time unless the `exporter.prometheusremotewritexporter.EnableMultipleWorkers`
feature gate is enabled. The `remote_write_multiple_workers` option enables that gate and
sets `remote_write_queue.num_consumers` to 5, which lifts the throughput cap but permits
out-of-order writes.
"""

import json

from helpers import get_otelcol_file
from ops.testing import Relation, State

from src.constants import CONFIG_PATH, SERVICE_NAME

MULTIPLE_WORKERS_GATE = "exporter.prometheusremotewritexporter.EnableMultipleWorkers"
PROFILES_GATE = "service.profilesSupport"


def _remote_write_relation() -> Relation:
    return Relation(
        endpoint="send-remote-write",
        interface="prometheus_remote_write",
        remote_units_data={
            0: {"remote_write": '{"url": "http://fqdn-0:9090/api/v1/write"}'},
        },
    )


def _send_profiles_relation() -> Relation:
    return Relation(
        endpoint="send-profiles",
        remote_app_data={
            "otlp_grpc_endpoint_url": json.dumps("my.fqdn.cluster.local:12345"),
            "insecure": json.dumps(False),
        },
    )


def _remote_write_queue(state_out, ctx) -> dict:
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    return cfg["exporters"]["prometheusremotewrite/send-remote-write/0"]["remote_write_queue"]


def test_default_uses_a_single_worker_without_feature_gate(ctx, otelcol_container):
    """Scenario: the option is left at its default of false."""
    # GIVEN a send-remote-write relation and the default config
    state_in = State(relations=[_remote_write_relation()], containers=otelcol_container)

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN otelcol runs without the EnableMultipleWorkers gate
    command = state_out.get_container("otelcol").plan.services[SERVICE_NAME].command
    assert MULTIPLE_WORKERS_GATE not in command
    assert "--feature-gates" not in command

    # AND the exporter queue uses a single in-order consumer
    assert _remote_write_queue(state_out, ctx)["num_consumers"] == 1


def test_multiple_workers_enables_feature_gate(ctx, otelcol_container):
    """Scenario: the option is enabled and a send-remote-write relation exists."""
    # GIVEN a send-remote-write relation and the option enabled
    state_in = State(
        relations=[_remote_write_relation()],
        containers=otelcol_container,
        config={"remote_write_multiple_workers": True},
    )

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN otelcol is started and validated with the EnableMultipleWorkers gate
    plan_out = state_out.get_container("otelcol").plan
    assert (
        plan_out.services[SERVICE_NAME].command
        == f"/usr/bin/otelcol --config={CONFIG_PATH} --feature-gates={MULTIPLE_WORKERS_GATE}"
    )
    assert (
        plan_out.checks["valid-config"].exec["command"]
        == f"otelcol validate --config={CONFIG_PATH} --feature-gates={MULTIPLE_WORKERS_GATE}"
    )

    # AND the exporter queue has multiple consumers
    assert _remote_write_queue(state_out, ctx)["num_consumers"] == 5


def test_multiple_workers_without_remote_write_relation_does_not_gate(ctx, otelcol_container):
    """Scenario: the option is enabled but no send-remote-write relation exists.

    There is no prometheusremotewrite exporter to act on, so passing the gate would only
    advertise a capability the collector does not use.
    """
    # GIVEN the option enabled and no remote-write relation
    state_in = State(
        containers=otelcol_container,
        config={"remote_write_multiple_workers": True},
    )

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN no feature gate is passed to otelcol
    command = state_out.get_container("otelcol").plan.services[SERVICE_NAME].command
    assert "--feature-gates" not in command


def test_multiple_workers_with_profiling_combines_gates(ctx, otelcol_container):
    """Scenario: multiple workers and profiling are both enabled."""
    # GIVEN a send-remote-write relation, a send-profiles relation, and the option enabled
    state_in = State(
        relations=[_remote_write_relation(), _send_profiles_relation()],
        containers=otelcol_container,
        config={"remote_write_multiple_workers": True},
    )

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN both feature gates are passed to otelcol
    plan_out = state_out.get_container("otelcol").plan
    expected_gates = f"{MULTIPLE_WORKERS_GATE},{PROFILES_GATE}"
    assert (
        plan_out.services[SERVICE_NAME].command
        == f"/usr/bin/otelcol --config={CONFIG_PATH} --feature-gates={expected_gates}"
    )
    assert (
        plan_out.checks["valid-config"].exec["command"]
        == f"otelcol validate --config={CONFIG_PATH} --feature-gates={expected_gates}"
    )

    # AND the exporter queue has multiple consumers
    assert _remote_write_queue(state_out, ctx)["num_consumers"] == 5
