from ops.testing import Container, Relation, State
from scenario import ActiveStatus, BlockedStatus


def test_missing_relation_pair_status(ctx, execs):
    source_relation = Relation("metrics-endpoint")
    # GIVEN the charm has no relations
    state = State(
        leader=True,
        relations=[source_relation],  # source_relation must exist in state for relation_joined
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    # WHEN a source is related to opentelemetry-collector
    state_out = ctx.run(ctx.on.relation_joined(source_relation), state)
    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    # AND the status message warns of the missing sink relations
    assert "] for metrics-endpoint" in state_out.unit_status.message


def test_valid_relation_pair_status(ctx, execs):
    source_relation = Relation("metrics-endpoint")
    sink_relation = Relation("send-remote-write")
    # GIVEN the charm has a source and no sink relation
    state = State(
        leader=True,
        relations=[
            source_relation,
            sink_relation,
        ],  # sink_relation must exist in state for relation_joined
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )
    # WHEN a sink is related to opentelemetry-collector
    state_out = ctx.run(ctx.on.relation_joined(sink_relation), state)
    # THEN the charm enters ActiveStatus
    assert isinstance(state_out.unit_status, ActiveStatus)
