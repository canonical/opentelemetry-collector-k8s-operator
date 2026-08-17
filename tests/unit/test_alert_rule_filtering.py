# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: block when a relation reports invalid alert rules.

The charm consumes alert rules over the `metrics-endpoint` and `receive-loki-logs`
relations. The `prometheus_scrape`/`loki_push_api` libs validate each rule set with
cos-tool and record any validation failures in the leader's relation app data (under
`event.errors`). An invalid rule set is excluded from the resulting alerts, so the
only way to detect it is to inspect that same relation data. The charm should set
`blocked` when any such error is present, and return to `active` once the errors are
cleared.
"""

import dataclasses
import json

from ops.testing import Model, Relation, State

MODEL_NAME = "test"
MODEL_UUID = "20ce8299-3634-4bef-8bd8-5ace6c8816b4"


def _alert_rules(group_name: str, valid: bool) -> str:
    # This expr is invalid intentionally. It is missing a value after the
    # '>' operator, which should cause validation to fail.
    invalid_expr = 'sum(rate({job="invalid"}[5m])) >'
    return json.dumps(
        {
            "groups": [
                {
                    "name": group_name,
                    "rules": [
                        {
                            "alert": f"{group_name}Valid",
                            "expr": 'sum(rate({job="valid"}[5m])) > 0',
                            "for": "1m",
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "valid-a"},
                        },
                        {
                            "alert": f"{group_name}Rule",
                            "expr": 'sum(rate({job="valid"}[5m])) > 0'
                            if valid
                            else invalid_expr,
                            "for": "1m",
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "b"},
                        },
                    ],
                }
            ]
        }
    )


def _scrape_metadata(app_name: str) -> str:
    return json.dumps(
        {
            "model": MODEL_NAME,
            "model_uuid": MODEL_UUID,
            "application": app_name,
            "charm_name": f"{app_name}-charm",
        }
    )


VALID_ALERT_RULE_RELATION = Relation(
    "metrics-endpoint",
    remote_app_name="alert-rule-valid",
    remote_app_data={
        "alert_rules": _alert_rules("valid-group", valid=True),
        "scrape_metadata": _scrape_metadata("alert-rule-valid"),
    },
)

INVALID_ALERT_RULE_RELATION = Relation(
    "metrics-endpoint",
    remote_app_name="alert-rule-invalid",
    remote_app_data={
        "alert_rules": _alert_rules("invalid-group", valid=False),
        "scrape_metadata": _scrape_metadata("alert-rule-invalid"),
    },
)

MODEL = Model(MODEL_NAME, uuid=MODEL_UUID)

# `metrics-endpoint` must be paired with a metrics sink (see `_get_missing_mandatory_relations`),
# otherwise the charm blocks on missing relations rather than on alert rule validity.
SEND_REMOTE_WRITE = Relation(
    "send-remote-write",
    interface="prometheus_remote_write",
    remote_units_data={
        0: {"remote_write": '{"url": "http://fqdn-0:9090/api/v1/write"}'},
    },
)

# Alert rules are validated only when alert rule forwarding is enabled
# (see `integrations.metrics_rules`).
FORWARD_ALERT_RULES: dict[str, str | int | float | bool] = {"forward_alert_rules": True}


def _loki_alert_rules(group_name: str, valid: bool) -> str:
    invalid_expr = 'sum(rate({job="invalid"}[5m])) > INVALID'
    return json.dumps(
        {
            "groups": [
                {
                    "name": group_name,
                    "rules": [
                        {
                            "alert": f"{group_name}Valid",
                            "expr": 'sum(rate({job="valid"}[5m])) > 0',
                            "for": "1m",
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "valid-a"},
                        },
                        {
                            "alert": f"{group_name}Rule",
                            "expr": 'sum(rate({job="valid"}[5m])) > 0'
                            if valid
                            else invalid_expr,
                            "for": "1m",
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "b"},
                        },
                    ],
                }
            ]
        }
    )


VALID_LOKI_ALERT_RULE_RELATION = Relation(
    "receive-loki-logs",
    remote_app_name="loki-alert-rule-valid",
    remote_app_data={"alert_rules": _loki_alert_rules("valid-group", valid=True)},
)

INVALID_LOKI_ALERT_RULE_RELATION = Relation(
    "receive-loki-logs",
    remote_app_name="loki-alert-rule-invalid",
    remote_app_data={"alert_rules": _loki_alert_rules("invalid-group", valid=False)},
)

# `receive-loki-logs` must be paired with a logs sink (see `_get_missing_mandatory_relations`),
# otherwise the charm blocks on missing relations rather than on alert rule validity.
SEND_LOKI_LOGS = Relation(
    "send-loki-logs",
    interface="loki_push_api",
    remote_app_name="loki",
)


def test_valid_alert_rule_relation_remains_active(ctx, otelcol_container):
    # GIVEN a relation with valid alert rules
    state = State(
        leader=True,
        relations=[VALID_ALERT_RULE_RELATION, SEND_REMOTE_WRITE],
        containers=otelcol_container,
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the charm stays active
    assert state_out.unit_status.name == "active"


def test_invalid_alert_rule_relation_blocks(ctx, otelcol_container):
    # GIVEN a relation with invalid alert rules
    state = State(
        leader=True,
        relations=[INVALID_ALERT_RULE_RELATION, SEND_REMOTE_WRITE],
        containers=otelcol_container,
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the charm is blocked with a helpful message
    assert state_out.unit_status.name == "blocked"
    assert state_out.unit_status.message == "Invalid Prometheus alerts. See debug-log"


def test_invalid_alert_rule_relation_broken_recovers_to_active(ctx, otelcol_container):
    # GIVEN an alert rule relation with invalid rules has already blocked the charm
    state = State(
        leader=True,
        relations=[INVALID_ALERT_RULE_RELATION, SEND_REMOTE_WRITE],
        containers=otelcol_container,
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )
    blocked_state = ctx.run(ctx.on.update_status(), state=state)
    assert blocked_state.unit_status.name == "blocked"

    # WHEN the invalid relation is removed
    removed_relation = blocked_state.get_relation(INVALID_ALERT_RULE_RELATION.id)
    state_out = ctx.run(ctx.on.relation_broken(removed_relation), blocked_state)

    # THEN the charm is active again
    assert state_out.unit_status.name == "active"

def test_invalid_alert_rule_relation_becoming_valid_recovers_to_active(
    ctx, otelcol_container
):
    # GIVEN an alert rule relation with invalid rules has already blocked the charm
    state = State(
        leader=True,
        relations=[INVALID_ALERT_RULE_RELATION, SEND_REMOTE_WRITE],
        containers=otelcol_container,
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )
    blocked_state = ctx.run(ctx.on.update_status(), state=state)
    assert blocked_state.unit_status.name == "blocked"
    relation_after_invalid = blocked_state.get_relation(INVALID_ALERT_RULE_RELATION.id)

    # WHEN the same relation updates its rules to become valid
    now_valid_relation = dataclasses.replace(
        relation_after_invalid,
        remote_app_data={
            **relation_after_invalid.remote_app_data,
            "alert_rules": VALID_ALERT_RULE_RELATION.remote_app_data["alert_rules"],
        },
    )
    recovered_state = ctx.run(
        ctx.on.relation_changed(now_valid_relation),
        dataclasses.replace(
            blocked_state, relations=[now_valid_relation, SEND_REMOTE_WRITE]
        ),
    )

    # THEN the charm is active again
    assert recovered_state.unit_status.name == "active"


def test_valid_loki_alert_rule_relation_remains_active(ctx, otelcol_container):
    # GIVEN a relation with valid loki alert rules
    state = State(
        leader=True,
        relations=[VALID_LOKI_ALERT_RULE_RELATION, SEND_LOKI_LOGS],
        containers=otelcol_container,
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the charm stays active
    assert state_out.unit_status.name == "active"


def test_invalid_loki_alert_rule_relation_blocks(ctx, otelcol_container):
    # GIVEN a relation with invalid loki alert rules
    state = State(
        leader=True,
        relations=[INVALID_LOKI_ALERT_RULE_RELATION, SEND_LOKI_LOGS],
        containers=otelcol_container,
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the charm is blocked with a helpful message
    assert state_out.unit_status.name == "blocked"
    assert state_out.unit_status.message == "Invalid Loki alerts. See debug-log"


def test_invalid_loki_alert_rule_relation_broken_recovers_to_active(
    ctx, otelcol_container
):
    # GIVEN a loki alert rule relation with invalid rules has already blocked the charm
    state = State(
        leader=True,
        relations=[INVALID_LOKI_ALERT_RULE_RELATION, SEND_LOKI_LOGS],
        containers=otelcol_container,
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )
    blocked_state = ctx.run(ctx.on.update_status(), state=state)
    assert blocked_state.unit_status.name == "blocked"

    # WHEN the invalid relation is removed
    removed_relation = blocked_state.get_relation(INVALID_LOKI_ALERT_RULE_RELATION.id)
    state_out = ctx.run(ctx.on.relation_broken(removed_relation), blocked_state)

    # THEN the charm is active again
    assert state_out.unit_status.name == "active"


def test_invalid_loki_alert_rule_relation_becoming_valid_recovers_to_active(
    ctx, otelcol_container
):
    # GIVEN a loki alert rule relation with invalid rules has already blocked the charm
    state = State(
        leader=True,
        relations=[INVALID_LOKI_ALERT_RULE_RELATION, SEND_LOKI_LOGS],
        containers=otelcol_container,
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )
    blocked_state = ctx.run(ctx.on.update_status(), state=state)
    assert blocked_state.unit_status.name == "blocked"
    relation_after_invalid = blocked_state.get_relation(INVALID_LOKI_ALERT_RULE_RELATION.id)

    # WHEN the same relation updates its rules to become valid
    now_valid_relation = dataclasses.replace(
        relation_after_invalid,
        remote_app_data={
            **relation_after_invalid.remote_app_data,
            "alert_rules": VALID_LOKI_ALERT_RULE_RELATION.remote_app_data["alert_rules"],
        },
    )
    recovered_state = ctx.run(
        ctx.on.relation_changed(now_valid_relation),
        dataclasses.replace(
            blocked_state, relations=[now_valid_relation, SEND_LOKI_LOGS]
        ),
    )

    # THEN the charm is active again
    assert recovered_state.unit_status.name == "active"
