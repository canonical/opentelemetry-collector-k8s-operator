# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: block when a metrics-endpoint relation reports invalid scrape jobs.

The charm consumes scrape jobs over the `metrics-endpoint` relation. The
`prometheus_scrape` lib validates each scrape job with cos-tool and records any
validation failures in the leader's relation app data (under `event.scrape_job_errors`).
An invalid scrape job is excluded from the resulting jobs list, so the only way to
detect it is to inspect that same relation data. The charm should set `blocked` when
any such error is present, and return to `active` once the errors are cleared.
"""

import dataclasses
import json

from ops.testing import Model, Relation, State

MODEL_NAME = "test"
MODEL_UUID = "20ce8299-3634-4bef-8bd8-5ace6c8816b4"


def _scrape_jobs(job_name: str, valid: bool) -> str:
    job = {
        "job_name": job_name,
        "metrics_path": "/metrics",
        "static_configs": [{"targets": ["192.0.2.1:9090"]}],
    }
    if not valid:
        # `sample_limit` must be a number; a dict makes the scrape job invalid.
        job["sample_limit"] = {"not_a_key": "not_a_value"}
    return json.dumps([job])


def _scrape_metadata(app_name: str) -> str:
    return json.dumps(
        {
            "model": MODEL_NAME,
            "model_uuid": MODEL_UUID,
            "application": app_name,
            "charm_name": f"{app_name}-charm",
        }
    )


VALID_SCRAPE_JOB_RELATION = Relation(
    "metrics-endpoint",
    remote_app_name="scrape-job-valid",
    remote_app_data={
        "scrape_jobs": _scrape_jobs("valid-job", valid=True),
        "scrape_metadata": _scrape_metadata("scrape-job-valid"),
    },
)

INVALID_SCRAPE_JOB_RELATION = Relation(
    "metrics-endpoint",
    remote_app_name="scrape-job-invalid",
    remote_app_data={
        "scrape_jobs": _scrape_jobs("invalid-job", valid=False),
        "scrape_metadata": _scrape_metadata("scrape-job-invalid"),
    },
)

MODEL = Model(MODEL_NAME, uuid=MODEL_UUID)

# `metrics-endpoint` must be paired with a metrics sink (see `_get_missing_mandatory_relations`),
# otherwise the charm blocks on missing relations rather than on scrape job validity.
SEND_REMOTE_WRITE = Relation(
    "send-remote-write",
    interface="prometheus_remote_write",
    remote_units_data={
        0: {"remote_write": '{"url": "http://fqdn-0:9090/api/v1/write"}'},
    },
)


def test_valid_scrape_job_relation_remains_active(ctx, otelcol_container):
    # GIVEN a scrape relation with a valid scrape job
    state = State(
        leader=True,
        relations=[VALID_SCRAPE_JOB_RELATION, SEND_REMOTE_WRITE],
        containers=otelcol_container,
        model=MODEL,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the charm stays active
    assert state_out.unit_status.name == "active"


def test_invalid_scrape_job_relation_blocks(ctx, otelcol_container):
    # GIVEN a scrape relation with an invalid scrape job
    state = State(
        leader=True,
        relations=[INVALID_SCRAPE_JOB_RELATION, SEND_REMOTE_WRITE],
        containers=otelcol_container,
        model=MODEL,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the charm is blocked with a helpful message
    assert state_out.unit_status.name == "blocked"
    assert state_out.unit_status.message == "Invalid scrape jobs. See debug-log"


def test_invalid_scrape_job_relation_broken_recovers_to_active(ctx, otelcol_container):
    # GIVEN an invalid scrape relation has already blocked the charm
    state = State(
        leader=True,
        relations=[INVALID_SCRAPE_JOB_RELATION, SEND_REMOTE_WRITE],
        containers=otelcol_container,
        model=MODEL,
    )
    blocked_state = ctx.run(ctx.on.update_status(), state=state)
    assert blocked_state.unit_status.name == "blocked"

    # WHEN the invalid scrape relation is removed
    removed_relation = blocked_state.get_relation(INVALID_SCRAPE_JOB_RELATION.id)
    state_out = ctx.run(ctx.on.relation_broken(removed_relation), blocked_state)

    # THEN the charm is active again
    assert state_out.unit_status.name == "active"


def test_invalid_scrape_job_relation_becoming_valid_recovers_to_active(
    ctx, otelcol_container
):
    # GIVEN an invalid scrape relation has already blocked the charm
    state = State(
        leader=True,
        relations=[INVALID_SCRAPE_JOB_RELATION, SEND_REMOTE_WRITE],
        containers=otelcol_container,
        model=MODEL,
    )
    blocked_state = ctx.run(ctx.on.update_status(), state=state)
    assert blocked_state.unit_status.name == "blocked"
    relation_after_invalid = blocked_state.get_relation(INVALID_SCRAPE_JOB_RELATION.id)

    # WHEN the same scrape relation updates its jobs to become valid
    now_valid_relation = dataclasses.replace(
        relation_after_invalid,
        remote_app_data={
            **relation_after_invalid.remote_app_data,
            "scrape_jobs": VALID_SCRAPE_JOB_RELATION.remote_app_data["scrape_jobs"],
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
