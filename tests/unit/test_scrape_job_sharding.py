# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: each scrape target is pulled by exactly one otelcol unit.

Every otelcol unit builds the same Prometheus receiver config from the same relation data.
Without sharding, scaling the charm duplicates every scraped series: all units scrape all
targets and remote-write identical series on independent schedules, and the backend rejects
the later, out-of-order copy. The charm assigns every scrape job to exactly one unit, so a
target is scraped once regardless of scale.
"""

import json

from helpers import get_otelcol_file
from ops.testing import Context, PeerRelation, Relation, State

from src.charm import OpenTelemetryCollectorK8sCharm
from src.constants import CONFIG_PATH
from src.integrations import _scrape_job_owner

MODEL_NAME = "test"
MODEL_UUID = "20ce8299-3634-4bef-8bd8-5ace6c8816b4"
APP_NAME = "opentelemetry-collector-k8s"

# `metrics-endpoint` must be paired with a metrics sink (see `_get_missing_mandatory_relations`),
# otherwise the charm blocks before it is useful to assert on the scrape config.
SEND_REMOTE_WRITE = Relation(
    "send-remote-write",
    interface="prometheus_remote_write",
    remote_units_data={
        0: {"remote_write": '{"url": "http://fqdn-0:9090/api/v1/write"}'},
    },
)

# The scraped app has four units and advertises a wildcard target, so the
# `prometheus_scrape` library expands it into one job per unit: four jobs to shard.
SCRAPED_UNITS = 4


def _metrics_endpoint_relation() -> Relation:
    return Relation(
        "metrics-endpoint",
        interface="prometheus_scrape",
        remote_app_data={
            "scrape_jobs": json.dumps(
                [
                    {
                        "job_name": "wildcard",
                        "metrics_path": "/metrics",
                        "static_configs": [{"targets": ["*:8000"]}],
                    }
                ]
            ),
            "scrape_metadata": json.dumps(
                {
                    "model": MODEL_NAME,
                    "model_uuid": MODEL_UUID,
                    "application": "scraped",
                    "charm_name": "scraped-charm",
                }
            ),
        },
        remote_units_data={
            i: {
                "prometheus_scrape_unit_name": f"scraped/{i}",
                "prometheus_scrape_unit_address": f"10.0.0.{i}",
                "prometheus_scrape_unit_fqdn": f"scraped-{i}.svc.cluster.local",
            }
            for i in range(SCRAPED_UNITS)
        },
    )


def _state(otelcol_container, peers_data: dict | None) -> State:
    """A charm with a scrape relation, optionally scaled via the peer relation."""
    peers = [PeerRelation("peers", peers_data=peers_data)] if peers_data is not None else []
    return State(
        relations=[_metrics_endpoint_relation(), SEND_REMOTE_WRITE, *peers],
        containers=otelcol_container,
        leader=True,
    )


def _scraped_job_names(state_out: State, ctx: Context) -> set[str]:
    """The names of the scrape jobs in the config that `ctx`'s unit wrote."""
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    receiver = f"prometheus/metrics-endpoint/{APP_NAME}/{ctx.unit_id}"
    return {job["job_name"] for job in cfg["receivers"][receiver]["config"]["scrape_configs"]}


def test_single_unit_scrapes_every_target(ctx, otelcol_container):
    """Scenario: an unscaled charm has no peer to share the jobs with."""
    # GIVEN a charm with no peer units
    state = _state(otelcol_container, peers_data=None)
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state)
    # THEN it keeps every scrape job rather than dropping any
    assert len(_scraped_job_names(state_out, ctx)) == SCRAPED_UNITS


def test_scaled_units_partition_the_scrape_jobs(ctx, otelcol_container):
    """Scenario: a two-unit charm splits the jobs without loss or duplication."""
    # GIVEN the jobs of an unscaled charm
    full = _scraped_job_names(
        ctx.run(ctx.on.update_status(), _state(otelcol_container, peers_data=None)), ctx
    )
    # AND the same charm scaled to two units
    second_unit = Context(OpenTelemetryCollectorK8sCharm, charm_root=ctx.charm_root, unit_id=1)
    # WHEN each unit executes the reconciler
    first_jobs = _scraped_job_names(
        ctx.run(ctx.on.update_status(), _state(otelcol_container, peers_data={1: {}})), ctx
    )
    second_jobs = _scraped_job_names(
        second_unit.run(
            second_unit.on.update_status(), _state(otelcol_container, peers_data={0: {}})
        ),
        second_unit,
    )
    # THEN the jobs are split between the units...
    assert first_jobs and second_jobs
    assert first_jobs.isdisjoint(second_jobs)
    # AND no job is lost
    assert first_jobs | second_jobs == full


def test_adding_a_unit_only_moves_the_jobs_it_takes_over():
    """Scenario: scaling does not disturb the assignment of the jobs it does not take.

    Rendezvous hashing reassigns only the jobs the new unit takes over, unlike modulo
    hashing which would reshuffle almost every job on each scale change.
    """
    # GIVEN the jobs of a two-unit application
    jobs = [{"job_name": f"job-{i}"} for i in range(50)]
    two_units = [f"{APP_NAME}/{i}" for i in range(2)]
    new_unit = f"{APP_NAME}/2"
    before = {job["job_name"]: _scrape_job_owner(job, two_units) for job in jobs}
    # WHEN a third unit is added
    after = {job["job_name"]: _scrape_job_owner(job, [*two_units, new_unit]) for job in jobs}
    # THEN every job either stays put or moves to the new unit, never between existing ones
    assert all(after[name] == before[name] or after[name] == new_unit for name in before)
    # AND the new unit does take some jobs over, so it is not left idle
    assert new_unit in after.values()
