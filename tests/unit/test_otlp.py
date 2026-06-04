# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoints and rules transfer."""

import dataclasses
import json
from contextlib import ExitStack
from unittest.mock import patch

import pytest
from charmlibs.interfaces.otlp import OtlpEndpoint
from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State

from src.integrations import cyclic_otlp_relations_exist, send_otlp

MODEL_NAME = "foo-model"
MODEL_UUID = "f4d59020-c8e7-4053-8044-a2c1e5591c7f"
MODEL = Model(MODEL_NAME, uuid=MODEL_UUID)
OTELCOL_METADATA = {
    "model": MODEL_NAME,
    "model_uuid": MODEL_UUID,
    "application": "opentelemetry-collector-k8s",
    "unit": "opentelemetry-collector-k8s/0",
    "charm_name": "opentelemetry-collector-k8s",
}
SEND_OTLP = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
RECEIVE_OTLP = Relation("receive-otlp", remote_app_data={"rules": "{}", "metadata": "{}"})


def _replace(*args, **kwargs):
    return dataclasses.replace(*args, **kwargs)


def _decompress(rules: str) -> dict:
    return json.loads(LZMABase64.decompress(rules))


def test_send_otlp(ctx, otelcol_container):
    # GIVEN otelcol supports (defined by OtlpRequirer) a subset of OTLP protocols and telemetries
    # * a remote app provides multiple OtlpEndpoints
    remote_app_data_1 = {
        "endpoints": json.dumps(
            [
                {
                    "protocol": "http",
                    "endpoint": "http://provider-123.endpoint:4318",
                    "telemetries": ["logs", "metrics"],
                }
            ]
        )
    }
    remote_app_data_2 = {
        "endpoints": json.dumps(
            [
                {
                    "protocol": "grpc",
                    "endpoint": "http://provider-456.endpoint:4317",
                    "telemetries": ["traces"],
                },
                {
                    "protocol": "http",
                    "endpoint": "http://provider-456.endpoint:4318",
                    "telemetries": ["metrics"],
                },
            ]
        )
    }

    expected_endpoints = {
        456: OtlpEndpoint(
            protocol="grpc",
            endpoint="http://provider-456.endpoint:4317",
            telemetries=["traces"],
        ),
        123: OtlpEndpoint(
            protocol="http",
            endpoint="http://provider-123.endpoint:4318",
            telemetries=["logs", "metrics"],
        ),
    }

    # WHEN they are related over the "send-otlp" endpoint
    provider_1 = Relation(
        "send-otlp",
        id=123,
        remote_app_data=remote_app_data_1,
    )
    provider_2 = Relation(
        "send-otlp",
        id=456,
        remote_app_data=remote_app_data_2,
    )
    state = State(
        relations=[provider_1, provider_2],
        leader=True,
        containers=otelcol_container,
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        remote_endpoints = send_otlp(mgr.charm)

    # THEN the returned endpoints are filtered accordingly
    assert {k: v.model_dump() for k, v in remote_endpoints.items()} == {
        k: v.model_dump() for k, v in expected_endpoints.items()
    }


@patch("socket.getfqdn", new=lambda *args: "fqdn")
def test_receive_otlp(ctx, otelcol_container):
    expected_endpoints = {
        "endpoints": [
            {
                "protocol": "http",
                "endpoint": "http://fqdn:4318",
                "telemetries": ["metrics", "logs", "traces"],
                "insecure": True,
            },
            {
                "protocol": "grpc",
                "endpoint": "fqdn:4317",
                "telemetries": ["metrics", "logs", "traces"],
                "insecure": True,
            }
        ],
    }

    # GIVEN a receive-otlp relation and no TLS relations
    state = State(
        leader=True,
        containers=otelcol_container,
        relations=[RECEIVE_OTLP],
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)
    local_app_data = list(state_out.relations)[0].local_app_data

    # THEN otelcol offers its supported OTLP endpoints in the databag as "insecure"
    assert (actual_endpoints := json.loads(local_app_data.get("endpoints", "[]")))
    assert actual_endpoints == expected_endpoints["endpoints"]


@pytest.mark.parametrize(
    "relations, is_cyclic",
    (
        (
            [
                _replace(SEND_OTLP, remote_app_name="a"),
                _replace(RECEIVE_OTLP, remote_app_name="b"),
            ],
            False,
        ),
        (
            [
                _replace(SEND_OTLP, remote_app_name="b"),
                _replace(RECEIVE_OTLP, remote_app_name="a"),
            ],
            False,
        ),
        (
            [
                _replace(SEND_OTLP, remote_app_name="a"),
                _replace(RECEIVE_OTLP, remote_app_name="a"),
            ],
            True,
        ),
        (
            [
                _replace(SEND_OTLP, remote_app_name="a", id=123),
                _replace(SEND_OTLP, remote_app_name="b", id=456),
                _replace(RECEIVE_OTLP, remote_app_name="b"),
            ],
            True,
        ),
    ),
)
def test_cyclic_relations(ctx, otelcol_container, relations, is_cyclic):
    # GIVEN multiple OTLP send and receive relations
    state = State(
        relations=relations,
        leader=True,
        containers=otelcol_container,
    )

    # WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        mgr.run()
        result = cyclic_otlp_relations_exist(mgr.charm)

    # THEN the charm correctly identifies cyclic relations (one-level deep)
    assert result == is_cyclic


@pytest.mark.parametrize("forward_rules", [True, False])
def test_received_otlp_rules_forwarded_to_remote_write(
    ctx, otelcol_container, all_rules, forward_rules
):
    """Regression test for https://github.com/canonical/opentelemetry-collector-operator/issues/297.

    Alert rules received over `receive-otlp` must be staged to disk by `stage_received_otlp_rules`
    so that `send_remote_write` forwards them to Prometheus. The OTLP interface only exposes
    received rules via relation data and does not persist them, so without staging them the rules
    would never reach Prometheus.
    """
    # GIVEN a receive-otlp relation carrying (compressed) alert rules AND a send-remote-write relation
    databag = {
        "rules": json.dumps(LZMABase64.compress(json.dumps(all_rules))),
        "metadata": json.dumps(OTELCOL_METADATA),
    }
    receiver = Relation("receive-otlp", remote_app_data=databag)
    remote_write = Relation("send-remote-write", remote_app_name="prometheus")
    state = State(
        relations=[receiver, remote_write],
        leader=True,
        containers=otelcol_container,
        model=MODEL,
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the received alert rule is forwarded to Prometheus iff forwarding is enabled
    rw_out = state_out.get_relation(remote_write.id)
    alert_rules = json.loads(rw_out.local_app_data.get("alert_rules", '{"groups": []}'))
    forwarded_alerts = {
        rule.get("alert")
        for group in alert_rules.get("groups", [])
        for rule in group.get("rules", [])
        if "alert" in rule
    }
    # "Workload Missing" is the promql alert defined in the `all_rules` fixture (received over otlp)
    if forward_rules:
        assert "Workload Missing" in forwarded_alerts
    else:
        assert "Workload Missing" not in forwarded_alerts


def test_reconcile_stages_otlp_rules_in_correct_order(ctx, otelcol_container, all_rules):
    """Guard the temporal ordering contract that makes OTLP rule forwarding work.

    Staging the received OTLP rules to disk (`stage_received_otlp_rules`) only forwards them to
    Prometheus/Loki if it runs:
      * AFTER `cleanup` (which wipes the rule directories), and
      * BEFORE the integrations that read those directories: `receive_loki_logs`/`scrape_metrics`
        (which copy the bundled rules in) and `send_loki_logs`/`send_remote_write` (which forward).

    This ordering lives in `charm._reconcile` and is otherwise only enforced by a comment, so a
    future reorder would silently regress https://github.com/canonical/opentelemetry-collector-operator/issues/297.
    This test spies on the reconcile call order to fail fast if that contract is broken.
    """
    # `charm.py` does `import integrations`, so spy on that same module object
    import integrations

    call_order: list[str] = []
    spied = [
        "cleanup",
        "stage_received_otlp_rules",
        "receive_loki_logs",
        "send_loki_logs",
        "scrape_metrics",
        "send_remote_write",
    ]
    real = {name: getattr(integrations, name) for name in spied}

    def make_spy(name):
        def spy(*args, **kwargs):
            call_order.append(name)
            return real[name](*args, **kwargs)

        return spy

    # GIVEN a receive-otlp relation carrying alert rules, with forwarding enabled
    databag = {
        "rules": json.dumps(LZMABase64.compress(json.dumps(all_rules))),
        "metadata": json.dumps(OTELCOL_METADATA),
    }
    state = State(
        relations=[Relation("receive-otlp", remote_app_data=databag)],
        leader=True,
        containers=otelcol_container,
        model=MODEL,
        config={"forward_alert_rules": True},
    )

    # WHEN any event executes the reconciler
    with ExitStack() as stack:
        for name in spied:
            stack.enter_context(patch.object(integrations, name, make_spy(name)))
        ctx.run(ctx.on.update_status(), state=state)

    # THEN staging runs after the cleanup and before every integration that reads the rule dirs
    assert call_order.index("cleanup") < call_order.index("stage_received_otlp_rules")
    for reader in ("receive_loki_logs", "send_loki_logs", "scrape_metrics", "send_remote_write"):
        assert call_order.index("stage_received_otlp_rules") < call_order.index(reader), (
            f"stage_received_otlp_rules must run before {reader}"
        )


def test_forwarded_rules_have_topology(ctx, otelcol_container):
    """Test that otelcol adds its own topology metadata in the databag.

    This test ensures that rules are always labeled even if labels are not
    present in the upstream rules already. `cos-lib` tests the rest of the
    labeling rules feature.
    """
    # GIVEN an upstream receive-otlp databag with no metadata
    # * a send-otlp relation
    receiver = Relation("receive-otlp", remote_app_data={"rules": "{}", "metadata": "{}"})
    sender_1 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    sender_2 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[receiver, sender_1, sender_2],
        leader=True,
        containers=otelcol_container,
        model=MODEL,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)
    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            # THEN otelcol adds its own topology metadata to the databag
            assert json.loads(relation.local_app_data.get("metadata")) == OTELCOL_METADATA
