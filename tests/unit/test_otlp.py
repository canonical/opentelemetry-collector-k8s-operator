# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoints and rules transfer."""

import dataclasses
import json
from typing import Mapping
from unittest.mock import patch

import pytest
from charmlibs.interfaces.otlp import OtlpEndpoint, OtlpProvider
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
        remote_endpoints = send_otlp(mgr.charm, OtlpProvider(mgr.charm))

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


def _alerts_from_send_otlp(local_app_data: Mapping[str, str]) -> set:
    """Extract alert names from a `send-otlp` outgoing databag.

    The OTLP requirer publishes rules under the (LZMA-compressed) ``rules`` field, split into
    ``promql`` and ``logql`` top-level keys.
    """
    rules = local_app_data.get("rules")
    if not rules:
        return set()
    decompressed = _decompress(rules)
    alerts: set = set()
    for tier in ("promql", "logql"):
        for group in decompressed.get(tier, {}).get("groups", []):
            for rule in group.get("rules", []):
                if "alert" in rule:
                    alerts.add(rule["alert"])
    return alerts


def _alerts_from_alert_rules_field(local_app_data: Mapping[str, str]) -> set:
    """Extract alert names from a databag using the ``alert_rules`` JSON field.

    Used by both `send-remote-write` (promql) and `send-loki-logs` (logql).
    """
    raw = local_app_data.get("alert_rules", '{"groups": []}')
    alerts: set = set()
    for group in json.loads(raw).get("groups", []):
        for rule in group.get("rules", []):
            if "alert" in rule:
                alerts.add(rule["alert"])
    return alerts


@pytest.mark.parametrize("forward_rules", [True, False])
@pytest.mark.parametrize(
    "downstream_endpoint, downstream_remote_app, downstream_remote_app_data, expected_alerts, extract_alerts",
    [
        pytest.param(
            "send-otlp",
            "downstream-otelcol",
            {"endpoints": "[]"},
            {"Workload Missing", "HighLogVolume"},
            _alerts_from_send_otlp,
            id="otlp-to-otlp",
        ),
        pytest.param(
            "send-remote-write",
            "prometheus",
            None,
            {"Workload Missing"},
            _alerts_from_alert_rules_field,
            id="otlp-to-remote-write",
        ),
        pytest.param(
            "send-loki-logs",
            "loki",
            None,
            {"HighLogVolume"},
            _alerts_from_alert_rules_field,
            id="otlp-to-loki",
        ),
    ],
)
def test_received_otlp_rules_forwarded_downstream(
    ctx,
    otelcol_container,
    all_rules,
    forward_rules,
    downstream_endpoint,
    downstream_remote_app,
    downstream_remote_app_data,
    expected_alerts,
    extract_alerts,
):
    """Rules via `receive-otlp` must reach every downstream.

    Alert rules received over `receive-otlp` must reach every downstream iff
    `forward_alert_rules` is enabled. Each downstream uses a different databag
    layout, so the matrix exercises all forwarding paths:

        * `send-otlp`: LZMA-compressed dict under `rules`, split by `promql`/`logql`.
        * `send-remote-write`: JSON dict under `alert_rules` (promql only).
        * `send-loki-logs`: JSON dict under `alert_rules` (logql only).
    """
    # GIVEN a receive-otlp relation carrying compressed alert rules
    # * a single downstream forwarding relation
    receiver = Relation(
        "receive-otlp",
        remote_app_data={
            "rules": json.dumps(LZMABase64.compress(json.dumps(all_rules))),
            "metadata": json.dumps(OTELCOL_METADATA),
        },
    )
    downstream_kwargs = {"remote_app_name": downstream_remote_app}
    if downstream_remote_app_data is not None:
        downstream_kwargs["remote_app_data"] = downstream_remote_app_data
    downstream = Relation(downstream_endpoint, **downstream_kwargs)
    state = State(
        relations=[receiver, downstream],
        leader=True,
        containers=otelcol_container,
        model=MODEL,
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the received alert rules reach the downstream databag iff forwarding is enabled
    out_relation = state_out.get_relation(downstream.id)
    forwarded = extract_alerts(out_relation.local_app_data)
    if forward_rules:
        missing = expected_alerts - forwarded
        assert not missing, (
            f"expected {expected_alerts} in {downstream_endpoint} databag but missing {missing}; "
            f"forwarded={forwarded}"
        )
    else:
        leaked = expected_alerts & forwarded
        assert not leaked, (
            f"forwarding disabled but received-OTLP alerts leaked into {downstream_endpoint}: {leaked}"
        )


@pytest.mark.parametrize("forward_rules", [True, False])
@pytest.mark.parametrize(
    "source_endpoint, source_remote_app_name, source_remote_app_data, expected_alerts",
    [
        pytest.param(
            "receive-otlp",
            "upstream-otelcol",
            None,  # filled in at runtime from the `all_rules` fixture
            {"Workload Missing", "HighLogVolume"},
            id="receive-otlp-to-send-otlp",
        ),
        pytest.param(
            "metrics-endpoint",
            "zinc",
            {
                "alert_rules": json.dumps(
                    {
                        "groups": [
                            {
                                "name": "scrape_endpoint_group",
                                "rules": [
                                    {
                                        "alert": "ScrapeEndpointAlert",
                                        "expr": "up == 0",
                                        "for": "0m",
                                        "labels": {"severity": "critical"},
                                    }
                                ],
                            }
                        ]
                    }
                ),
                "scrape_metadata": json.dumps(
                    {
                        "model": MODEL_NAME,
                        "model_uuid": MODEL_UUID,
                        "application": "zinc",
                        "charm_name": "zinc-k8s",
                        "unit": "zinc/0",
                    }
                ),
                "scrape_jobs": json.dumps(
                    [{"job_name": "zinc", "static_configs": [{"targets": ["1.2.3.4:8080"]}]}]
                ),
            },
            {"ScrapeEndpointAlert"},
            # `send_otlp` currently only forwards rules from bundled SRC dirs and `OtlpProvider`
            # (i.e. `receive-otlp`). It does not pick up rules from `metrics-endpoint` or
            # `receive-loki-logs` upstreams, so they never reach downstream OTLP collectors.
            # This `xfail` documents the desired behavior; once `send_otlp` is taught to include
            # those sources, drop `marks=` to flip this back to a passing assertion.
            # `strict=False` because the `forward_rules=False` row trivially passes today
            # (nothing flows in or out), so it would XPASS and noise up the run.
            marks=pytest.mark.xfail(
                reason=(
                    "send_otlp does not forward rules received over metrics-endpoint or "
                    "receive-loki-logs; tracked separately."
                ),
                strict=False,
            ),
            id="metrics-endpoint-to-send-otlp",
        ),
    ],
)
def test_incoming_rules_forwarded_to_send_otlp(
    ctx,
    otelcol_container,
    all_rules,
    forward_rules,
    source_endpoint,
    source_remote_app_name,
    source_remote_app_data,
    expected_alerts,
):
    """Alert rules received over any incoming relation must reach `send-otlp` iff forwarding is enabled.

    Symmetric counterpart to `test_received_otlp_rules_forwarded_downstream`: that test fans out
    from `receive-otlp` to every downstream forwarding endpoint; this one fans in from every
    rule-bearing incoming endpoint to a single `send-otlp` downstream. Each source uses a
    different databag layout:

        * `receive-otlp`: LZMA-compressed dict under `rules`, split by `promql`/`logql`.
        * `metrics-endpoint`: JSON dict under `alert_rules` plus `scrape_metadata`/`scrape_jobs`.
    """
    # GIVEN one rule-bearing incoming relation AND a single `send-otlp` downstream relation
    if source_endpoint == "receive-otlp":
        source_remote_app_data = {
            "rules": json.dumps(LZMABase64.compress(json.dumps(all_rules))),
            "metadata": json.dumps(OTELCOL_METADATA),
        }
    source = Relation(
        source_endpoint,
        remote_app_name=source_remote_app_name,
        remote_app_data=source_remote_app_data,
    )
    downstream = Relation(
        "send-otlp", remote_app_name="downstream-otelcol", remote_app_data={"endpoints": "[]"}
    )
    state = State(
        relations=[source, downstream],
        leader=True,
        containers=otelcol_container,
        model=MODEL,
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the source's alert rules reach the `send-otlp` databag iff forwarding is enabled
    out_relation = state_out.get_relation(downstream.id)
    forwarded = _alerts_from_send_otlp(out_relation.local_app_data)
    if forward_rules:
        missing = expected_alerts - forwarded
        assert not missing, (
            f"expected {expected_alerts} from {source_endpoint} in send-otlp databag but missing "
            f"{missing}; forwarded={forwarded}"
        )
    else:
        leaked = expected_alerts & forwarded
        assert not leaked, (
            f"forwarding disabled but {source_endpoint} alerts leaked into send-otlp: {leaked}"
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
