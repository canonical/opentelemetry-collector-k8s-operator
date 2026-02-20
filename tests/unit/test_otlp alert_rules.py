# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Rules aggregation and forwarding."""

import json

import pytest
from cosl.rules import LZMABase64
from helpers import get_group_by_name
from ops.testing import Model, Relation, State

from src.otlp import OtlpConsumerAppData

LOKI_RULES = {
    "groups": [
        {
            "name": "otelcol_f4d59020_loki_loki_alerts_alerts",
            "rules": [
                {
                    "alert": "HighLogVolume",
                    "expr": 'count_over_time({%%juju_topology%%job=~".+"}[30s]) > 100',
                    "labels": {
                        "severity": "high",
                        "juju_model": "otelcol",
                        "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                        "juju_application": "loki",
                        "juju_charm": "loki-coordinator-k8s",
                    },
                    "annotations": {
                        "summary": "Log rate is too high!",
                    },
                },
            ],
        }
    ]
}

ZOO_RULES = {
    "groups": [
        {
            "name": "otelcol_f4d59020_zoo_zookeeper_alerting_alerts",
            "rules": [
                {
                    "alert": "ZooKeeper Missing",
                    "expr": 'up{juju_charm!=".*"} == 0',
                    "for": "0m",
                    "labels": {
                        "severity": "critical",
                        "juju_model": "otelcol",
                        "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                        "juju_application": "zoo",
                        "juju_charm": "zookeeper",
                    },
                    "annotations": {
                        "summary": "Prometheus target missing (instance {{ $labels.instance }})",
                        "description": "ZooKeeper target has disappeared. An exporter might be crashed.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}",
                    },
                },
            ],
        }
    ]
}


@pytest.fixture
def generic_promql_alert_rule_labeled():
    return {
        "name": "otelcol_f4d59020_opentelemetry_collector_k8s_AggregatorHostHealth_alerts",
        "rules": [
            {
                "alert": "HostMetricsMissing",
                "annotations": {
                    "description": "`Up` missing for unit '{{ $labels.juju_unit }}' of application {{ $labels.juju_application }} in model {{ $labels.juju_model }}. Please ensure the unit or the collector scraping it is up and is able to successfully reach the metrics backend.",
                    "summary": "Unit '{{ $labels.juju_unit }}' of application '{{ $labels.juju_application }}' is down or failing to remote write.",
                },
                "expr": 'absent(up{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"})',
                "for": "5m",
                "labels": {
                    "juju_application": "opentelemetry-collector-k8s",
                    "juju_charm": "opentelemetry-collector-k8s",
                    "juju_model": "otelcol",
                    "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                    "severity": "warning",
                },
            },
            {
                "alert": "AggregatorMetricsMissing",
                "annotations": {
                    "description": "`Up` missing for ALL units of application {{ $labels.juju_application }} in model {{ $labels.juju_model }}. This can also mean the units or the collector scraping them are unable to reach the remote write endpoint of the metrics backend. Please ensure the correct firewall rules are applied.",
                    "summary": "Metrics not received from application '{{ $labels.juju_application }}'. All units are down or failing to remote write.",
                },
                "expr": 'absent(up{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"})',
                "for": "5m",
                "labels": {
                    "juju_application": "opentelemetry-collector-k8s",
                    "juju_charm": "opentelemetry-collector-k8s",
                    "juju_model": "otelcol",
                    "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                    "severity": "critical",
                },
            },
        ],
    }


@pytest.fixture
def databag_promql_alert_rule_labeled():
    return {
        "name": "otelcol_f4d59020_zoo_zookeeper_alerting_alerts",
        "rules": [
            {
                "alert": "ZooKeeper Missing",
                "annotations": {
                    "description": "ZooKeeper target has disappeared. An exporter might be crashed.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}",
                    "summary": "Prometheus target missing (instance {{ $labels.instance }})",
                },
                "expr": 'up{juju_application="zoo",juju_charm!=".*",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"} == 0',
                "for": "0m",
                "labels": {
                    "juju_application": "zoo",
                    "juju_charm": "zookeeper",
                    "juju_model": "otelcol",
                    "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                    "severity": "critical",
                },
            },
        ],
    }


@pytest.fixture
def databag_logql_alert_rule_labeled():
    return {
        "name": "otelcol_f4d59020_loki_loki_alerts_alerts",
        "rules": [
            {
                "alert": "HighLogVolume",
                "annotations": {"summary": "Log rate is too high!"},
                "expr": '(count_over_time({job=~".+", juju_application="loki", juju_charm="loki-coordinator-k8s", juju_model="otelcol", juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"}[30s]) > 100)',
                "labels": {
                    "juju_application": "loki",
                    "juju_charm": "loki-coordinator-k8s",
                    "juju_model": "otelcol",
                    "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                    "severity": "high",
                },
            }
        ],
    }


@pytest.fixture
def otelcol_bundled_promql_alert_rule_labeled():
    return {
        "name": "otelcol_f4d59020_opentelemetry_collector_k8s_Hardware_alerts",
        "rules": [
            {
                "alert": "high-cpu-usage",
                "expr": 'max(rate(otelcol_process_cpu_seconds_total{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"}[5m]) * 100) > 90',
                "for": "5m",
                "labels": {
                    "severity": "critical",
                    "juju_model": "otelcol",
                    "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                    "juju_application": "opentelemetry-collector-k8s",
                    "juju_charm": "opentelemetry-collector-k8s",
                },
                "annotations": {
                    "summary": "High max CPU usage",
                    "description": "Collector needs to scale up",
                },
            }
        ],
    }


@pytest.mark.parametrize(
    "databag, expected_group_counts",
    [
        # format , databag_groups, generic_groups, bundled_groups, total
        # logql  , (0)           , (0)           , (0)           , (0)
        # promql , (1)           , (1)           , (3)           , (5)
        (
            {"rules": {"logql": {"alert_rules": None}, "promql": {"alert_rules": ZOO_RULES}}},
            {"logql": 0, "promql": 5},
        ),
        # format , databag_groups, generic_groups, bundled_groups, total
        # logql  , (1)           , (0)           , (0)           , (1)
        # promql , (1)           , (1)           , (3)           , (5)
        (
            {
                "rules": {
                    "logql": {"alert_rules": LOKI_RULES},
                    "promql": {"alert_rules": ZOO_RULES},
                }
            },
            {"logql": 1, "promql": 5},
        ),
        # format , databag_groups, generic_groups, bundled_groups, total
        # logql  , (1)           , (0)           , (0)           , (1)
        # promql , (0)           , (1)           , (3)           , (4)
        (
            {"rules": {"logql": {"alert_rules": LOKI_RULES}, "promql": {"alert_rules": None}}},
            {"logql": 1, "promql": 4},
        ),
    ],
)
def test_forwarded_otlp_alert_rule_counts(ctx, otelcol_container, databag, expected_group_counts):
    # GIVEN receive-otlp and send-otlp relations
    provider_appdata = OtlpConsumerAppData.model_validate(databag)
    receiver = Relation("receive-otlp", remote_app_data=provider_appdata.to_databag())
    sender_1 = Relation("send-otlp")
    sender_2 = Relation("send-otlp")
    state = State(
        relations=[receiver, sender_1, sender_2],
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN all expected loki and prom alert rules exist in the databag
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules

        assert rules.logql.alert_rules is not None
        assert rules.promql.alert_rules is not None
        assert len(rules.logql.alert_rules.get("groups", [])) == expected_group_counts["logql"]
        assert len(rules.promql.alert_rules.get("groups", [])) == expected_group_counts["promql"]


@pytest.mark.parametrize(
    "databag, expected_group_counts",
    [
        # format , databag_groups, generic_groups, bundled_groups, total
        # logql  , (0)           , (0)           , (0)           , (0)
        # promql , (0)           , (0)           , (0)           , (0)
        (
            {"rules": {"logql": {"recording_rules": None}, "promql": {"recording_rules": None}}},
            {"logql": 0, "promql": 0},
        ),
    ],
)
def test_forwarded_otlp_record_rule_counts(ctx, otelcol_container, databag, expected_group_counts):
    # GIVEN receive-otlp and send-otlp relations
    provider_appdata = OtlpConsumerAppData.model_validate(databag)
    receiver = Relation("receive-otlp", remote_app_data=provider_appdata.to_databag())
    sender_1 = Relation("send-otlp")
    sender_2 = Relation("send-otlp")
    state = State(
        relations=[receiver, sender_1, sender_2],
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN all expected loki and prom alert rules exist in the databag
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules

        assert rules.logql.recording_rules is not None
        assert rules.promql.recording_rules is not None
        assert len(rules.logql.recording_rules.get("groups", [])) == expected_group_counts["logql"]
        assert (
            len(rules.promql.recording_rules.get("groups", [])) == expected_group_counts["promql"]
        )


def test_forwarded_alert_rules_have_topology(
    ctx,
    otelcol_container,
    databag_logql_alert_rule_labeled,
    databag_promql_alert_rule_labeled,
    otelcol_bundled_promql_alert_rule_labeled,
    generic_promql_alert_rule_labeled,
):
    # GIVEN receive-otlp and send-otlp relations
    databag = {
        "rules": {"logql": {"alert_rules": LOKI_RULES}, "promql": {"alert_rules": ZOO_RULES}}
    }
    provider_appdata = OtlpConsumerAppData.model_validate(databag)
    receiver = Relation("receive-otlp", remote_app_data=provider_appdata.to_databag())
    sender_1 = Relation("send-otlp")
    sender_2 = Relation("send-otlp")
    state = State(
        relations=[receiver, sender_1, sender_2],
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN all expected loki and prom alert rules exist in the databag
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules

        # --- logql assertions ---
        # THEN the upstream databag alert rule has topology labels injected
        group_name = "otelcol_f4d59020_loki_loki_alerts_alerts"
        actual = get_group_by_name(rules.logql.alert_rules, group_name)
        assert actual == databag_logql_alert_rule_labeled

        # --- promql assertions ---
        # THEN the upstream databag alert rule has topology labels injected
        group_name = "otelcol_f4d59020_zoo_zookeeper_alerting_alerts"
        actual = get_group_by_name(rules.promql.alert_rules, group_name)
        assert actual == databag_promql_alert_rule_labeled

        # THEN the bundled alert rule has topology labels injected
        group_name = "otelcol_f4d59020_opentelemetry_collector_k8s_Hardware_alerts"
        actual = get_group_by_name(rules.promql.alert_rules, group_name)
        assert actual == otelcol_bundled_promql_alert_rule_labeled

        # THEN the generic alert rule has topology labels injected
        group_name = "otelcol_f4d59020_opentelemetry_collector_k8s_AggregatorHostHealth_alerts"
        actual = get_group_by_name(rules.promql.alert_rules, group_name)
        assert actual == generic_promql_alert_rule_labeled


def test_forwarded_alert_rules_compression(
    ctx,
    otelcol_container,
):
    # GIVEN receive-otlp and send-otlp relations
    databag = {
        "rules": {"logql": {"alert_rules": LOKI_RULES}, "promql": {"alert_rules": ZOO_RULES}}
    }
    provider_appdata = OtlpConsumerAppData.model_validate(databag)
    receiver = Relation("receive-otlp", remote_app_data=provider_appdata.to_databag())
    sender_1 = Relation("send-otlp")
    sender_2 = Relation("send-otlp")
    state = State(
        relations=[receiver, sender_1, sender_2],
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        raw_data = rel.local_app_data
        # THEN the databag contains a compressed set of alert rules
        expected = json.loads(LZMABase64.decompress(raw_data.get("rules", "")))
        # AND WHEN they are accessed with OtlpConsumerAppData.rules
        actual = json.loads(OtlpConsumerAppData.model_validate(raw_data).rules.model_dump_json())
        # THEN they are decompressed
        assert actual == expected
