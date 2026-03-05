# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Unit tests for rules_forwarded_with_topology.feature."""

import dataclasses
import json

from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State
from pytest_bdd import scenarios, given, parsers, then, when

from src.otlp import OtlpConsumerAppData

# scenarios("features/rules_forwarded_with_topology.feature")


# ----- HELPERS -----


def _replace(*args, **kwargs):
    return dataclasses.replace(*args, **kwargs)


# ----- GIVEN -----


@given("a logql alerting rule", target_fixture="logql_alert_rule")
def logql_alert_rule():
    return {
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


@given("a promql alerting rule", target_fixture="promql_alert_rule")
def promql_alert_rule():
    return {
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


# ----- STATE -----


# Databag
@given("empty remote appdata", target_fixture="remote_app_data")
def empty_remote_appdata():
    return {}


@given("logql and promql alerting rules in remote appdata", target_fixture="remote_app_data")
def logql_and_promql_alerting_rules_in_remote_appdata(logql_alert_rule, promql_alert_rule):
    provider_appdata = OtlpConsumerAppData.model_validate(
        {"rules": {"logql": logql_alert_rule, "promql": promql_alert_rule}}
    )
    return provider_appdata.to_databag()


# Relations
@given(parsers.parse('a "{endpoint}" endpoint'), target_fixture="endpoint")
def endpoint_name(endpoint):
    return endpoint


# Config
@given(parsers.parse('"{config}" config is set to True'), target_fixture="config")
def bool_config_true(config):
    return {config: True}


@given(parsers.parse('"{config}" config is set to False'), target_fixture="config")
def bool_config_false(config):
    return {config: False}


@given("the operator is initialized", target_fixture="state")
def base_state(otelcol_container):
    return State(
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )


# State
@when("integrated with our charm", target_fixture="state")
def integrate(state, endpoint, remote_app_data):
    updated_relations = list(state.relations).copy()
    updated_relations.append(Relation(endpoint, remote_app_data=remote_app_data))
    return _replace(state, relations=updated_relations)


@when("the charm is config is applied", target_fixture="state")
def update_config(state, config):
    updated_config = state.config.copy()
    updated_config.update(config)
    return _replace(state, config=updated_config)


# ----- EVENTS -----


@when(parsers.parse('the operator executes the "{event}" event'), target_fixture="state_out")
def operator_executes_event(ctx, state, event):
    return ctx.run(getattr(ctx.on, event)(), state=state)


# ----- THEN -----


@then("bundled promql, alerting rules are published to local appdata, with topology")
def bundled_promql_alert_rules_are_published_to_local_appdata(state_out):
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules
        group_name = "otelcol_f4d59020_opentelemetry_collector_k8s_Hardware_alerts"
        actual = get_group_by_name(rules.promql.alerting, group_name)
        assert actual == {
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


@then("generic promql, alerting rules are published to local appdata, with topology")
def generic_promql_alert_rules_are_published_to_local_appdata(state_out):
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules
        group_name = "otelcol_f4d59020_opentelemetry_collector_k8s_AggregatorHostHealth_alerts"
        actual = get_group_by_name(rules.promql.alerting, group_name)
        assert actual == {
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


@then("upstream logql, alerting rules are published to local appdata, with topology")
def upstream_logql_alert_rules_are_published_to_local_appdata(state_out):
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules
        group_name = "otelcol_f4d59020_loki_loki_alerts_alerts"
        actual = get_group_by_name(rules.logql.alerting, group_name)
        assert actual == {
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


@then("upstream promql, alerting rules are published to local appdata, with topology")
def upstream_promql_alert_rules_are_published_to_local_appdata(state_out):
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules
        group_name = "otelcol_f4d59020_zoo_zookeeper_alerting_alerts"
        actual = get_group_by_name(rules.promql.alerting, group_name)
        assert actual == {
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


@then(parsers.parse("local appdata contains the following rules:"))
def count_rules_in_send_otlp_local_appdata(state_out, datatable):
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules
        for row in datatable[1:]:
            query_type = row[0].strip()
            type = row[1].strip()
            upstream_rules = int(row[2])
            generic_rules = int(row[3])
            bundled_rules = int(row[4])
            total = generic_rules + bundled_rules + upstream_rules
            assert (rule_types := getattr(rules, query_type, None)) is not None
            assert (rule_group := getattr(rule_types, type, None)) is not None
            assert len(rule_group.get("groups", [])) == total


@then("local appdata alert rules are compressed")
def local_appdata_alert_rules_are_compressed(state_out):
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        raw_data = rel.local_app_data
        expected = json.loads(LZMABase64.decompress(raw_data.get("rules", "")))
        actual = json.loads(OtlpConsumerAppData.model_validate(raw_data).rules.model_dump_json())
        assert actual == expected
