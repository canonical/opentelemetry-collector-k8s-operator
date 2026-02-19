# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoint handling."""

from helpers import count_src_rules
from ops.testing import Model, Relation, State

from src.constants import LOKI_RULES_SRC_PATH, METRICS_RULES_SRC_PATH
from src.otlp import OtlpConsumerAppData

# TODO: Combine this with test_otlp. I separated for clarity for now
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

PROM_RULES = {
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

# TODO: Split up the alert rules test into the ones Leon suggested so that we can have dict equality assertions
REMOTE_DATABAG = {
    "groups": [
        {
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
        },
        {
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
        },
        {
            "alert": "AggregatorMetricsMissing",
            "expr": 'absent(up{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"})',
            "for": "5m",
            "labels": {
                "severity": "critical",
                "juju_model": "otelcol",
                "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                "juju_application": "opentelemetry-collector-k8s",
                "juju_charm": "opentelemetry-collector-k8s",
            },
            "annotations": {
                "summary": "Metrics not received from application '{{ $labels.juju_application }}'. All units are down or failing to remote write.",
                "description": "`Up` missing for ALL units of application {{ $labels.juju_application }} in model {{ $labels.juju_model }}. This can also mean the units or the collector scraping them are unable to reach the remote write endpoint of the metrics backend. Please ensure the correct firewall rules are applied.",
            },
        },
        {
            "name": "otelcol_f4d59020_opentelemetry_collector_k8s_Exporter_alerts",
            "rules": [
                {
                    "alert": "failed-logs",
                    "expr": 'sum(rate(otelcol_exporter_send_failed_log_records_total{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"}[5m])) > 0',
                    "for": "5m",
                    "labels": {
                        "severity": "critical",
                        "juju_model": "otelcol",
                        "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                        "juju_application": "opentelemetry-collector-k8s",
                        "juju_charm": "opentelemetry-collector-k8s",
                    },
                    "annotations": {
                        "summary": "Some log points failed to send by exporter",
                        "description": "Destination may have a problem or payload is incorrect",
                    },
                },
                {
                    "alert": "failed-metrics",
                    "expr": 'sum(rate(otelcol_exporter_send_failed_metric_points_total{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"}[5m])) > 0',
                    "for": "5m",
                    "labels": {
                        "severity": "critical",
                        "juju_model": "otelcol",
                        "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                        "juju_application": "opentelemetry-collector-k8s",
                        "juju_charm": "opentelemetry-collector-k8s",
                    },
                    "annotations": {
                        "summary": "Some metric points failed to send by exporter",
                        "description": "Destination may have a problem or payload is incorrect",
                    },
                },
                {
                    "alert": "queue-full-prediction",
                    "expr": 'predict_linear(otelcol_exporter_queue_size{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"}[1h], 3600) > otelcol_exporter_queue_capacity{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"}',
                    "for": "5m",
                    "labels": {
                        "severity": "critical",
                        "juju_model": "otelcol",
                        "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                        "juju_application": "opentelemetry-collector-k8s",
                        "juju_charm": "opentelemetry-collector-k8s",
                    },
                    "annotations": {
                        "summary": "The queue is expected to be full within the next hour",
                        "description": "The exporter may be incorrectly configured for the pipeline, check that the exporter's endpoint is operational",
                    },
                },
            ],
        },
        {
            "name": "otelcol_f4d59020_opentelemetry_collector_k8s_Receiver_alerts",
            "rules": [
                {
                    "alert": "receiver-refused-logs",
                    "expr": 'sum(rate(otelcol_receiver_refused_log_records_total{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"}[5m])) > 0',
                    "for": "5m",
                    "labels": {
                        "severity": "critical",
                        "juju_model": "otelcol",
                        "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                        "juju_application": "opentelemetry-collector-k8s",
                        "juju_charm": "opentelemetry-collector-k8s",
                    },
                    "annotations": {
                        "summary": "Some log points have been refused by receiver",
                        "description": "Maybe collector has received non standard log points or it reached some limits",
                    },
                },
                {
                    "alert": "receiver-refused-metrics",
                    "expr": 'sum(rate(otelcol_receiver_refused_metric_points_total{juju_application="opentelemetry-collector-k8s",juju_model="otelcol",juju_model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"}[5m])) > 0',
                    "for": "5m",
                    "labels": {
                        "severity": "critical",
                        "juju_model": "otelcol",
                        "juju_model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
                        "juju_application": "opentelemetry-collector-k8s",
                        "juju_charm": "opentelemetry-collector-k8s",
                    },
                    "annotations": {
                        "summary": "Some metric points have been refused by receiver",
                        "description": "Maybe collector has received non standard metric points or it reached some limits",
                    },
                },
            ],
        },
    ]
}


def test_forward_otlp_alert_rules(ctx, otelcol_container):
    # GIVEN receive-otlp and send-otlp relations
    provider_appdata = OtlpConsumerAppData.model_validate(
        {"rules": {"logql": {"alert_rules": LOKI_RULES}, "promql": {"alert_rules": PROM_RULES}}}
    )
    receiver = Relation("receive-otlp", remote_app_data=provider_appdata.to_databag())
    provider_1 = Relation(
        "send-otlp",
        id=123,
    )
    provider_2 = Relation(
        "send-otlp",
        id=456,
    )
    state = State(
        relations=[receiver, provider_1, provider_2],
        leader=True,
        containers=otelcol_container,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN all expected loki and prom alert rules exist in the databag
    databag_groups = 1  # from ZOO_RULES
    generic_groups = 1
    promql_groups = count_src_rules([METRICS_RULES_SRC_PATH])
    logql_groups = count_src_rules([LOKI_RULES_SRC_PATH])
    for rel in list(state_out.relations):
        if rel.endpoint != "send-otlp":
            continue
        rules = OtlpConsumerAppData.model_validate(rel.local_app_data).rules

        assert rules.logql.alert_rules is not None
        assert rules.promql.alert_rules is not None
        group_count = len(rules.logql.alert_rules.get("groups", []))
        assert group_count == logql_groups + databag_groups
        group_count = len(rules.promql.alert_rules.get("groups", []))
        assert group_count == promql_groups + generic_groups + databag_groups

        # THEN the upstream databag rule has topology labels injected
        expected_group = REMOTE_DATABAG["groups"][0]
        group_by_name = {
            group["name"]: group for group in rules.promql.alert_rules.get("groups", [])
        }
        assert expected_group["name"] in group_by_name
        assert expected_group == group_by_name[expected_group["name"]]
