# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from typing import Any, Dict, Union

from cosl.utils import LZMABase64
from ops.testing import Relation, State, Model

ConfigDict = Dict[str, Union[str, int, float, bool]]

MODEL_NAME = "my_model"
MODEL_UUID = "74a5690b-89c9-44dd-984b-f69f26a6b751"
MODEL = Model(MODEL_NAME, uuid=MODEL_UUID)
ZINC_GROUP_NAME_SUBSTR = "I_AM_A_ZINC_GROUP"
ZINC_TOPOLOGY_LABELS = {
    "juju_application": "zinc",
    "juju_charm": "zinc-k8s",
    "juju_model": MODEL_NAME,
    "juju_model_uuid": MODEL_UUID,
}
OTLP_TOPOLOGY_LABELS = {
    "juju_application": "opentelemetry-collector-k8s",
    "juju_charm": "opentelemetry-collector-k8s",
    "juju_model": MODEL_NAME,
    "juju_model_uuid": MODEL_UUID,
}

zinc_alerts = {
    "alert_rules": json.dumps(
        {
            "groups": [
                {
                    "name": ZINC_GROUP_NAME_SUBSTR,
                    "rules": [
                        {
                            "alert": "Missing",
                            "expr": "up == 0",
                            "for": "0m",
                            "labels": {
                                "juju_model": MODEL_NAME,
                                "juju_model_uuid": MODEL_UUID,
                                "juju_application": "zinc",
                                "juju_charm": "zinc-k8s",
                            },
                        }
                    ],
                }
            ]
        }
    )
}


def _assert_extra_labels(
    alert_rules: Dict[str, Any], extra_labels: Dict[str, str], *, present: bool
):
    """Assert extra alert labels are present/absent and topology labels are always present."""
    assert alert_rules.get("groups"), "No groups found in alert rules"
    for group in alert_rules["groups"]:
        common_labels = (
            ZINC_TOPOLOGY_LABELS
            if ZINC_GROUP_NAME_SUBSTR in group["name"]
            else OTLP_TOPOLOGY_LABELS
        )
        for rule in group["rules"]:
            if present:
                for key, value in extra_labels.items():
                    assert rule["labels"][key] == value
            else:
                for key in extra_labels:
                    assert key not in rule["labels"]
            for key, value in common_labels.items():
                assert rule["labels"][key] == value


def test_extra_metrics_alerts_config(ctx, otelcol_container):
    # GIVEN a new key-value pair of extra alerts labels, for instance:
    # juju config otelcol extra_alerts_labels="environment: PRODUCTION, zone=Mars"
    extra_labels = {"environment": "PRODUCTION", "zone": "Mars"}
    config1: ConfigDict = {
        "extra_alert_labels": "environment: PRODUCTION, zone=Mars",
    }

    # THEN The extra_alert_labels MUST be added to the alert rules.
    metrics_endpoint_relation = Relation(
        "metrics-endpoint", remote_app_name="zinc", remote_app_data=zinc_alerts
    )
    remote_write_relation = Relation("send-remote-write", remote_app_name="prometheus")
    state = State(
        leader=True,
        model=MODEL,
        relations=[metrics_endpoint_relation, remote_write_relation],
        containers=otelcol_container,
        config=config1,  # type: ignore
    )
    out_0 = ctx.run(ctx.on.relation_changed(relation=metrics_endpoint_relation), state)
    out_1 = ctx.run(
        ctx.on.relation_joined(relation=out_0.get_relation(remote_write_relation.id)), out_0
    )
    alert_rules = json.loads(
        out_1.get_relation(remote_write_relation.id).local_app_data["alert_rules"]
    )
    _assert_extra_labels(alert_rules, extra_labels, present=True)

    # GIVEN the config option for extra alert labels is unset
    config2: ConfigDict = {"extra_alert_labels": ""}

    # THEN the only labels present in the alert are the JujuTopology labels
    next_state = State(
        leader=True,
        model=MODEL,
        relations=out_1.relations,
        containers=out_1.containers,
        config=config2,
    )
    out_2 = ctx.run(ctx.on.config_changed(), next_state)
    alert_rules_mod = json.loads(
        out_2.get_relation(remote_write_relation.id).local_app_data["alert_rules"]
    )
    _assert_extra_labels(alert_rules_mod, extra_labels, present=False)


def test_extra_loki_alerts_config(ctx, otelcol_container):
    # GIVEN a new key-value pair of extra alerts labels, for instance:
    # juju config otelcol extra_alerts_labels="environment: PRODUCTION, zone=Mars"
    extra_labels = {"environment": "PRODUCTION", "zone": "Mars"}
    config1: ConfigDict = {"extra_alert_labels": "environment: PRODUCTION, zone=Mars"}

    # THEN The extra_alert_labels MUST be added to the alert rules.
    receive_loki_logs_relation = Relation(
        "receive-loki-logs", remote_app_name="zinc", remote_app_data=zinc_alerts
    )
    send_loki_logs_relation = Relation("send-loki-logs", remote_app_name="loki")
    state = State(
        leader=True,
        model=MODEL,
        relations=[receive_loki_logs_relation, send_loki_logs_relation],
        containers=otelcol_container,
        config=config1,  # type: ignore
    )
    out_0 = ctx.run(ctx.on.relation_changed(relation=receive_loki_logs_relation), state)
    out_1 = ctx.run(
        ctx.on.relation_joined(relation=out_0.get_relation(send_loki_logs_relation.id)), out_0
    )
    alert_rules = json.loads(
        out_1.get_relation(send_loki_logs_relation.id).local_app_data["alert_rules"]
    )
    _assert_extra_labels(alert_rules, extra_labels, present=True)

    # GIVEN the config option for extra alert labels is unset
    config2: ConfigDict = {"extra_alert_labels": ""}

    # THEN the only labels present in the alert are the JujuTopology labels
    next_state = State(
        leader=True,
        model=MODEL,
        relations=out_1.relations,
        containers=out_1.containers,
        config=config2,
    )
    out_2 = ctx.run(ctx.on.config_changed(), next_state)
    alert_rules_mod = json.loads(
        out_2.get_relation(send_loki_logs_relation.id).local_app_data["alert_rules"]
    )
    _assert_extra_labels(alert_rules_mod, extra_labels, present=False)


def test_extra_otlp_alerts_config(ctx, otelcol_container, all_rules):
    # GIVEN a new key-value pair of extra alerts labels
    extra_labels = {"environment": "PRODUCTION", "zone": "Mars"}
    config1: ConfigDict = {"extra_alert_labels": "environment: PRODUCTION, zone=Mars"}

    # THEN The extra_alert_labels MUST be added to the alert rules in the send-otlp databag.
    receive_otlp_relation = Relation(
        "receive-otlp",
        remote_app_data={"rules": json.dumps(all_rules, sort_keys=True), "metadata": "{}"},
    )
    send_otlp_relation = Relation("send-otlp")
    state = State(
        leader=True,
        model=MODEL,
        relations=[receive_otlp_relation, send_otlp_relation],
        containers=otelcol_container,
        config=config1,  # type: ignore
    )
    out_0 = ctx.run(ctx.on.relation_changed(relation=receive_otlp_relation), state)
    out_1 = ctx.run(
        ctx.on.relation_joined(relation=out_0.get_relation(send_otlp_relation.id)), out_0
    )
    compressed_rules = out_1.get_relation(send_otlp_relation.id).local_app_data.get("rules")
    assert compressed_rules
    decompressed = json.loads(LZMABase64.decompress(json.loads(compressed_rules)))
    # Check promql rules have extra labels
    for groups in decompressed.get("logql", {}), decompressed.get("promql", {}):
        _assert_extra_labels(groups, extra_labels, present=True)

    # GIVEN the config option for extra alert labels is unset
    config2: ConfigDict = {"extra_alert_labels": ""}

    # THEN the extra labels are no longer present
    next_state = State(
        leader=True,
        model=MODEL,
        relations=out_1.relations,
        containers=out_1.containers,
        config=config2,
    )
    out_2 = ctx.run(ctx.on.config_changed(), next_state)
    compressed_rules_mod = out_2.get_relation(send_otlp_relation.id).local_app_data.get("rules")
    assert compressed_rules_mod
    decompressed_mod = json.loads(LZMABase64.decompress(json.loads(compressed_rules_mod)))
    for groups in decompressed_mod.get("logql", {}), decompressed_mod.get("promql", {}):
        _assert_extra_labels(groups, extra_labels, present=False)
