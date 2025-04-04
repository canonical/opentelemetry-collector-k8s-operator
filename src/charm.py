#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import json
import logging
import os
import shutil
from collections import namedtuple
from pathlib import Path
from typing import Any, Dict, List, cast

import yaml
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LokiPushApiConsumer, LokiPushApiProvider
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointConsumer,
)
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
)
from cosl import JujuTopology, LZMABase64
from ops import CharmBase, main
from ops.model import ActiveStatus, MaintenanceStatus
from ops.pebble import Layer

from config import PORTS, Config

logger = logging.getLogger(__name__)
PathMapping = namedtuple("PathMapping", ["src", "dest"])


def _aggregate_alerts(rules: Dict, rule_path_map: PathMapping, forward_alert_rules: bool):
    rules = rules if forward_alert_rules else {}
    if os.path.exists(rule_path_map.dest):
        shutil.rmtree(rule_path_map.dest)
    shutil.copytree(rule_path_map.src, rule_path_map.dest)
    for topology_identifier, rule in rules.items():
        rule_file = Path(rule_path_map.dest) / f"juju_{topology_identifier}.rules"
        rule_file.write_text(yaml.safe_dump(rule))
        logger.debug(f"updated alert rules file {rule_file.as_posix()}")


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    _config_path = "/etc/otelcol/config.yaml"
    _container_name = "otelcol"
    _metrics_rules_src_path = "src/prometheus_alert_rules"
    _metrics_rules_dest_path = "prometheus_alert_rules"
    _loki_rules_src_path = "src/loki_alert_rules"
    _loki_rules_dest_path = "loki_alert_rules"
    _dashboards_src_path = "src/grafana_dashboards"
    _dashboards_dest_path = (
        "grafana_dashboards"  # TODO from gagent: placeholder until we figure out the plug
    )

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container(self._container_name).can_connect():
            self.unit.status = MaintenanceStatus("Waiting for otelcol to start")
            return

        self.topology = JujuTopology.from_charm(self)
        self.otel_config = Config.default_config()

        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm."""
        container = self.unit.get_container(self._container_name)
        charm_root = self.charm_dir.absolute()
        forward_alert_rules = cast(bool, self.config["forward_alert_rules"])

        # Dashboards setup
        dashboard_paths = PathMapping(
            src=charm_root.joinpath(*self._dashboards_src_path.split("/")),
            dest=charm_root.joinpath(*self._dashboards_dest_path.split("/")),
        )
        if not os.path.isdir(dashboard_paths.dest):
            # TODO @leon We create the src directory to avoid excessive mocking in tests
            dashboard_paths.src.mkdir(parents=True, exist_ok=True)
            shutil.copytree(dashboard_paths.src, dashboard_paths.dest, dirs_exist_ok=True)
        grafana_dashboards_provider = GrafanaDashboardProvider(
            self,
            relation_name="grafana-dashboards-provider",
            dashboards_path=dashboard_paths.dest,
        )
        self._aggregate_dashboards(dashboard_paths)
        # TODO Make this a public method like reload_alerts for logs and metrics
        grafana_dashboards_provider._update_all_dashboards_from_dir()
        # TODO Do we need to implement dashboard status changed? I think not since we reconcile
        # self._on_dashboard_status_changed,
        # grafana_dashboards_provider._reinitialize_dashboard_data(inject_dropdowns=False)  # noqa

        # Logs setup
        loki_rules_paths = PathMapping(
            src=charm_root.joinpath(*self._loki_rules_src_path.split("/")),
            dest=charm_root.joinpath(*self._loki_rules_dest_path.split("/")),
        )
        loki_provider = LokiPushApiProvider(
            self,
            relation_name="receive-loki-logs",
            port=PORTS.LOKI_HTTP,
        )
        loki_consumer = LokiPushApiConsumer(
            self,
            relation_name="send-loki-logs",
            alert_rules_path=loki_rules_paths.dest,
            forward_alert_rules=forward_alert_rules,
        )
        _aggregate_alerts(loki_provider.alerts, loki_rules_paths, forward_alert_rules)
        loki_consumer.reload_alerts()
        self._add_log_ingestion()
        self._add_log_forwarding(loki_consumer.loki_endpoints)

        # Metrics setup
        metrics_rules_paths = PathMapping(
            src=charm_root.joinpath(*self._metrics_rules_src_path.split("/")),
            dest=charm_root.joinpath(*self._metrics_rules_dest_path.split("/")),
        )
        # Receive alert rules and scrape jobs
        metrics_consumer = MetricsEndpointConsumer(self)
        _aggregate_alerts(metrics_consumer.alerts, metrics_rules_paths, forward_alert_rules)
        self._add_self_scrape()
        self.otel_config.add_prometheus_scrape(metrics_consumer.jobs(), self._incoming_metrics)
        # Forward alert rules and scrape jobs to Prometheus
        remote_write = PrometheusRemoteWriteConsumer(
            self, alert_rules_path=metrics_rules_paths.dest
        )
        remote_write.reload_alerts()
        self._add_remote_write(remote_write.endpoints)

        # Deploy/update
        container.push(self._config_path, self.otel_config.yaml)
        container.add_layer(self._container_name, self._pebble_layer, combine=True)
        container.replan()
        self.unit.set_ports(
            *self.otel_config.ports
        )  # TODO Conditionally open ports based on the otelcol config file rather than opening all ports
        self.unit.status = ActiveStatus()

    @property
    def _pebble_layer(self) -> Layer:
        """Construct the Pebble layer informataion."""
        layer = Layer(
            {
                "summary": "opentelemetry-collector-k8s layer",
                "description": "opentelemetry-collector-k8s layer",
                "services": {
                    "otelcol": {
                        "override": "replace",
                        "summary": "opentelemetry-collector-k8s service",
                        "command": f"/usr/bin/otelcol --config={self._config_path}",
                        "startup": "enabled",
                        "environment": {
                            "_config_hash": self.otel_config.hash,  # Restarts the service on config change via pebble replan
                            "https_proxy": os.environ.get("JUJU_CHARM_HTTPS_PROXY", ""),
                            "http_proxy": os.environ.get("JUJU_CHARM_HTTP_PROXY", ""),
                            "no_proxy": os.environ.get("JUJU_CHARM_NO_PROXY", ""),
                        },
                    }
                },
                "checks": self._pebble_checks,
            }
        )

        return layer

    @property
    def _pebble_checks(self) -> Dict[str, Any]:
        """Pebble checks to run in the charm."""
        checks = {
            "up": {
                "override": "replace",
                "level": "alive",
                "period": "30s",
                "http": {"url": f"http://localhost:{PORTS.HEALTH}/health"},  # TODO: TLS
            },
            "valid-config": {
                "override": "replace",
                "level": "alive",
                "exec": {"command": f"otelcol validate --config={self._config_path}"},
            },
        }
        return checks

    @property
    def _incoming_metrics(self) -> bool:
        return any(self.model.relations.get("metrics-endpoint", []))

    @property
    def _incoming_logs(self) -> bool:
        return any(self.model.relations.get("receive-loki-logs", []))

    @property
    def _outgoing_metrics(self) -> bool:
        return any(self.model.relations.get("send-remote-write", []))

    @property
    def _outgoing_logs(self) -> bool:
        return any(self.model.relations.get("send-loki-logs", []))

    @property
    def dashboards(self) -> list:
        """Returns an aggregate of all dashboards received by this otelcol."""
        aggregate = {}
        for rel in self.model.relations["grafana-dashboards-consumer"]:
            dashboards = json.loads(rel.data[rel.app].get("dashboards", "{}"))  # type: ignore
            if "templates" not in dashboards:
                continue
            for template in dashboards["templates"]:
                content = json.loads(
                    LZMABase64.decompress(dashboards["templates"][template].get("content"))
                )
                entry = {
                    "charm": dashboards["templates"][template].get("charm", "charm_name"),
                    "relation_id": rel.id,
                    "title": template,
                    "content": content,
                }
                aggregate[template] = entry

        return list(aggregate.values())

    # TODO we have self.dashboards, why did we support Any for dashboards? Check other code paths.
    def _aggregate_dashboards(self, mapping: PathMapping):
        """Copy dashboards from relations, save them to disk, and update."""
        logger.info("updating dashboards")

        if not self.unit.is_leader():
            return

        shutil.rmtree(mapping.dest)
        shutil.copytree(mapping.src, mapping.dest)
        for dash in self.dashboards:
            # Build dashboard custom filename
            charm = dash.get("charm", "charm-name")
            rel_id = dash.get("relation_id", "rel_id")
            title = dash.get("title").replace(" ", "_").replace("/", "_").lower()
            filename = f"juju_{title}-{charm}-{rel_id}.json"

            with open(Path(mapping.dest, filename), mode="w", encoding="utf-8") as f:
                f.write(json.dumps(dash["content"]))
                logger.debug("updated dashboard file %s", f.name)

    def _add_self_scrape(self):
        """Configure self-monitoring scrape jobs."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver
        self.otel_config.add_receiver(
            "prometheus",
            {
                "config": {
                    "scrape_configs": [
                        {
                            "job_name": self.topology.identifier,  # This job name is overwritten with "otelcol" when remote-writing
                            "scrape_interval": "60s",
                            "static_configs": [
                                {
                                    "targets": [f"0.0.0.0:{PORTS.METRICS}"],
                                    "labels": self.topology.alert_expression_dict,
                                }
                            ],
                        }
                    ]
                }
            },
            pipelines=["metrics"],
        )

    def _add_remote_write(self, endpoints: List[Dict[str, str]]):
        """Configure forwarding alert rules to prometheus/mimir via remote-write."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/prometheusremotewriteexporter
        for idx, endpoint in enumerate(endpoints):
            self.otel_config.add_exporter(
                f"prometheusremotewrite/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "tls": {"insecure": True},  # TODO TLS
                },
                pipelines=["metrics"],
            )

        # TODO Receive alert rules via remote write
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277

    def _add_log_ingestion(self):
        """Configure receiving logs, allowing Promtail instances to specify the Otelcol as their lokiAddress."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/lokireceiver

        # For now, the only incoming and outgoing log relations are loki push api,
        # so we don't need to mix and match between them yet.
        if self._incoming_logs:
            self.otel_config.add_receiver(
                "loki",
                {
                    "protocols": {
                        "http": {"endpoint": f"0.0.0.0:{PORTS.LOKI_HTTP}"},
                    },
                    "use_incoming_timestamp": True,
                },
                pipelines=["logs"],
            )

    def _add_log_forwarding(self, endpoints: List[dict]):
        """Configure sending logs to Loki via the Loki push API endpoint.

        The LogRecord format is controlled with the `loki.format` hint.

        The Loki exporter converts OTLP resource and log attributes into Loki labels, which are indexed.
        Configuring hints (e.g. `loki.attribute.labels`) specifies which attributes should be placed as labels.
        The hints are themselves attributes and will be ignored when exporting to Loki.
        """
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.122.0/exporter/lokiexporter
        for idx, endpoint in enumerate(endpoints):
            self.otel_config.add_exporter(
                f"loki/exporter-{idx}",
                {
                    "endpoint": endpoint["url"],
                    "default_labels_enabled": {"exporter": False, "job": True},
                },
                pipelines=["logs"],
            )
        if self._outgoing_logs:
            self.otel_config.add_processor(
                "resource",
                {
                    "attributes": [
                        {
                            "action": "insert",
                            "key": "loki.format",
                            "value": "raw",  # logfmt, json, raw
                        },
                    ]
                },
                pipelines=["logs"],
            ).add_processor(
                "attributes",
                {
                    "actions": [
                        {
                            "action": "upsert",
                            "key": "loki.attribute.labels",
                            # These labels are set in `_scrape_configs` of the `v1.loki_push_api` lib
                            "value": "container, job, filename, juju_application, juju_charm, juju_model, juju_model_uuid, juju_unit",
                        },
                    ]
                },
                pipelines=["logs"],
            )


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
