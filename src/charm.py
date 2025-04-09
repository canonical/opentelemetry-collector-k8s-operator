#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import logging
import os
import shutil
from collections import namedtuple
from pathlib import Path
from typing import Any, Dict, List, cast
from constants import RECV_CA_CERT_FOLDER_PATH, CONFIG_PATH
import yaml
from charms.loki_k8s.v1.loki_push_api import LokiPushApiConsumer, LokiPushApiProvider
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointConsumer,
)
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
)
from charms.certificate_transfer_interface.v1.certificate_transfer import CertificateTransferRequires
from cosl import JujuTopology
from ops import CharmBase, main, Container
from ops.model import ActiveStatus, MaintenanceStatus
from ops.pebble import Layer

from config import PORTS, Config, sha256

logger = logging.getLogger(__name__)
RulesMapping = namedtuple("RulesMapping", ["src", "dest"])


def _aggregate_alerts(rules: Dict, rule_path_map: RulesMapping, forward_alert_rules: bool):
    rules = rules if forward_alert_rules else {}
    if os.path.exists(rule_path_map.dest):
        shutil.rmtree(rule_path_map.dest)
    # TODO Why does scenario need this to find dirs
    rule_path_map.src.mkdir(parents=True, exist_ok=True)
    shutil.copytree(rule_path_map.src, rule_path_map.dest)
    for topology_identifier, rule in rules.items():
        rule_file = Path(rule_path_map.dest) / f"juju_{topology_identifier}.rules"
        rule_file.write_text(yaml.safe_dump(rule))
        logger.debug(f"updated alert rules file {rule_file.as_posix()}")


def receive_ca_certs(charm: CharmBase, container: Container) -> str:
    """Returns a 'pebble replan sentinel' (hash of all certs), for pebble to determine whether a replan is required."""
    # Obtain certs from relation data
    certificate_transfer = CertificateTransferRequires(charm, "receive-ca-cert")
    ca_certs = certificate_transfer.get_all_certificates()

    # Clean-up previously existing certs
    container.remove_path(RECV_CA_CERT_FOLDER_PATH, recursive=True)

    # Write current certs
    for i, cert in enumerate(ca_certs):
        container.push(RECV_CA_CERT_FOLDER_PATH + f"/{i}.crt", cert, make_dirs=True)

    # Refresh system certs
    container.exec(["update-ca-certificates", "--fresh"]).wait()

    # A hot-reload doesn't pick up new system certs - need to restart the service
    return sha256(yaml.safe_dump(ca_certs))


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    _container_name = "otelcol"
    _metrics_rules_src_path = "src/prometheus_alert_rules"
    _metrics_rules_dest_path = "prometheus_alert_rules"
    _loki_rules_src_path = "src/loki_alert_rules"
    _loki_rules_dest_path = "loki_alert_rules"

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

        # Logs setup
        loki_rules_paths = RulesMapping(
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
        metrics_rules_paths = RulesMapping(
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

        # TLS: receive-ca-cert
        replan_manifest = receive_ca_certs(self, container)

        # Deploy/update
        container.push(CONFIG_PATH, self.otel_config.yaml, make_dirs=True)
        replan_manifest += self.otel_config.hash

        container.add_layer(self._container_name, self._pebble_layer(replan_manifest), combine=True)
        container.replan()
        self.unit.set_ports(
            *self.otel_config.ports
        )  # TODO Conditionally open ports based on the otelcol config file rather than opening all ports
        self.unit.status = ActiveStatus()

    def _pebble_layer(self, sentinel: str) -> Layer:
        """Construct the Pebble layer information.

        Args:
            sentinel: A value indicative of a change that should prompt a replan.
        """
        layer = Layer(
            {
                "summary": "opentelemetry-collector-k8s layer",
                "description": "opentelemetry-collector-k8s layer",
                "services": {
                    "otelcol": {
                        "override": "replace",
                        "summary": "opentelemetry-collector-k8s service",
                        "command": f"/usr/bin/otelcol --config={CONFIG_PATH}",
                        "startup": "enabled",
                        "environment": {
                            "_config_hash": sentinel,  # Restarts the service via pebble replan
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
                "exec": {"command": f"otelcol validate --config={CONFIG_PATH}"},
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
                f"loki/{idx}",
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
