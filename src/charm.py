#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import os
from typing import Any, Dict, List
from pathlib import Path
import yaml
import logging

from config import Config, PORTS

from ops import CharmBase, main
from ops.model import ActiveStatus, MaintenanceStatus
from ops.pebble import Layer
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointConsumer,
)
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
)
from collections import namedtuple
import shutil
from cosl import JujuTopology

logger = logging.getLogger(__name__)
RulesMapping = namedtuple("RulesMapping", ["src", "dest"])


def _aggregate_alerts(rules: Dict, rule_path_map: RulesMapping):
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
    _rules_source_path = "src/prometheus_alert_rules"
    _rules_destination_path = "prometheus_alert_rules"

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container(self._container_name).can_connect():
            self.unit.status = MaintenanceStatus("Waiting for prometheus to start")
            return

        self.topology = JujuTopology.from_charm(self)
        self.otel_config = Config.default_config()

        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm."""
        container = self.unit.get_container(self._container_name)
        charm_root = self.charm_dir.absolute()

        PORTS.clear_ports()  # This must be run before any otelcol config is built

        # Metrics setup
        metrics_rules_paths = RulesMapping(
            src=charm_root.joinpath(*self._rules_source_path.split("/")),
            dest=charm_root.joinpath(*self._rules_destination_path.split("/")),
        )
        # Receive alert rules and scrape jobs
        metrics_consumer = MetricsEndpointConsumer(self)
        _aggregate_alerts(metrics_consumer.alerts, metrics_rules_paths)
        # Update the otel config
        self._add_self_scrape()
        self.otel_config.add_prometheus_scrape(metrics_consumer.jobs())

        # Forward alert rules and scrape jobs to Prometheus
        remote_write = PrometheusRemoteWriteConsumer(
            self, alert_rules_path=metrics_rules_paths.dest
        )
        remote_write.reload_alerts()
        # Update the otel config
        self._add_remote_write(remote_write.endpoints)

        container.push(self._config_path, self.otel_config.yaml)

        container.add_layer(self._container_name, self._pebble_layer, combine=True)
        container.replan()

        self.unit.set_ports(*PORTS.active_ports())
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
                "http": {
                    "url": f"http://localhost:{PORTS.HEALTH}/health"
                },  # TODO: TLS
            },
            "valid-config": {
                "override": "replace",
                "level": "alive",
                "exec": {"command": f"otelcol validate --config={self._config_path}"},
            },
        }
        return checks

    def _add_self_scrape(self):
        """Configure self-monitoring scrape jobs."""
        self.otel_config.add_receiver(
            "prometheus",
            {
                "config": {
                    "scrape_configs": [
                        {
                            "job_name": self.topology.identifier,
                            "scrape_interval": "60s",
                            "static_configs": [
                                {
                                    "targets": [
                                        f"0.0.0.0:{PORTS.METRICS}"
                                    ],
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


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
