#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import os
from typing import Any, Dict
from pathlib import Path
import yaml
import logging
import socket

from config import ConfigManager

from ops import CharmBase, main
from ops.model import ActiveStatus
from ops.pebble import Layer
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointConsumer,
)
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
    PrometheusRemoteWriteProvider,
    DEFAULT_RELATION_NAME as DEFAULT_REMOTE_WRITE_RELATION_NAME,
)

logger = logging.getLogger(__name__)

class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container("opentelemetry-collector").can_connect():
            return
        self.reconcile()

    def reconcile(self):
        """Recreate the world state for the charm."""
        name = "opentelemetry-collector"
        container = self.unit.get_container(name)
        config_manager = ConfigManager().default_config()

        self.unit.set_ports(*config_manager.ports)


        # Receive alert rules and scrape jobs
        self.metrics_consumer = MetricsEndpointConsumer(self)
        for job in self.metrics_consumer.jobs():
            config_manager = config_manager.add_scrape_job(job)

        # Receive metrics via remote-write and forward alert rules to prometheus/mimir
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/dcc223ecdf413318c33728cc712b1230903fb22d/CHANGELOG-API.md#-enhancements--4
        # TODO v0.113.0 - remote-write was added but not implemented yet, see above
        self.remote_write_provider = PrometheusRemoteWriteProvider(
            charm=self,
            relation_name=DEFAULT_REMOTE_WRITE_RELATION_NAME,
            server_url_func=lambda: f"http://{socket.getfqdn()}:8888",
            endpoint_path="/api/v1/write",
        )

        alert_rules_path = "/etc/otelcol/aggregated_prometheus_alert_rules"
        for topology_identifier, rule in self.metrics_consumer.alerts.items():
            rule_file = Path(alert_rules_path) / f"juju_{topology_identifier}.rules"
            container.push(rule_file, yaml.safe_dump(rule))
            logger.debug(f"updated alert rules file {rule_file.as_posix()}")
        # Receive alert rules
        self.remote_write = PrometheusRemoteWriteConsumer(self, alert_rules_path=alert_rules_path)
        self.remote_write.reload_alerts()

        container.push("/etc/otelcol/config.yaml", config_manager.yaml)
        container.add_layer(name, self._pebble_layer, combine=True)
        container.replan()

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
                        "command": "/usr/bin/otelcol --config=/etc/otelcol/config.yaml",
                        "startup": "enabled",
                        "environment": {
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
                "http": {"url": "http://localhost:13133/health"},
            },
        }
        return checks


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
