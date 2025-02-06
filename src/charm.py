#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import socket
import os
from typing import Any, Dict, Set
from pathlib import Path
import yaml
import logging

from config import OpenTelemetryCollectorConfig

from ops import CharmBase, main
from ops.model import ActiveStatus, Port
from ops.pebble import Layer
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointConsumer,
)
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
    PrometheusRemoteWriteProvider,
    DEFAULT_RELATION_NAME as DEFAULT_REMOTE_WRITE_RELATION_NAME,
)

PORTS: Set[Port] = {
    Port(protocol="tcp", port=8888),  # for self-monitoring metrics
}

logger = logging.getLogger(__name__)

class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    def __init__(self, *args):
        super().__init__(*args)

        self._name = "opentelemetry-collector"
        self._container = self.unit.get_container(self._name)
        self._config_manager = OpenTelemetryCollectorConfig()
        self.reconcile()

    def reconcile(self):
        """Recreate the world state for the charm."""
        if not self._container.can_connect():
            # TODO:: set MaintenceStatus ?
            return

        self._set_ports(ports=PORTS)

        self._container.push("/etc/otelcol/config.yaml", self._config_manager.build_config())

        self._container.add_layer(self._name, self._pebble_layer, combine=True)
        self._container.replan()

        for job in self.metrics_consumer.jobs:
            self._config_manager.add_scrape_job(job)

        # Receive alert rules and scrape jobs
        self.metrics_consumer = MetricsEndpointConsumer(self)

        # Receive metrics via remote-write and forward alert rules to prometheus/mimir
        self.remote_write_provider = PrometheusRemoteWriteProvider(
            charm=self,
            relation_name=DEFAULT_REMOTE_WRITE_RELATION_NAME,
            server_url_func=lambda: f"http://{socket.getfqdn()}:{self.get_port()}",
            endpoint_path="/api/v1/write",
        )
        alert_rules_path = "/tmp/aggregated_prometheus_alert_rules"
        for topology_identifier, rule in self.metrics_consumer.alerts.items():
            file_handle = Path(alert_rules_path, f"juju_{topology_identifier}.rules")
            file_handle.write_text(yaml.dump(rule))
            logger.debug("updated alert rules file {}".format(file_handle.absolute()))
        # Receive alert rules
        self.remote_write = PrometheusRemoteWriteConsumer(self, alert_rules_path=alert_rules_path)
        self.remote_write.reload_alerts()

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
                "http": {"url": f"http://{socket.getfqdn()}:13133/health"},
            },
        }
        return checks

    def _set_ports(self, ports: Set[Port]) -> None:
        """Open necessary (and close no longer needed) workload ports."""
        if not self.unit.is_leader():
            return
        actual_ports = self.unit.opened_ports()

        # Ports may change across an upgrade, so need to sync
        ports_to_close = actual_ports.difference(ports)
        for p in ports_to_close:
            self.unit.close_port(p.protocol, p.port)

        new_ports_to_open = ports.difference(ports)
        for p in new_ports_to_open:
            self.unit.open_port(p.protocol, p.port)


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
