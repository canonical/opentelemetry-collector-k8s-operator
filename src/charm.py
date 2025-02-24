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

from urllib.parse import urlparse
from config import Config, Ports

from ops import CharmBase, main
from ops.model import ActiveStatus
from ops.pebble import Layer
from charms.loki_k8s.v1.loki_push_api import LokiPushApiProvider
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


def _aggregate_alerts(alerts: Dict, rule_path_mapping: RulesMapping):
    # TODO Do we need to make this extendable for loki_alerts like in grafana_agent.py #L493
    if os.path.exists(rule_path_mapping.dest):
        shutil.rmtree(rule_path_mapping.dest)
    shutil.copytree(rule_path_mapping.src, rule_path_mapping.dest)
    for topology_identifier, rule in alerts.items():
        rule_file = Path(rule_path_mapping.dest) / f"juju_{topology_identifier}.rules"
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

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container(self._container_name).can_connect():
            return

        self.topology = JujuTopology.from_charm(self)
        self.otel_config = Config.default_config()
        charm_root = self.charm_dir.absolute()

        # Logs setup
        self.loki_rules_paths = RulesMapping(
            src=charm_root.joinpath(*self._loki_rules_src_path.split("/")),
            dest=charm_root.joinpath(*self._loki_rules_dest_path.split("/")),
        )
        # TODO Determine if we can use these libs without events
        internal_url = urlparse(self.internal_url)
        self.loki_provider = LokiPushApiProvider(
            self,
            address=internal_url.hostname,
            port=Ports.LOKI_GRPC.value,
            scheme=internal_url.scheme,
            path=internal_url.path,  # TODO "/loki/api/v1/push" is now pathless in otelcol
        )

        # Metrics setup
        self.metrics_rules_paths = RulesMapping(
            src=charm_root.joinpath(*self._metrics_rules_src_path.split("/")),
            dest=charm_root.joinpath(*self._metrics_rules_dest_path.split("/")),
        )
        self.metrics_consumer = MetricsEndpointConsumer(self)
        self.remote_write = PrometheusRemoteWriteConsumer(
            self, alert_rules_path=self.metrics_rules_paths.dest
        )

        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm."""
        container = self.unit.get_container(self._container_name)

        self._add_log_ingestion()
        self._add_remote_write()
        self._add_self_scrape()
        # Receive and update alert rules
        _aggregate_alerts(self.metrics_consumer.alerts, self.metrics_rules_paths)
        self.remote_write.reload_alerts()
        # Receive scrape jobs and add them to the otel config
        self.otel_config.add_prometheus_scrape(self.metrics_consumer.jobs())

        container.push(self._config_path, self.otel_config.yaml)

        container.add_layer(self._container_name, self._pebble_layer, combine=True)
        container.replan()

        self.unit.set_ports(*self.otel_config.ports)
        self.unit.status = ActiveStatus()

    @property
    def internal_url(self):
        """Fqdn plus appropriate scheme and server port."""
        scheme = "http"
        return f"{scheme}://{socket.getfqdn()}"

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
                "http": {"url": f"http://localhost:{Ports.HEALTH.value}/health"},  # TODO: TLS
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
                                    "targets": [f"0.0.0.0:{Ports.METRICS.value}"],
                                    "labels": self.topology.alert_expression_dict,
                                }
                            ],
                        }
                    ]
                }
            },
            pipelines=["metrics"],
        )

    def _add_remote_write(self):
        """Configure forwarding alert rules to prometheus/mimir via remote-write."""
        for idx, endpoint in enumerate(self.remote_write.endpoints):
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
        # The Loki receiver implements the Loki push api.
        # It allows Promtail instances to specify the open telemetry collector as their lokiAddress.
        self.otel_config.add_receiver(
            "loki",
            {
                "protocols": {
                    "http": {"endpoint": f"0.0.0.0:{Ports.LOKI_HTTP.value}"},
                    "grpc": {"endpoint": f"0.0.0.0:{Ports.LOKI_GRPC.value}"},
                },
                "use_incoming_timestamp": True,  # if set true the timestamp from Loki log entry is used
            },
            pipelines=["logs"],
        )


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
