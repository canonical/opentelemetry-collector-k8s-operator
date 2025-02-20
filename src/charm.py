#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import os
from typing import Any, Dict
from pathlib import Path
import yaml
import logging
import hashlib

from config import Config, Ports

from ops import CharmBase, main
from ops.model import ActiveStatus
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


def sha256(hashable) -> str:
    """Use instead of the builtin hash() for repeatable values."""
    if isinstance(hashable, str):
        hashable = hashable.encode("utf-8")
    return hashlib.sha256(hashable).hexdigest()


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    _config_path = "/etc/otelcol/config.yaml"
    _container_name = "otelcol"
    _rules_source_path = "src/prometheus_alert_rules"
    _rules_destination_path = "prometheus_alert_rules"

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container(self._container_name).can_connect():
            return

        self.otel_config = Config.default_config()
        # Metrics setup
        charm_root = self.charm_dir.absolute()
        self.metrics_consumer = MetricsEndpointConsumer(self)
        self.metrics_rules_paths = RulesMapping(
            src=charm_root.joinpath(*self._rules_source_path.split("/")),
            dest=charm_root.joinpath(*self._rules_destination_path.split("/")),
        )
        self.remote_write = PrometheusRemoteWriteConsumer(
            self, alert_rules_path=self.metrics_rules_paths.dest
        )

        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm."""
        container = self.unit.get_container(self._container_name)

        self.unit.set_ports(*self.otel_config.ports)

        self._configure_prometheus_remote_write()
        self._configure_prometheus_scrape()

        container.push(self._config_path, self.otel_config.yaml)

        container.add_layer(self._container_name, self._pebble_layer, combine=True)
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
                        "command": f"/usr/bin/otelcol --config={self._config_path}",
                        "startup": "enabled",
                        "environment": {
                            "config_hash": self._otel_config_hash,  # This restarts the service on config change via pebble replan
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
                "http": {"url": f"http://localhost:{Ports.HEALTH.value}/health"},
            },
            "valid-config": {
                "override": "replace",
                "level": "alive",
                "exec": {"command": f"otelcol validate --config={self._config_path}"},
            },
        }
        return checks

    @property
    def _otel_config_hash(self):
        return sha256(yaml.safe_dump(self.otel_config.yaml))

    def _configure_prometheus_scrape(self):
        """Configure alert rules and scrape jobs."""
        # Add self-monitoring
        self.otel_config.add_receiver(
            "prometheus",
            {
                "config": {
                    "scrape_configs": [
                        {
                            "job_name": JujuTopology.from_charm(self).identifier,
                            "scrape_interval": "5s",
                            "static_configs": [
                                {
                                    "targets": [f"0.0.0.0:{Ports.METRICS.value}"],
                                    "labels": JujuTopology.from_charm(self).alert_expression_dict,
                                }
                            ],
                        }
                    ]
                }
            },
            pipelines=["metrics"],
        )
        # Receive and update alert rules
        if os.path.exists(self.metrics_rules_paths.dest):
            shutil.rmtree(self.metrics_rules_paths.dest)
        shutil.copytree(self.metrics_rules_paths.src, self.metrics_rules_paths.dest)
        for topology_identifier, rule in self.metrics_consumer.alerts.items():
            rule_file = Path(self.metrics_rules_paths.dest) / f"juju_{topology_identifier}.rules"
            rule_file.write_text(yaml.safe_dump(rule))
            logger.debug(f"updated alert rules file {rule_file.as_posix()}")
        self.remote_write.reload_alerts()
        # Receive scrape jobs and add them to the otel config
        for job in self.metrics_consumer.jobs():
            self.otel_config.add_scrape_job(job)

    def _configure_prometheus_remote_write(self):
        """Configure forwarding alert rules to prometheus/mimir via remote-write."""
        if self.remote_write.endpoints:
            self.otel_config.add_exporter(
                "prometheusremotewrite",
                {
                    "endpoint": self.remote_write.endpoints[0][
                        "url"
                    ],  # TODO Fix this for scalability
                    "tls": {"insecure": True},
                },
                pipelines=["metrics"],
            )

        # TODO Receive alert rules via remote write
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
