#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import os
from typing import Any, Dict
from pathlib import Path
import yaml
import logging

from config import ConfigManager

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

logger = logging.getLogger(__name__)
RulesMapping = namedtuple("RulesMapping", ["src", "dest"])


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container("opentelemetry-collector").can_connect():
            return
        charm_root = self.charm_dir.absolute()
        self.metrics_rules_paths = RulesMapping(
            # TODO how to inject topology only for this charm's own rules?
            # FIXED: this is already handled by reusing the *Rules classes
            src=charm_root.joinpath(*"src/prometheus_alert_rules".split("/")),
            dest=charm_root.joinpath(*"prometheus_alert_rules".split("/")),
        )
        self.reconcile()

    def reconcile(self):
        """Recreate the world state for the charm."""
        name = "opentelemetry-collector"
        container = self.unit.get_container(name)
        config_manager = ConfigManager().default_config()

        self.unit.set_ports(*config_manager.ports)

        # Receive metrics via remote-write and forward alert rules to prometheus/mimir
        self.remote_write = PrometheusRemoteWriteConsumer(
            self, alert_rules_path=self.metrics_rules_paths.dest
        )
        config_manager = config_manager.add_exporter(
            "prometheusremotewrite",  # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/prometheusremotewriteexporter
            {
                "endpoint": self.remote_write.endpoints[0]["url"],  # TODO Fix this for scalability
                "tls": {"insecure": True},  # TODO This is temporary
            },
        )

        # Receive alert rules and scrape jobs
        # TODO We are not scraping otel-collector so we do not get an `up` metric for generic alert rules
        self.metrics_consumer = MetricsEndpointConsumer(self)
        # add self-monitoring
        self._update_alerts_rules()  # TODO This method relies on self.remote_write which is a bit weird
        for job in self.metrics_consumer.jobs():
            config_manager = config_manager.add_scrape_job(
                job
            )  # TODO Is this doing anything besides writing the otel config
        # TODO metrics_consumer.jobs() come from relations so we can get av jobs to otel from relations
        #   but then this is not transferred to prom bc prom is not receiving jobs (only alerts) from otel

        # Receive alert rules
        # config_manager.add_receiver(
        #     "prometheusremotewritereceiver",  # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusremotewritereceiver
        #     {
        #         # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277
        #     },
        # )
        # self.remote_write_provider = PrometheusRemoteWriteProvider(
        #     charm=self,
        #     relation_name=DEFAULT_REMOTE_WRITE_RELATION_NAME,
        #     server_url_func=lambda: "http://10.152.183.136:9090",
        #     endpoint_path="/api/v1/write",
        # )

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

    def _update_alerts_rules(
        self,
        copy_files: bool = False,
    ):
        """Copy alert rules from relations and save them to disk."""
        if os.path.exists(self.metrics_rules_paths.dest):
            shutil.rmtree(self.metrics_rules_paths.dest)
        if copy_files:
            shutil.copytree(self.metrics_rules_paths.src, self.metrics_rules_paths.dest)
        else:
            os.mkdir(
                self.metrics_rules_paths.dest
            )  # This dir gets created in gagent and should be created in otel as well
        for topology_identifier, rule in self.metrics_consumer.alerts.items():
            rule_file = Path(self.metrics_rules_paths.dest) / f"juju_{topology_identifier}.rules"
            rule_file.write_text(yaml.safe_dump(rule))
            logger.debug(f"updated alert rules file {rule_file.as_posix()}")
        self.remote_write.reload_alerts()


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
