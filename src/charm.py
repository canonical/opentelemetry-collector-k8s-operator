#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import socket
import os
from typing import Any, Dict, Set

from config import OpenTelemetryCollectorConfig

from ops import CharmBase, main
from ops.model import ActiveStatus, Port
from ops.pebble import Layer


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
        config_manager = OpenTelemetryCollectorConfig()

        self.unit.set_ports(*config_manager.ports)

        container.push("/etc/otelcol/config.yaml", config_manager.build_config())

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
