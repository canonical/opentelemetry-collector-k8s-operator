#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import socket
import os
from typing import Any, Dict, Set

from ops import CharmBase, main
from ops.model import ActiveStatus, Port
from ops.pebble import Layer

PORTS: Set[Port] = {
    Port(protocol="tcp", port=8888),  # for self-monitoring metrics
}


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    def __init__(self, *args):
        super().__init__(*args)

        self._name = "opentelemetry-collector"
        self._container = self.unit.get_container(self._name)
        self._set_ports(ports=PORTS)
        self.reconcile()

    def reconcile(self):
        """Recreate the world state for the charm."""
        if not self._container.can_connect():
            # TODO:: set MaintenceStatus ?
            return

        self._container.add_layer(self._name, self._pebble_layer, combine=True)
        self._container.replan()
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
            }
        )

        return layer

    @property
    def _pebble_checks(self) -> Dict[str, Any]:
        """Pebble checks to run in the charm."""
        checks = {
            "health": {
                "override": "replace",
                "level": "alive",
                "period": "30s",
                "http": {"url": f"http://{socket.getfqdn()}:13133/health"},
            },
            "metrics": {
                "override": "replace",
                "level": "health",
                "period": "30s",
                "http": {"url": f"http://{socket.getfqdn()}:8888/metrics"},
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
