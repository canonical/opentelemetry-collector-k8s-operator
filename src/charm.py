#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import os

from ops import CharmBase
from ops.model import ActiveStatus
from ops.pebble import Layer


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    def __init__(self, *args):
        self._name = "opentelemetry-collector"
        self._container = self.unit.get_container(self._name)
        self.reconcile()

    def reconcile(self):
        """Recreate the world state for the charm."""
        self._container.add_layer(self._name, self._pebble_layer, combine=True)
        self.unit.status = ActiveStatus()

    @property
    def _pebble_layer(self) -> Layer:
        """Construct the Pebble layer informataion."""
        layer = Layer(
            {
                "summary": "opentelemetry-collector-k8s layer",
                "description": "opentelemetry-collector-k8s layer",
                "services": {
                    self._name: {
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
