#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import logging
import os
from typing import Dict, cast, Optional, List
from functools import partial

from charmlibs.pathops import ContainerPath
from cosl import JujuTopology, MandatoryRelationPairs
from ops import BlockedStatus, CharmBase, Container, main
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus
from ops.pebble import CheckDict, ExecDict, HttpDict, Layer

import integrations
from config_builder import Port
from config_manager import ConfigManager
from constants import (
    CONFIG_PATH,
    RECV_CA_CERT_FOLDER_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
    SERVICE_NAME,
)


logger = logging.getLogger(__name__)


def is_tls_ready(container: Container) -> bool:
    """Return True if the server cert and private key are present on disk."""
    return container.exists(path=SERVER_CERT_PATH) and container.exists(
        path=SERVER_CERT_PRIVATE_KEY_PATH
    )


def refresh_certs(container: Container):
    """Run `update-ca-certificates` to refresh the trusted system certs."""
    container.exec(["update-ca-certificates", "--fresh"]).wait()


def _get_missing_mandatory_relations(charm: CharmBase) -> Optional[str]:
    """Check whether mandatory relations are in place.

    The charm can use this information to set BlockedStatus.
    Without any matching outgoing relation, the collector could incur data loss.

    Incoming relations are evaluated with AND, while outgoing relations with OR.

    Returns:
        A string containing the missing relations in string format, or None if
        all the mandatory relation pairs are present.
    """
    relation_pairs = MandatoryRelationPairs(
        pairs={
            "metrics-endpoint": [  # must be paired with:
                {"send-remote-write"},  # or
                {"cloud-config"},
            ],
            "receive-loki-logs": [  # must be paired with:
                {"send-loki-logs"},  # or
                {"cloud-config"},
            ],
            "receive-traces": [  # must be paired with:
                {"send-traces"},  # or
                {"cloud-config"},
            ],
            "grafana-dashboards-consumer": [  # must be paired with:
                {"grafana-dashboards-provider"},  # or
                {"cloud-config"},
            ],
        }
    )
    active_relations = {name for name, relation in charm.model.relations.items() if relation}
    missing_str = relation_pairs.get_missing_as_str(*active_relations)
    return missing_str or None


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    _container_name = "otelcol"

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container(self._container_name).can_connect():
            self.unit.status = MaintenanceStatus("Waiting for otelcol to start")
            return

        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm.

        In order to trigger a restart when needed, this method tracks configuration changes
        via environment variables in the Pebble layer. A hash of the configuration is stored
        in the layer, triggering a restart when changes are detected. The same approach is
        used for managing server certificates.

        Note:
            The pattern used in this charm avoids holding instances as attributes. When using
            event-based libraries, instances will be garbage collected between the charm
            initialization and the event emission.
        """
        container = self.unit.get_container(self._container_name)
        insecure_skip_verify = cast(bool, self.config.get("tls_insecure_skip_verify"))
        integrations.cleanup()

        # Integrate with TLS relations
        receive_ca_certs_hash = integrations.receive_ca_cert(
            self,
            recv_ca_cert_folder_path=ContainerPath(RECV_CA_CERT_FOLDER_PATH, container=container),
            refresh_certs=partial(refresh_certs, container=container),
        )
        server_cert_hash = integrations.receive_server_cert(
            self,
            server_cert_path=ContainerPath(SERVER_CERT_PATH, container=container),
            private_key_path=ContainerPath(SERVER_CERT_PRIVATE_KEY_PATH, container=container),
        )

        config_manager = ConfigManager(
            receiver_tls=is_tls_ready(container),
            insecure_skip_verify=cast(bool, self.config.get("tls_insecure_skip_verify")),
            queue_size=cast(int, self.config.get("queue_size")),
            max_elapsed_time_min=cast(int, self.config.get("max_elapsed_time_min")),
        )

        # TODO: if/when we support multiple feature gates, make this a list and find out how to
        #  pass multiple feature gates into the pebble layer command;
        #  cf: https://github.com/canonical/opentelemetry-collector-k8s-operator/issues/17
        feature_gates: Optional[str] = None

        # Logs setup
        integrations.receive_loki_logs(self, tls=is_tls_ready(container))
        loki_endpoints = integrations.send_loki_logs(self)
        if self._incoming_logs:
            config_manager.add_log_ingestion()
        config_manager.add_log_forwarding(loki_endpoints, insecure_skip_verify)

        # Metrics setup
        topology = JujuTopology.from_charm(self)
        config_manager.add_self_scrape(
            identifier=topology.identifier,
            labels={
                "instance": f"{topology.identifier}_{topology.unit}",
                "juju_charm": topology.charm_name,
                "juju_model": topology.model,
                "juju_model_uuid": topology.model_uuid,
                "juju_application": topology.application,
                "juju_unit": topology.unit,
            },
        )
        # For now, the only incoming and outgoing metrics relations are remote-write/scrape
        metrics_consumer_jobs = integrations.scrape_metrics(self)
        config_manager.add_prometheus_scrape_jobs(metrics_consumer_jobs)
        remote_write_endpoints = integrations.send_remote_write(self)
        config_manager.add_remote_write(remote_write_endpoints)

        # Profile forwarding setup
        profiling_endpoints = integrations.send_profiles(self)
        if profiling_endpoints:
            config_manager.add_profiling(profiling_endpoints, tls=is_tls_ready(container))
            feature_gates = "service.profilesSupport"

        # Tracing setup
        requested_tracing_protocols = integrations.receive_traces(
            self, tls=is_tls_ready(container)
        )
        if self._incoming_traces:
            config_manager.add_traces_ingestion(requested_tracing_protocols)
            # Add default processors to traces
            config_manager.add_traces_processing(
                sampling_rate_charm=cast(bool, self.config.get("tracing_sampling_rate_charm")),
                sampling_rate_workload=cast(
                    bool, self.config.get("tracing_sampling_rate_workload")
                ),
                sampling_rate_error=cast(bool, self.config.get("tracing_sampling_rate_error")),
            )
        tracing_otlp_http_endpoint = integrations.send_traces(self)
        if tracing_otlp_http_endpoint:
            config_manager.add_traces_forwarding(tracing_otlp_http_endpoint)
        integrations.send_charm_traces(self)

        # Dashboards setup
        integrations.forward_dashboards(self)

        # GrafanaCloudIntegrator setup
        cloud_integrator_data = integrations.cloud_integrator(self)
        config_manager.add_cloud_integrator(
            username=cloud_integrator_data.username,
            password=cloud_integrator_data.password,
            prometheus_url=cloud_integrator_data.prometheus_url,
            loki_url=cloud_integrator_data.loki_url,
            tempo_url=cloud_integrator_data.tempo_url,
        )

        # Add custom processors from Juju config
        if custom_processors := cast(str, self.config.get("processors")):
            config_manager.add_custom_processors(custom_processors)

        # Push the config and Push the config and deploy/update
        container.push(CONFIG_PATH, config_manager.config.build(), make_dirs=True)

        # If the config file or any cert has changed, a change in this environment variable
        # will trigger a restart
        pebble_extra_env = {
            "_reload": ",".join(
                [
                    config_manager.config.hash,
                    receive_ca_certs_hash,
                    server_cert_hash,
                ]
            )
        }
        container.add_layer(
            self._container_name,
            self._pebble_layer(environment=pebble_extra_env, feature_gates=feature_gates),
            combine=True
        )
        # TODO: Conditionally open ports based on the otelcol config file rather than opening all ports
        self.unit.set_ports(*[port.value for port in Port])

        if self._has_server_cert_relation and not is_tls_ready(container):
            # A tls relation to a CA was formed, but we didn't get the cert yet.
            container.stop(SERVICE_NAME)
            self.unit.status = WaitingStatus("CSR sent; otelcol down while waiting for a cert")
        else:
            container.replan()
            self.unit.status = ActiveStatus()

        # Mandatory relation pairs
        missing_relations = _get_missing_mandatory_relations(self)
        if missing_relations:
            self.unit.status = BlockedStatus(missing_relations)

    def _pebble_layer(self, environment: Dict, feature_gates:Optional[str]) -> Layer:
        """Construct the Pebble layer configuration.

        Args:
            environment: Dictionary containing environment variables to be passed to the Pebble layer.
            feature_gates: Feature gates that should be enabled by otelcol, if any..

        Returns:
            Layer: A Pebble Layer object containing the service configuration.
        """
        otelcol_args = [
            f"--config={CONFIG_PATH}"
        ]
        if feature_gates:
            otelcol_args.append(f"--feature-gates={feature_gates}")

        layer = Layer(
            {
                "summary": "opentelemetry-collector-k8s layer",
                "description": "opentelemetry-collector-k8s layer",
                "services": {
                    SERVICE_NAME: {
                        "override": "replace",
                        "summary": "opentelemetry-collector-k8s service",
                        "command": " ".join(("/usr/bin/otelcol", *otelcol_args)),
                        "startup": "enabled",
                        "environment": {
                            "https_proxy": os.environ.get("JUJU_CHARM_HTTPS_PROXY", ""),
                            "http_proxy": os.environ.get("JUJU_CHARM_HTTP_PROXY", ""),
                            "no_proxy": os.environ.get("JUJU_CHARM_NO_PROXY", ""),
                            **environment,
                        },
                    }
                },
                "checks": self._pebble_checks(otelcol_args=otelcol_args),
            }
        )

        return layer

    def _pebble_checks(self, otelcol_args:List[str]) -> Dict[str, CheckDict]:
        """Define Pebble checks for the workload container.

        Returns:
            Dict[str, Any]: A dictionary containing Pebble check configurations
            for the OpenTelemetry Collector service.
        """
        checks = {
            "up": CheckDict(
                override="replace",
                level="alive",
                period="30s",
                # TODO If we render TLS config for the extensions::health_check, switch to https
                http=HttpDict(url=f"http://localhost:{Port.health.value}/health"),
            ),
            "valid-config": CheckDict(
                override="replace",
                level="alive",
                exec=ExecDict(command=" ".join(filter(None,("otelcol", "validate", *otelcol_args)))),
            ),
        }
        return checks

    @property
    def _incoming_logs(self) -> bool:
        return any(self.model.relations.get("receive-loki-logs", []))

    @property
    def _incoming_traces(self) -> bool:
        return any(self.model.relations.get("receive-traces", []))

    @property
    def _has_server_cert_relation(self) -> bool:
        return any(self.model.relations.get("receive-server-cert", []))


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
