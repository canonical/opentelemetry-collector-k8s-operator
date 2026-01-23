#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import logging
import os
import re
import socket
from typing import Dict, List, Optional, cast

from charmlibs.pathops import ContainerPath
from charms.observability_libs.v0.kubernetes_compute_resources_patch import (
    KubernetesComputeResourcesPatch,
    adjust_resource_requirements,
)
from charms.traefik_k8s.v0.traefik_route import TraefikRouteRequirer
from cosl import JujuTopology, MandatoryRelationPairs
from lightkube.models.core_v1 import ResourceRequirements
from ops import BlockedStatus, CharmBase, Container, StatusBase, main
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus
from ops.pebble import APIError, CheckDict, ExecDict, HttpDict, Layer

import integrations
from config_builder import Port
from config_manager import ConfigManager
from constants import (
    CERTS_DIR,
    CONFIG_PATH,
    EXTERNAL_CONFIG_SECRETS_DIR,
    RECV_CA_CERT_FOLDER_PATH,
    SERVER_CA_CERT_PATH,
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


def scheme(container: Container) -> str:
    """Return the URI scheme that should be used when communicating with this unit."""
    return "https" if is_tls_ready(container) else "http"


def external_url(ingress: TraefikRouteRequirer) -> Optional[str]:
    """Return the external URL for the ingress, if configured."""
    return (
        f"{ingress.scheme}://{ingress.external_host}"
        if integrations.ingress_ready(ingress)
        else None
    )


def internal_url(container: Container) -> str:
    """Return the locally addressable, FQDN based service address."""
    return f"{scheme(container)}://{socket.getfqdn()}"


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
        self.resources_patch = KubernetesComputeResourcesPatch(
            self,
            container_name=self._container_name,
            resource_reqs_func=self._resource_reqs_from_config,
        )
        resources_patch_status: StatusBase = self.resources_patch.get_status()
        if not isinstance(resources_patch_status, ActiveStatus):
            self.unit.status = resources_patch_status
            return

        insecure_skip_verify = cast(bool, self.config.get("tls_insecure_skip_verify"))
        integrations.cleanup()

        # Service mesh integration
        integrations.setup_service_mesh(self)

        # Ingress integration
        ingress = integrations.setup_ingress(self, tls=is_tls_ready(container))

        # Integrate with TLS relations
        receive_ca_certs_hash = integrations.receive_ca_cert(
            self,
            recv_ca_cert_folder_path=ContainerPath(RECV_CA_CERT_FOLDER_PATH, container=container),
        )
        server_cert_hash = integrations.receive_server_cert(
            self,
            server_cert_path=ContainerPath(SERVER_CERT_PATH, container=container),
            private_key_path=ContainerPath(SERVER_CERT_PRIVATE_KEY_PATH, container=container),
            root_ca_cert_path=ContainerPath(SERVER_CA_CERT_PATH, container=container),
        )
        # Refresh system certs
        # This must be run after receive_ca_cert and/or receive_server_cert because they update
        # certs in the /usr/local/share/ca-certificates directory
        refresh_certs(container)

        # Global scrape configs
        global_configs = {
            "global_scrape_interval": cast(str, self.config.get("global_scrape_interval")),
            "global_scrape_timeout": cast(str, self.config.get("global_scrape_timeout")),
        }
        for name, global_config in global_configs.items():
            pattern = r"^\d+[ywdhms]$"
            match = re.fullmatch(pattern, global_config)
            if not match:
                self.unit.status = BlockedStatus(
                    f"The {name} config requires format: '\\d+[ywdhms]'."
                )
                return

        # Create the config manager
        config_manager = ConfigManager(
            global_scrape_interval=global_configs["global_scrape_interval"],
            global_scrape_timeout=global_configs["global_scrape_timeout"],
            receiver_tls=is_tls_ready(container),
            insecure_skip_verify=cast(bool, self.config.get("tls_insecure_skip_verify")),
            queue_size=cast(int, self.config.get("queue_size")),
            max_elapsed_time_min=cast(int, self.config.get("max_elapsed_time_min")),
            unit_name=self.unit.name,
        )

        # TODO: if/when we support multiple feature gates, make this a list and find out how to
        #  pass multiple feature gates into the pebble layer command;
        #  cf: https://github.com/canonical/opentelemetry-collector-k8s-operator/issues/17
        feature_gates: Optional[str] = None

        # Logs setup
        integrations.receive_loki_logs(self, is_tls_ready(container), external_url(ingress))
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
        # Write CA certificates to disk and update job configurations
        self._ensure_certs_dir(container)
        cert_paths = self._write_ca_certificates_to_disk(metrics_consumer_jobs, container)
        metrics_consumer_jobs = config_manager.update_jobs_with_ca_paths(
            metrics_consumer_jobs, cert_paths
        )
        config_manager.add_prometheus_scrape_jobs(metrics_consumer_jobs)
        remote_write_endpoints = integrations.send_remote_write(self)
        config_manager.add_remote_write(remote_write_endpoints)

        # External-config setup
        integrations.receive_external_configs(self)
        self._ensure_external_configs_secrets_dir(container)
        self._write_secrets_to_disk(container)
        self._configure_external_configs(config_manager)
        self._remove_external_configs_secrets_dir(container)

        # Profiling setup
        if self._incoming_profiles:
            config_manager.add_profile_ingestion()
            integrations.receive_profiles(self, tls=is_tls_ready(container))
        if profiling_endpoints := integrations.send_profiles(self):
            config_manager.add_profile_forwarding(profiling_endpoints)
        if self._incoming_profiles or integrations.send_profiles(self):
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

        # Add debug exporters from Juju config
        config_manager.add_debug_exporters(
            cast(bool, self.config.get("debug_exporter_for_logs")),
            cast(bool, self.config.get("debug_exporter_for_metrics")),
            cast(bool, self.config.get("debug_exporter_for_traces")),
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
            combine=True,
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

        # Workload version
        self.unit.set_workload_version(self._otelcol_version or "")

    def _pebble_layer(self, environment: Dict, feature_gates: Optional[str]) -> Layer:
        """Construct the Pebble layer configuration.

        Args:
            environment: Dictionary containing environment variables to be passed to the Pebble layer.
            feature_gates: Feature gates that should be enabled by otelcol, if any..

        Returns:
            Layer: A Pebble Layer object containing the service configuration.
        """
        otelcol_args = [f"--config={CONFIG_PATH}"]
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

    def _pebble_checks(self, otelcol_args: List[str]) -> Dict[str, CheckDict]:
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
                threshold=3,
            ),
            "valid-config": CheckDict(
                override="replace",
                level="alive",
                exec=ExecDict(
                    command=" ".join(filter(None, ("otelcol", "validate", *otelcol_args)))
                ),
                threshold=3,
            ),
        }
        return checks

    def _ensure_certs_dir(self, container: Container) -> None:
        if not container.can_connect():
            logger.warning("container not accessible, skipping certificates directory creation")
            return

        directory = ContainerPath(CERTS_DIR, container=container)
        directory.mkdir(exist_ok=True)

    def _ensure_external_configs_secrets_dir(self, container: Container) -> None:
        if not container.can_connect():
            logger.warning("container not accessible, skipping external config secrets directory creation")
            return

        directory = ContainerPath(EXTERNAL_CONFIG_SECRETS_DIR, container=container)
        directory.mkdir(exist_ok=True)

    def _remove_external_configs_secrets_dir(self, container: Container) -> None:
        if not container.can_connect():
            logger.warning("container not accessible, skipping external config secrets directory creation")
            return

        if self.external_secret_files:
            return

        container.remove_path(EXTERNAL_CONFIG_SECRETS_DIR, recursive=True)

    def _write_ca_certificates_to_disk(
        self, scrape_jobs: List[Dict], container: Container
    ) -> Dict[str, str]:
        cert_paths = {}

        if not container.can_connect():
            logger.warning("Container not accessible, skipping CA certificate processing")
            return cert_paths

        for job in scrape_jobs:
            tls_config = job.get("tls_config", {})
            ca_content = tls_config.get("ca")

            if not ca_content or not self._validate_cert(ca_content):
                continue

            job_name = job.get("job_name", "default")
            # Since the `MetricsEndpointProvider` accepts a `jobs` arg, we cannot rely on the job name being safe
            safe_job_name = job_name.replace("/", "_").replace(" ", "_").replace("-", "_")
            ca_cert_path = f"{CERTS_DIR}otel_{safe_job_name}_ca.pem"

            container.push(ca_cert_path, ca_content, permissions=0o644)
            cert_paths[job_name] = ca_cert_path
            logger.debug(f"CA certificate for job '{job_name}' written to {ca_cert_path}")

        return cert_paths

    def _write_secrets_to_disk(self, container: Container):
        if not container.can_connect():
            logger.warning("Container not accessible, cannot write secrets to disk")
            return

        for filepath, secret in self.external_secret_files.items():
            filepath = ContainerPath(filepath, container=container)
            filepath.write_text(secret, mode=0o644)
            logger.debug("secret written to %s", filepath)

        return

    def _configure_external_configs(self, config_manager: ConfigManager):
        config_manager.add_external_configs(self.external_configs)


    @property
    def _otelcol_version(self) -> Optional[str]:
        """Returns the otelcol workload version."""
        try:
            container = self.unit.get_container(self._container_name)
            version_output, _ = container.exec(
                ["/usr/bin/otelcol", "--version"], timeout=30
            ).wait_output()
        except APIError:
            return None

        # Output looks like this:
        # otelcol version 0.130.1
        result = re.search(r"version (\d*\.\d*\.\d*)", version_output)
        if result is None:
            return result
        return result.group(1)

    @property
    def _incoming_logs(self) -> bool:
        return any(self.model.relations.get("receive-loki-logs", []))

    @property
    def _incoming_traces(self) -> bool:
        return any(self.model.relations.get("receive-traces", []))

    @property
    def _incoming_profiles(self) -> bool:
        return any(self.model.relations.get("receive-profiles", []))

    @property
    def _has_server_cert_relation(self) -> bool:
        return any(self.model.relations.get("receive-server-cert", []))

    def _resource_reqs_from_config(self) -> ResourceRequirements:
        limits = {
            "cpu": self.model.config.get("cpu"),
            "memory": self.model.config.get("memory"),
        }
        requests = {"cpu": "0.25", "memory": "200Mi"}
        return adjust_resource_requirements(limits, requests, adhere_to_requests=True)

    def _validate_cert(self, cert: str) -> bool:
        pem_pattern = r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
        return bool(re.search(pem_pattern, cert, re.DOTALL))


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
