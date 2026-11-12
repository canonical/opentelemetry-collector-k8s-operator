#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import logging
import os
import re
import warnings
from typing import Any, Dict, List, Optional, Tuple, cast

from charmlibs.pathops import ContainerPath
from charms.loki_k8s.v1.loki_push_api import LokiPushApiProvider
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointConsumer
from cosl import JujuTopology, MandatoryRelationPairs
from ops import BlockedStatus, CharmBase, Container, main
from ops.jujucontext import JujuContext
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus
from ops.pebble import APIError, CheckDict, ExecDict, HttpDict, Layer

import integrations
from config_builder import Port, sha256
from config_manager import ConfigManager
from constants import (
    CA_TRUST_RESTART_PENDING,
    CA_TRUST_STAMP_PATH,
    CERTS_DIR,
    CONFIG_PATH,
    EXTERNAL_CONFIG_SECRETS_DIR,
    RECV_CA_CERT_FOLDER_PATH,
    SERVER_CA_CERT_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
    SERVICE_NAME,
)
from utils import MemoryDetectionError, container_memory_mib, quantity_to_mib

logger = logging.getLogger(__name__)


def charm_address(
    container: Container,
    traefik_ingress: integrations.TraefikRouteRequirer,
    istio_ingress: integrations.IstioIngressRouteRequirer,
    internal_host: str,
) -> integrations.Address | integrations.MultipleIngressesConfigured:
    """Return the Address dataclass from charm context.

    Args:
        container: An ops.Container where the TLS certificates exist
        traefik_ingress: A TraefikRouteRequirer containing ingress context
        istio_ingress: An IstioIngressRouteRequirer containing ingress context
        internal_host: the in-cluster address remote charms should use to reach this app

    Returns:
        The Address dataclass summarizing the charm's networking context or
        MultipleIngressesConfigured if both Traefik and Istio ingresses are configured.
    """
    istio_ready = integrations.istio_ingress_ready(istio_ingress)
    traefik_ready = integrations.traefik_ingress_ready(traefik_ingress)
    if istio_ready and traefik_ready:
        return integrations.MultipleIngressesConfigured()

    if istio_ready:
        external_tls = istio_ingress.tls_enabled
        external_host = istio_ingress.external_host
    elif traefik_ready:
        external_tls = traefik_ingress.scheme == "https"
        external_host = traefik_ingress.external_host
    else:
        external_tls = False
        external_host = None

    internal_tls = integrations.is_tls_ready(container)
    resolved_host = external_host if external_host else internal_host
    return integrations.Address(
        ingress=traefik_ready or istio_ready,
        resolved_tls=external_tls if (traefik_ready or istio_ready) else internal_tls,
        resolved_host=resolved_host,
    )


def _read_trust_stamp(container: Container) -> Optional[str]:
    try:
        return ContainerPath(CA_TRUST_STAMP_PATH, container=container).read_text()
    except FileNotFoundError:
        return None


def _write_trust_stamp(container: Container, stamp: str) -> None:
    container.push(CA_TRUST_STAMP_PATH, stamp.encode("utf-8"), make_dirs=True)


def _pending_trust_stamp(trust_hash: str) -> str:
    return f"{trust_hash}\n{CA_TRUST_RESTART_PENDING}"


def refresh_certs(container: Container, trust_hash: str) -> bool:
    """Rebuild the system trust store if the certs feeding it changed.

    Args:
        container: the workload container.
        trust_hash: hash of every cert feeding the trust store.

    Returns:
        True if otelcol has not been restarted since the trust store was rebuilt.
    """
    pending_stamp = _pending_trust_stamp(trust_hash)
    stamp = _read_trust_stamp(container)
    # `update-ca-certificates` takes seconds, so skip it when the certs are unchanged.
    if stamp == trust_hash:
        logger.debug("System trust store unchanged; skipping update-ca-certificates")
        return False
    # Built, but not loaded yet: a previous reconcile returned early or failed.
    if stamp == pending_stamp:
        logger.debug("System trust store unchanged, but otelcol has not loaded it yet")
        return True

    container.exec(["update-ca-certificates", "--fresh"]).wait()
    # Stamp only after a successful rebuild; pending until otelcol is restarted.
    _write_trust_stamp(container, pending_stamp)
    return True


def replan_with_trust_store(container: Container, trust_hash: str, restart_pending: bool) -> None:
    """Replan otelcol, restarting it if it has not loaded the rebuilt trust store yet.

    Args:
        container: the workload container.
        trust_hash: hash the trust store was built from, as passed to `refresh_certs`.
        restart_pending: as returned by `refresh_certs`.
    """
    if not restart_pending:
        container.replan()
        return

    service = container.get_services(SERVICE_NAME).get(SERVICE_NAME)
    was_running = bool(service and service.is_running())
    container.replan()
    # Go loads the system cert pool once per process, and `replan()` only restarts on layer
    # changes. On a CA rotation this is a second restart, which is tolerated.
    if was_running:
        logger.info("System trust store rebuilt; restarting %s", SERVICE_NAME)
        container.restart(SERVICE_NAME)

    # A different stamp means the container restarted mid-hook: leave it to be rebuilt.
    if _read_trust_stamp(container) != _pending_trust_stamp(trust_hash):
        logger.warning(
            "System trust store stamp changed during this hook (container restarted?); "
            "leaving it for the next reconcile to rebuild the trust store"
        )
        return
    _write_trust_stamp(container, trust_hash)


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
                {"send-otlp"},
                {"cloud-config"},
            ],
            "receive-loki-logs": [  # must be paired with:
                {"send-loki-logs"},  # or
                {"send-otlp"},
                {"cloud-config"},
            ],
            "receive-traces": [  # must be paired with:
                {"send-traces"},  # or
                {"send-otlp"},
                {"cloud-config"},
            ],
            "grafana-dashboards-consumer": [  # must be paired with:
                {"grafana-dashboards-provider"},  # or
                {"cloud-config"},
            ],
            "receive-otlp": [  # must be paired with:
                {"send-otlp"},  # or
                # Technically, this would depend on databag contents for enabled pipelines,
                # but we keep it simple for now.
                {"send-traces"},
                {"send-loki-logs"},
                {"send-remote-write"},
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
    metrics_consumer: MetricsEndpointConsumer
    loki_provider: LokiPushApiProvider

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container(self._container_name).can_connect():
            self.unit.status = MaintenanceStatus("Waiting for otelcol to start")
            return

        self.external_configs: List[Dict[str, Any]] = []
        self.external_secret_files: Dict[str, str] = {}
        self._reconcile()

    @property
    def unit_fqdn(self) -> str:
        """Return the DNS name of this unit's pod.

        On Kubernetes this resolves to the headless-service address of a single pod, e.g.
        ``otelcol-0.otelcol-endpoints.mymodel.svc.cluster.local``. It addresses exactly one
        unit, so it must only be used for unit-local concerns such as the collector's own
        internal telemetry.
        """
        return integrations.unit_fqdn()

    @property
    def service_fqdn(self) -> str:
        """Return the DNS name of the Kubernetes Service fronting all units of this app.

        Juju creates a ClusterIP service named after the application, which load-balances
        across all ready pods. This is the address that must be advertised to remote charms,
        so that telemetry is distributed over the units instead of being duplicated to each
        of them (or pinned to the leader).
        """
        return f"{self.app.name}.{self.model.name}.svc.cluster.local"

    @property
    def _joined_units(self) -> int:
        """Return how many units of this application are currently in the peer relation.

        Deliberately not ``self.app.planned_units()``: that shells out to ``goal-state``,
        which hard-fails for every hook in the model once an unclean cross-model teardown
        leaves a dangling SAAS reference behind, taking this charm to error state
        (https://github.com/juju/juju/issues/23212). Counting the peers avoids the hook
        command altogether.
        """
        peers = self.model.get_relation("peers")
        return len(peers.units) + 1 if peers else 1

    def internal_host(self, container: Container) -> str:
        """Return the in-cluster address that remote charms should use to reach this app.

        This is the Kubernetes Service FQDN, so that traffic is load-balanced across units
        instead of being duplicated to every unit or pinned to the leader.

        Any unit may terminate a connection made to the Service, so a TLS-enabled unit can only
        be addressed that way once its certificate lists the Service name as a SAN. Until the CA
        issues that certificate we keep advertising this pod's FQDN, and switch over on the
        reconcile that follows its arrival. Without TLS there is no name to verify, so there is
        nothing to wait for.
        """
        if not integrations.is_tls_ready(container):
            return self.service_fqdn
        return (
            self.service_fqdn
            if self.service_fqdn in integrations.server_cert_sans_dns(container)
            else self.unit_fqdn
        )

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

        if JujuContext.from_environ().hook_name == "config-changed" and self.config.get("cpu"):
            warnings.warn(
                "The 'cpu' config option is deprecated and has no effect; "
                "use Juju constraints instead, e.g. `juju deploy --constraints cpu-power=500`.",
                DeprecationWarning,
                stacklevel=1,
            )

        insecure_skip_verify = cast(bool, self.config.get("tls_insecure_skip_verify"))
        integrations.cleanup(self.charm_dir.absolute())

        # Service mesh integration
        integrations.setup_service_mesh(self)

        # Integrate with TLS relations
        receive_ca_certs_hash = integrations.receive_ca_cert(
            self,
            recv_ca_cert_folder_path=ContainerPath(RECV_CA_CERT_FOLDER_PATH, container=container),
        )
        server_cert_hash = integrations.receive_server_cert(
            self,
            service_fqdn=self.service_fqdn,
            server_cert_path=ContainerPath(SERVER_CERT_PATH, container=container),
            private_key_path=ContainerPath(SERVER_CERT_PRIVATE_KEY_PATH, container=container),
            root_ca_cert_path=ContainerPath(SERVER_CA_CERT_PATH, container=container),
        )
        # Refresh system certs
        # This must be run after receive_ca_cert and/or receive_server_cert because they update
        # certs in the /usr/local/share/ca-certificates directory
        trust_hash = sha256(receive_ca_certs_hash + server_cert_hash)
        trust_restart_pending = refresh_certs(container, trust_hash)

        # Ingress integration and address manager
        # NOTE: executed after the TLS integrations. Traefik verifies the hostname of its
        # backend, so it must be given an address the served certificate is actually valid for.
        internal_host = self.internal_host(container)
        traefik_ingress = integrations.setup_traefik_ingress(
            self, internal_host, integrations.is_tls_ready(container)
        )
        istio_ingress = integrations.setup_istio_ingress(self)
        otelcol_address = charm_address(container, traefik_ingress, istio_ingress, internal_host)
        match otelcol_address:
            case integrations.MultipleIngressesConfigured():
                self.unit.status = BlockedStatus(otelcol_address.message)
                return

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
        topology = JujuTopology.from_charm(self)
        topology_labels = {
            "juju_charm": topology.charm_name,
            "juju_model": topology.model,
            "juju_model_uuid": topology.model_uuid,
            "juju_application": topology.application,
            "juju_unit": topology.unit,
        }
        config_manager = ConfigManager(
            global_scrape_interval=global_configs["global_scrape_interval"],
            global_scrape_timeout=global_configs["global_scrape_timeout"],
            receiver_tls=integrations.is_tls_ready(container),
            insecure_skip_verify=cast(bool, self.config.get("tls_insecure_skip_verify")),
            queue_size=cast(int, self.config.get("queue_size")),
            max_elapsed_time_min=cast(int, self.config.get("max_elapsed_time_min")),
            remote_write_num_consumers=cast(int, self.config.get("remote_write_num_consumers")),
            unit_name=self.unit.name,
            self_telemetry_host=self.unit_fqdn,
            topology_labels=topology_labels,
        )

        feature_gates: List[str] = []

        # OTLP setup
        traefik_ingress = integrations.traefik_ingress_ready(traefik_ingress)
        otlp_provider = integrations.receive_otlp(self, otelcol_address, traefik_ingress)
        otlp_endpoints = integrations.send_otlp(self)
        config_manager.add_otlp_forwarding(otlp_endpoints)

        # Logs setup
        integrations.receive_loki_logs(self, otelcol_address)
        loki_endpoints = integrations.send_loki_logs(self)
        if self._incoming_logs:
            config_manager.add_log_ingestion()
        config_manager.add_log_forwarding(loki_endpoints, insecure_skip_verify)

        # Metrics setup
        config_manager.add_self_scrape(
            identifier=topology.identifier,
            labels={
                "instance": f"{topology.identifier}_{topology.unit}",
                **topology_labels,
            },
        )
        # For now, the only incoming and outgoing metrics relations are remote-write/scrape.
        # Only the scrape jobs are needed for otelcol's own config; forwarding alert rules is
        # deferred to `stage_artifacts` and `forward_artifacts`.
        metrics_consumer_jobs = integrations.scrape_metrics(self)
        # Write CA certificates to disk and update job configurations
        self._ensure_certs_dir(container)
        cert_paths = self._write_tls_certificates_to_disk(metrics_consumer_jobs, container)
        metrics_consumer_jobs = config_manager.update_jobs_with_cert_paths(
            metrics_consumer_jobs, cert_paths
        )
        config_manager.add_prometheus_scrape_jobs(metrics_consumer_jobs)
        remote_write_endpoints = integrations.send_remote_write(self)
        config_manager.add_remote_write(remote_write_endpoints)

        # External-config setup
        self.external_configs, self.external_secret_files = integrations.receive_external_configs(
            self
        )
        self._write_secrets_to_disk(container, self.external_secret_files)
        self._configure_external_configs(config_manager)

        # Profiling setup
        if self._incoming_profiles:
            config_manager.add_profile_ingestion()
            integrations.receive_profiles(self, otelcol_address)
        profiling_endpoints = integrations.send_profiles(self)
        if profiling_endpoints:
            config_manager.add_profile_forwarding(profiling_endpoints)
        if self._incoming_profiles or integrations.send_profiles(self):
            feature_gates.append("service.profilesSupport")
        profiles_enabled = bool(self._incoming_profiles or profiling_endpoints)
        if profiles_enabled:
            feature_gates = "service.profilesSupport"

        # Tracing setup
        requested_tracing_protocols = integrations.receive_traces(self, otelcol_address)
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
        for idx, endpoint in enumerate(integrations.send_traces(self)):
            config_manager.add_traces_forwarding(endpoint, identifier=str(idx))
        integrations.send_charm_traces(self)

        # GrafanaCloudIntegrator setup
        cloud_integrator_data = integrations.cloud_integrator(self)
        config_manager.add_cloud_integrator(
            username=cloud_integrator_data.username,
            password=cloud_integrator_data.password,
            prometheus_url=cloud_integrator_data.prometheus_url,
            loki_url=cloud_integrator_data.loki_url,
            tempo_url=cloud_integrator_data.tempo_url,
        )
        if cast(int, self.config.get("remote_write_num_consumers")) > 1:
            feature_gates.append(
                "exporter.prometheusremotewritexporter.EnableMultipleWorkers"
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

        # Add the default memory limiter, unless the processors config option provides one
        available_memory_mib, memory_problem = self._available_memory_mib(container)
        if available_memory_mib is not None:
            config_manager.add_default_memory_limiter(
                available_memory_mib, profiles=profiles_enabled
            )

        # Push the config and deploy/update
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

        if self._has_server_cert_relation and not integrations.is_tls_ready(container):
            # A tls relation to a CA was formed, but we didn't get the cert yet.
            container.stop(SERVICE_NAME)
            self.unit.status = WaitingStatus("CSR sent; otelcol down while waiting for a cert")
        else:
            # The service is (re)started here, as soon as the config is ready. Forwarding alert
            # rules and dashboards (below) only updates relation data, which does not affect the
            # running service, so it must not delay the restart: with hundreds of relations, that
            # processing can take long enough to look like an outage.
            replan_with_trust_store(container, trust_hash, trust_restart_pending)
            self.unit.status = ActiveStatus()

        self.stage_artifacts(otlp_provider)
        self.forward_artifacts(otlp_provider)

        # Scaling status
        # Traffic is normally addressed to the Kubernetes Service, which load-balances over all
        # units. The exception is a TLS deployment whose certificate does not list the Service
        # name yet: until the CA issues the widened certificate every sender, ingressed or not,
        # is pinned to this one pod.
        if self._joined_units > 1 and internal_host != self.service_fqdn:
            self.unit.status = WaitingStatus(
                "Waiting for a certificate valid for the Kubernetes Service name"
            )
            logger.warning(
                "The server certificate does not list %s as a SAN, so this pod's address is "
                "advertised instead and traffic is not distributed across units. This resolves "
                "itself once the CA issues a certificate for the Kubernetes Service name.",
                self.service_fqdn,
            )

        # Invalid memory config, or undetectable memory
        if memory_problem:
            self.unit.status = BlockedStatus(memory_problem)

        # Mandatory relation pairs
        missing_relations = _get_missing_mandatory_relations(self)
        if missing_relations:
            self.unit.status = BlockedStatus(missing_relations)

        # Cyclic OTLP relations
        if integrations.cyclic_otlp_relations_exist(self):
            self.unit.status = BlockedStatus("cyclic OTLP relations exist")

        # Invalid alert rules
        if self._has_invalid_prometheus_alerts():
            self.unit.status = BlockedStatus("Invalid Prometheus alerts. See debug-log")

        # Invalid loki alert rules
        if self._has_invalid_loki_alerts():
            self.unit.status = BlockedStatus("Invalid Loki alerts. See debug-log")

        # Invalid scrape jobs
        if self._has_invalid_scrape_job():
            self.unit.status = BlockedStatus("Invalid scrape jobs. See debug-log")

        # Invalid OTLP alert rules (rejected by the remote `send-otlp` provider)
        if self._has_invalid_otlp_rules():
            self.unit.status = BlockedStatus("Invalid OTLP alert rules. See debug-log")

        # Workload version
        self.unit.set_workload_version(self._otelcol_version or "")

    def stage_artifacts(self, otlp_provider: integrations.OtlpProvider) -> None:
        """Stage alert rules and dashboards on disk after cleanup and before forwarding.

        This does not affect otelcol's own config, so it is
        deliberately run after the workload has already been (re)started in `_reconcile`.
        Its cost is linearly proportional to the number of relations, which can be large,
        and must not delay the restart of the service.
        """
        # See `stage_received_otlp_rules` for the ordering contract it depends on.
        # Ref: https://github.com/canonical/opentelemetry-collector-operator/issues/297
        integrations.stage_received_otlp_rules(self, otlp_provider)
        integrations.stage_loki_alert_rules(self)
        integrations.stage_metrics_alert_rules(self)
        integrations.stage_dashboards(self)

    def forward_artifacts(self, otlp_provider: integrations.OtlpProvider) -> None:
        """Publish alert rules and dashboards after `stage_artifacts` has populated disk."""
        integrations.forward_send_loki_logs_alerts(self)
        integrations.forward_send_remote_write_alerts(self)
        integrations.forward_otlp_rules(self, otlp_provider)
        integrations.forward_dashboards(self)

    def _pebble_layer(self, environment: Dict, feature_gates: List[str]) -> Layer:
        """Construct the Pebble layer configuration.

        Args:
            environment: Dictionary containing environment variables to be passed to the Pebble layer.
            feature_gates: Feature gates that should be enabled by otelcol, if any..

        Returns:
            Layer: A Pebble Layer object containing the service configuration.
        """
        otelcol_args = [f"--config={CONFIG_PATH}"]
        if feature_gates:
            otelcol_args.append(f"--feature-gates={','.join(feature_gates)}")

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
        directory.mkdir(parents=True, exist_ok=True)

    def _write_tls_certificates_to_disk(
        self, scrape_jobs: List[Dict], container: Container
    ) -> Dict[str, Dict[str, str]]:
        cert_paths = {}

        if not container.can_connect():
            logger.warning("Container not accessible, skipping certificate processing")
            return cert_paths

        # Prometheus accepts both the inline (`ca`) and the file (`ca_file`) spelling
        specs = (
            ("ca", ("ca_file", "ca"), self._validate_cert, 0o644),
            ("key", ("key_file", "key"), self._validate_private_key, 0o600),
            ("cert", ("cert_file", "cert"), self._validate_cert, 0o644),
        )

        for job in scrape_jobs:
            tls_config = job.get("tls_config", {})
            job_name = job.get("job_name", "default")
            safe_job_name = job_name.replace("/", "_").replace(" ", "_").replace("-", "_")
            job_cert_paths = {}

            for kind, tls_keys, validate, permissions in specs:
                content = next((tls_config[key] for key in tls_keys if tls_config.get(key)), None)
                if not content or "-----BEGIN" not in content:
                    continue
                if not validate(content):
                    logger.warning(
                        f"Ignoring malformed PEM {kind} for job '{job_name}'; "
                        "it is passed through to the workload config as-is"
                    )
                    continue
                path = f"{CERTS_DIR}otel_{safe_job_name}_{kind}.pem"
                container.push(path, content, permissions=permissions)
                job_cert_paths[kind] = path

            if job_cert_paths:
                cert_paths[job_name] = job_cert_paths

        return cert_paths

    def _write_secrets_to_disk(self, container: Container, secret_files: Dict[str, str]) -> None:
        if not container.can_connect():
            logger.warning("Container not accessible, cannot write secrets to disk")
            return

        if not secret_files:
            container.remove_path(EXTERNAL_CONFIG_SECRETS_DIR, recursive=True)
            return

        directory = ContainerPath(EXTERNAL_CONFIG_SECRETS_DIR, container=container)
        directory.mkdir(parents=True, exist_ok=True)
        for filepath, secret in secret_files.items():
            filepath = ContainerPath(filepath, container=container)
            filepath.write_text(secret, mode=0o644)
            logger.debug("secret written to %s", filepath)

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

    def _has_invalid_prometheus_alerts(self) -> bool:
        """Check if any metrics-endpoint relation reported invalid alert rules."""
        return self.metrics_consumer.has_invalid_alert_rules()

    def _has_invalid_loki_alerts(self) -> bool:
        """Check if any receive-loki-logs relation reported invalid alert rules."""
        return self.loki_provider.has_invalid_alert_rules()

    def _has_invalid_scrape_job(self) -> bool:
        """Check if any metrics-endpoint relation reported invalid scrape jobs."""
        return self.metrics_consumer.has_invalid_scrape_jobs()

    def _has_invalid_otlp_rules(self) -> bool:
        """Check if any send-otlp relation reported invalid alert rules."""
        return integrations.has_invalid_otlp_rules(self)

    def _available_memory_mib(self, container: Container) -> Tuple[Optional[int], Optional[str]]:
        """Return the memory available to otelcol in MiB, and a blocked status message, if any.

        The memory is None if it cannot be determined, in which case the message says why.

        The memory config option takes precedence over the memory detected in the container, but
        it is capped by it: otelcol cannot use more than its container has, so a limit above that
        would never trigger.
        """
        try:
            detected = container_memory_mib(container)
        except MemoryDetectionError as e:
            logger.error("Cannot detect the memory available to otelcol: %s", e)
            detected = None

        memory = cast(Optional[str], self.config.get("memory"))
        if not memory:
            if detected is None:
                return None, "Cannot detect the memory of otelcol: set the memory config option"
            return detected, None

        try:
            configured = quantity_to_mib(memory)
        except ValueError as e:
            logger.warning("Invalid 'memory' config option: %s", e)
            if detected is None:
                return None, "Invalid memory config value and cannot detect memory, see debug-log"
            return detected, "Invalid memory config value: using the detected memory instead"

        if detected is not None and configured > detected:
            logger.warning(
                "The 'memory' config option (%s MiB) is more than the memory available to the "
                "workload container (%s MiB), which is used instead.",
                configured,
                detected,
            )
            return detected, None
        return configured, None

    def _validate_cert(self, cert: str) -> bool:
        pem_pattern = r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
        return bool(re.search(pem_pattern, cert, re.DOTALL))

    @staticmethod
    def _validate_private_key(key: str) -> bool:
        pem_pattern = r"-----BEGIN( .*)? PRIVATE KEY-----(.*?)-----END( .*)? PRIVATE KEY-----"
        return bool(re.search(pem_pattern, key, re.DOTALL))


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
