#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import json
import logging
import socket
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, cast, get_args
from constants import (
    DASHBOARDS_DEST_PATH,
    DASHBOARDS_SRC_PATH,
    RECV_CA_CERT_FOLDER_PATH,
    CONFIG_PATH,
    METRICS_RULES_SRC_PATH,
    METRICS_RULES_DEST_PATH,
    LOKI_RULES_SRC_PATH,
    LOKI_RULES_DEST_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
    SERVICE_NAME,
)
import yaml
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LokiPushApiConsumer, LokiPushApiProvider
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointConsumer,
)
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
)
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferRequires,
)
from charms.grafana_cloud_integrator.v0.cloud_config_requirer import (
    GrafanaCloudConfigRequirer,
)
from charms.tempo_coordinator_k8s.v0.tracing import (
    ReceiverProtocol,
    TracingEndpointProvider,
    TracingEndpointRequirer,
    TransportProtocolType,
    receiver_protocol_to_transport_protocol,
)
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    Mode,
    TLSCertificatesRequiresV4,
)
from cosl import JujuTopology, LZMABase64
from ops import CharmBase, main, Container
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus, Relation
from ops.pebble import Layer

from config_builder import Component, Port, sha256
from config_manager import ConfigManager

logger = logging.getLogger(__name__)


def aggregate_alerts(alerts: Dict, src_path: Path, dest_path: Path):
    """Aggregate the alerts in src_path with the ones passed to the function.

    Args:
        alerts: Dictionary of alerts to aggregate with the ones present in src_path
        src_path: Path to some already-existing alerts
        dest_path: Path to the folder where both alert sources will be aggregated
    """
    if os.path.exists(dest_path):
        shutil.rmtree(dest_path)
    shutil.copytree(src_path, dest_path)
    for topology_identifier, rule in alerts.items():
        rule_file = Path(dest_path) / f"juju_{topology_identifier}.rules"
        rule_file.write_text(yaml.safe_dump(rule))
        logger.debug(f"updated alert rules file {rule_file.as_posix()}")


def get_dashboards(relations: List[Relation]) -> List[Dict[str, Any]]:
    """Returns a deduplicated list of all dashboards received by this otelcol."""
    aggregate = {}
    for rel in relations:
        dashboards = json.loads(rel.data[rel.app].get("dashboards", "{}"))  # type: ignore
        if "templates" not in dashboards:
            continue
        for template in dashboards["templates"]:
            content = json.loads(
                LZMABase64.decompress(dashboards["templates"][template].get("content"))
            )
            entry = {
                "charm": dashboards["templates"][template].get("charm", "charm_name"),
                "relation_id": rel.id,
                "title": template,
                "content": content,
            }
            aggregate[template] = entry

    return list(aggregate.values())


def is_server_cert_on_disk(container: Container) -> bool:
    """Return True if the server cert and private key are present in the workload container."""
    return container.exists(path=SERVER_CERT_PATH) and container.exists(
        path=SERVER_CERT_PRIVATE_KEY_PATH
    )


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    _container_name = "otelcol"

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container(self._container_name).can_connect():
            self.unit.status = MaintenanceStatus("Waiting for otelcol to start")
            return

        self.topology = JujuTopology.from_charm(self)

        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm.

        In order to trigger a restart when needed, the changes that require one
        are tracked via environment variables in the Pebble layer. A hash of
        the configuration is put in the layer so that `.replan()` will trigger
        a restart on changes.
        A similar approach is used for server certificates.

        With this pattern, we do not hold instances as attributes. When using events-based
        libraries, these instances will be garbage collected:
        > Reference to ops.Object at path OpenTelemetryCollectorK8sCharm/INSTANCE has been
        > garbage collected between when the charm was initialised and when the event was emitted.
        """
        container = self.unit.get_container(self._container_name)
        charm_root = self.charm_dir.absolute()
        forward_alert_rules = cast(bool, self.config.get("forward_alert_rules"))
        insecure_skip_verify = cast(bool, self.config.get("tls_insecure_skip_verify"))
        pebble_extra_env = {}

        # Integrate with TLS relations
        receive_ca_certs_hash = self.reconcile_receive_ca_cert(container)
        pebble_extra_env["RECEIVE_CA_CERT"] = receive_ca_certs_hash

        server_cert_hash = self.reconcile_server_cert(container)
        pebble_extra_env["SERVER_CERT"] = server_cert_hash

        self.config_manager = ConfigManager(
            receiver_tls=is_server_cert_on_disk(container),
            insecure_skip_verify=cast(bool, self.config.get("tls_insecure_skip_verify")),
        )

        # Dashboards setup
        self.forward_dashboards()

        # Logs setup
        loki_provider = LokiPushApiProvider(
            self,
            relation_name="receive-loki-logs",
            port=Port.loki_http,
            scheme="https" if is_server_cert_on_disk(container) else "http",
        )
        loki_consumer = LokiPushApiConsumer(
            self,
            relation_name="send-loki-logs",
            alert_rules_path=LOKI_RULES_DEST_PATH,
            forward_alert_rules=forward_alert_rules,
        )
        aggregate_alerts(
            alerts=loki_provider.alerts if forward_alert_rules else {},
            src_path=charm_root.joinpath(*LOKI_RULES_SRC_PATH.split("/")),
            dest_path=charm_root.joinpath(*LOKI_RULES_DEST_PATH.split("/")),
        )
        loki_consumer.reload_alerts()
        # For now, the only incoming and outgoing log relations are loki push api
        if self._incoming_logs:
            self.config_manager.add_log_ingestion()
        self.config_manager.add_log_forwarding(loki_consumer.loki_endpoints, insecure_skip_verify)

        # Metrics setup
        metrics_consumer = MetricsEndpointConsumer(self)
        aggregate_alerts(
            alerts=metrics_consumer.alerts if forward_alert_rules else {},
            src_path=charm_root.joinpath(*METRICS_RULES_SRC_PATH.split("/")),
            dest_path=charm_root.joinpath(*METRICS_RULES_DEST_PATH.split("/")),
        )
        self.config_manager.add_self_scrape(
            identifier=self.topology.identifier,
            labels={
                "instance": f"{self.topology.identifier}_{self.topology.unit}",
                "juju_charm": self.topology.charm_name,
                "juju_model": self.topology.model,
                "juju_model_uuid": self.topology.model_uuid,
                "juju_application": self.topology.application,
                "juju_unit": self.topology.unit,
            },
        )
        # For now, the only incoming and outgoing metrics relations are remote-write/scrape
        if self._incoming_metrics:
            self.config_manager.add_prometheus_scrape_jobs(metrics_consumer.jobs())
        remote_write = PrometheusRemoteWriteConsumer(
            self, alert_rules_path=METRICS_RULES_DEST_PATH
        )
        # TODO: add alerts from remote write
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277
        remote_write.reload_alerts()
        self.config_manager.add_remote_write(remote_write.endpoints)

        # Tracing setup
        # Enable traces ingestion with TracingEndpointProvider, i.e. configure the receivers
        tracing_provider = TracingEndpointProvider(self, relation_name="receive-traces")
        requested_tracing_protocols = set(tracing_provider.requested_protocols()).union(
            {
                receiver
                for receiver in get_args(ReceiverProtocol)
                if self.config.get(f"always_enable_{receiver}")
            }
        )
        # Send tracing receivers over relation data to charms sending traces to otel collector
        if self.unit.is_leader():
            tracing_provider.publish_receivers(
                tuple(
                    (
                        protocol,
                        self._get_tracing_receiver_url(
                            protocol=protocol,
                            tls_enabled=is_server_cert_on_disk(container),
                        ),
                    )
                    for protocol in requested_tracing_protocols
                )
            )
        self.config_manager.add_traces_ingestion(requested_tracing_protocols)
        # Add default processors to traces
        self.config_manager.add_traces_processing(
            sampling_rate_charm=cast(bool, self.config.get("tracing_sampling_rate_charm")),
            sampling_rate_workload=cast(bool, self.config.get("tracing_sampling_rate_workload")),
            sampling_rate_error=cast(bool, self.config.get("tracing_sampling_rate_error")),
        )
        # Enable pushing traces to a backend (i.e. Tempo) with TracingEndpointRequirer, i.e. configure the exporters
        tracing_requirer = TracingEndpointRequirer(
            self,
            relation_name="send-traces",
            protocols=[
                "otlp_http",  # for charm traces
                "otlp_grpc",  # for forwarding workload traces
            ],
        )
        if tracing_requirer.is_ready():
            if tracing_otlp_http_endpoint := tracing_requirer.get_endpoint("otlp_http"):
                self.config_manager.add_traces_forwarding(tracing_otlp_http_endpoint)

        # Enable forwarding telemetry with GrafanaCloudIntegrator
        cloud_integrator = GrafanaCloudConfigRequirer(self, relation_name="cloud-config")
        # We're intentionally not getting the CA cert from Grafana Cloud Integrator;
        # we decided that we should only get certs from receive-ca-cert.
        username, password = (
            (cloud_integrator.credentials.username, cloud_integrator.credentials.password)
            if cloud_integrator.credentials
            else (None, None)
        )
        self.config_manager.add_cloud_integrator(
            username=username,
            password=password,
            prometheus_url=cloud_integrator.prometheus_url
            if cloud_integrator.prometheus_ready
            else None,
            loki_url=cloud_integrator.loki_url if cloud_integrator.loki_ready else None,
            tempo_url=cloud_integrator.tempo_url if cloud_integrator.tempo_ready else None,
        )

        # Add custom processors from Juju config
        self._add_custom_processors()

        # Push the config and Push the config and deploy/update
        container.push(CONFIG_PATH, self.config_manager.config.build(), make_dirs=True)
        pebble_extra_env["OTELCOL_CONFIG"] = self.config_manager.config.hash

        container.add_layer(
            self._container_name, self._pebble_layer(environment=pebble_extra_env), combine=True
        )
        # TODO: Conditionally open ports based on the otelcol config file rather than opening all ports
        self.unit.set_ports(*[port.value for port in Port])

        if bool(self.model.relations.get("receive-server-cert")) and not is_server_cert_on_disk(
            container
        ):
            # A tls relation to a CA was formed, but we didn't get the cert yet.
            container.stop(SERVICE_NAME)
            self.unit.status = WaitingStatus("Waiting for cert")
        else:
            container.replan()
            self.unit.status = ActiveStatus()

    def _pebble_layer(self, environment: Dict) -> Layer:
        """Construct the Pebble layer information.

        Args:
            environment: A dictionary to be passed as environment variables to the Pebble layer.
        """
        layer = Layer(
            {
                "summary": "opentelemetry-collector-k8s layer",
                "description": "opentelemetry-collector-k8s layer",
                "services": {
                    SERVICE_NAME: {
                        "override": "replace",
                        "summary": "opentelemetry-collector-k8s service",
                        "command": f"/usr/bin/otelcol --config={CONFIG_PATH}",
                        "startup": "enabled",
                        "environment": {
                            "https_proxy": os.environ.get("JUJU_CHARM_HTTPS_PROXY", ""),
                            "http_proxy": os.environ.get("JUJU_CHARM_HTTP_PROXY", ""),
                            "no_proxy": os.environ.get("JUJU_CHARM_NO_PROXY", ""),
                            **environment,
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
                # TODO If we render TLS config for the extensions::health_check, switch to https
                "http": {"url": f"http://localhost:{Port.health}/health"},
            },
            "valid-config": {
                "override": "replace",
                "level": "alive",
                "exec": {"command": f"otelcol validate --config={CONFIG_PATH}"},
            },
        }
        return checks

    @property
    def _incoming_metrics(self) -> bool:
        return any(self.model.relations.get("metrics-endpoint", []))

    @property
    def _incoming_logs(self) -> bool:
        return any(self.model.relations.get("receive-loki-logs", []))

    @property
    def _outgoing_metrics(self) -> bool:
        return any(self.model.relations.get("send-remote-write", [])) or any(
            self.model.relations.get("cloud-config", [])
        )

    @property
    def _outgoing_logs(self) -> bool:
        return any(self.model.relations.get("send-loki-logs", [])) or any(
            self.model.relations.get("cloud-config", [])
        )

    def _add_custom_processors(self):
        """Add custom processors from Juju config."""
        if processors_raw := cast(str, self.config.get("processors")):
            for processor_name, processor_config in yaml.safe_load(processors_raw).items():
                self.config_manager.config.add_component(
                    component=Component.processor,
                    name=processor_name,
                    config=processor_config,
                    pipelines=["metrics", "logs", "traces"],
                )

    def reconcile_server_cert(self, container: Container) -> str:
        """Reconcile the certificate and private key for the charm from relation data.

        The certificate and key are obtained via the tls_certificates(v4) library,
        and pushed to the workload container.

        Returns:
            Hash of server cert and private key, to be used as reload trigger if it changed.
        """
        # Common name length must be >= 1 and <= 64, so fqdn is too long.
        common_name = self.unit.name.replace("/", "-")
        domain = socket.getfqdn()
        csr_attrs = CertificateRequestAttributes(
            common_name=common_name, sans_dns=frozenset({domain})
        )
        certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name="receive-server-cert",
            certificate_requests=[csr_attrs],
            mode=Mode.UNIT,
        )

        # Request a certificate
        # TLSCertificatesRequiresV4 is garbage collected, see the `_reconcile`` docstring for more
        # details. So we need to call _configure() ourselves:
        certificates._configure(None)  # type: ignore[reportArgumentType]

        provider_certificate, private_key = certificates.get_assigned_certificate(
            certificate_request=csr_attrs
        )
        # If there no certificate or private key coming from relation data, cleanup
        # the existing ones. This typically happens after a "revoked" or "renewal"
        # event.
        if not provider_certificate or not private_key:
            if not provider_certificate:
                logger.debug("TLS disabled: Certificate is not available")
            if not private_key:
                logger.debug("TLS disabled: Private key is not available")

            container.remove_path(SERVER_CERT_PATH, recursive=True)
            container.remove_path(SERVER_CERT_PRIVATE_KEY_PATH, recursive=True)
            return sha256("")

        # Push the certificate and key to disk
        container.push(
            path=SERVER_CERT_PATH,
            source=str(provider_certificate.certificate),
            make_dirs=True,
        )
        container.push(
            path=f"{SERVER_CERT_PRIVATE_KEY_PATH}",
            source=str(private_key),
            make_dirs=True,
        )
        logger.info("Certificate and private key have been pushed to workload container")

        return sha256(str(provider_certificate.certificate) + str(private_key))

    def reconcile_receive_ca_cert(self, container: Container) -> str:
        """Reconcile the certificates from the `receive-ca-cert` relation.

        This function saves the certificates to disk, and runs
        `update-ca-certificates` to trust them.

        Returns:
            Hash of the certificates to trust, to be used as reload trigger when changed.
        """
        # Obtain certs from relation data
        certificate_transfer = CertificateTransferRequires(self, "receive-ca-cert")
        ca_certs = certificate_transfer.get_all_certificates()

        # Clean-up previously existing certs
        container.remove_path(RECV_CA_CERT_FOLDER_PATH, recursive=True)

        # Write current certs
        for i, cert in enumerate(ca_certs):
            container.push(RECV_CA_CERT_FOLDER_PATH + f"/{i}.crt", cert, make_dirs=True)

        # Refresh system certs
        container.exec(["update-ca-certificates", "--fresh"]).wait()

        # A hot-reload doesn't pick up new system certs - need to restart the service
        return sha256(yaml.safe_dump(ca_certs))

    def forward_dashboards(self):
        """Instantiate the GrafanaDashboardProvider and update the dashboards in the relation databag.

        First, dashboards from relations (including those bundled with Otelcol) and save them to disk.
        Then, update the relation databag with these dashboards for Grafana.
        """
        src_path = self.charm_dir.absolute().joinpath(*DASHBOARDS_SRC_PATH.split("/"))
        dest_path = self.charm_dir.absolute().joinpath(*DASHBOARDS_DEST_PATH.split("/"))

        # The leader copies dashboards from relations and save them to disk."""
        if not self.unit.is_leader():
            return
        shutil.rmtree(dest_path, ignore_errors=True)
        shutil.copytree(src_path, dest_path)
        for dash in get_dashboards(self.model.relations["grafana-dashboards-consumer"]):
            # Build dashboard custom filename
            charm_name = dash.get("charm", "charm-name")
            rel_id = dash.get("relation_id", "rel_id")
            title = dash.get("title", "").replace(" ", "_").replace("/", "_").lower()
            filename = f"juju_{title}-{charm_name}-{rel_id}.json"
            with open(Path(dest_path, filename), mode="w", encoding="utf-8") as f:
                f.write(json.dumps(dash["content"]))
                logger.debug("updated dashboard file %s", f.name)

        # GrafanaDashboardProvider is garbage collected, see the `_reconcile`` docstring for more details
        grafana_dashboards_provider = GrafanaDashboardProvider(
            self,
            relation_name="grafana-dashboards-provider",
            dashboards_path=dest_path.as_posix(),
        )
        # Scan the built-in dashboards and update relations with changes
        grafana_dashboards_provider.reload_dashboards()

        # TODO: Do we need to implement dashboard status changed logic?
        #   This propagates Grafana's errors to the charm which provided the dashboard
        # grafana_dashboards_provider._reinitialize_dashboard_data(inject_dropdowns=False)

    def _get_tracing_receiver_url(self, protocol: ReceiverProtocol, tls_enabled: bool):
        """Build the endpoint for the tracing receiver based on the protocol and TLS.

        Args:
            protocol: The ReceiverProtocol of a certain receiver (e.g., 'otlp_grpc', 'zipkin').
            tls_enabled: Flag indicating whether the endpoint should use 'https' or not.
        """
        scheme = "http"
        if tls_enabled:
            scheme = "https"

        # The correct transport protocol is specified in the tracing library, and it's always
        # either http or grpc.
        # We assume the user of the receiver is in-model, since this charm doesn't have ingress.
        if receiver_protocol_to_transport_protocol[protocol] == TransportProtocolType.grpc:
            return f"{socket.getfqdn()}:{Port.otlp_grpc}"
        return f"{scheme}://{socket.getfqdn()}:{Port.otlp_http}"


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
