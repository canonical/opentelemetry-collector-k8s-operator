#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Kubernetes."""

import json
import logging
import socket
import os
import shutil
from collections import namedtuple
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, cast, get_args
from constants import (
    RECV_CA_CERT_FOLDER_PATH,
    CONFIG_PATH,
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
    Credentials,
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
    Certificate,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    TLSCertificatesRequiresV4,
)
from cosl import JujuTopology, LZMABase64
from ops import CharmBase, main, Container
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus, Relation
from ops.pebble import Layer

from config import PORTS, Config, sha256

logger = logging.getLogger(__name__)
PathMapping = namedtuple("PathMapping", ["src", "dest"])


def _aggregate_alerts(rules: Dict, rule_path_map: PathMapping, forward_alert_rules: bool):
    rules = rules if forward_alert_rules else {}
    if os.path.exists(rule_path_map.dest):
        shutil.rmtree(rule_path_map.dest)
    shutil.copytree(rule_path_map.src, rule_path_map.dest)
    for topology_identifier, rule in rules.items():
        rule_file = Path(rule_path_map.dest) / f"juju_{topology_identifier}.rules"
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


def forward_dashboards(charm: CharmBase):
    """Instantiate the GrafanaDashboardProvider and update the dashboards in the relation databag.

    First, dashboards from relations (including those bundled with Otelcol) and save them to disk.
    Then, update the relation databag with these dashboards for Grafana.
    """
    charm_root = charm.charm_dir.absolute()
    dashboard_paths = PathMapping(
        src=charm_root.joinpath(*"src/grafana_dashboards".split("/")),
        dest=charm_root.joinpath(*"grafana_dashboards".split("/")),
    )
    if not os.path.isdir(dashboard_paths.dest):
        shutil.copytree(dashboard_paths.src, dashboard_paths.dest, dirs_exist_ok=True)

    # The leader copies dashboards from relations and save them to disk."""
    if not charm.unit.is_leader():
        return
    shutil.rmtree(dashboard_paths.dest)
    shutil.copytree(dashboard_paths.src, dashboard_paths.dest)
    for dash in get_dashboards(charm.model.relations["grafana-dashboards-consumer"]):
        # Build dashboard custom filename
        charm_name = dash.get("charm", "charm-name")
        rel_id = dash.get("relation_id", "rel_id")
        title = dash.get("title", "").replace(" ", "_").replace("/", "_").lower()
        filename = f"juju_{title}-{charm_name}-{rel_id}.json"
        with open(Path(dashboard_paths.dest, filename), mode="w", encoding="utf-8") as f:
            f.write(json.dumps(dash["content"]))
            logger.debug("updated dashboard file %s", f.name)

    # GrafanaDashboardProvider is garbage collected, see the `_reconcile`` docstring for more details
    grafana_dashboards_provider = GrafanaDashboardProvider(
        charm,
        relation_name="grafana-dashboards-provider",
        dashboards_path=dashboard_paths.dest,
    )
    # Scan the built-in dashboards and update relations with changes
    grafana_dashboards_provider.reload_dashboards()

    # TODO: Do we need to implement dashboard status changed logic?
    #   This propagates Grafana's errors to the charm which provided the dashboard
    # grafana_dashboards_provider._reinitialize_dashboard_data(inject_dropdowns=False)


def receive_ca_certs(charm: CharmBase, container: Container) -> str:
    """Returns a 'pebble replan sentinel' (hash of all certs), for pebble to determine whether a replan is required."""
    # Obtain certs from relation data
    certificate_transfer = CertificateTransferRequires(charm, "receive-ca-cert")
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


def server_cert(charm: CharmBase, container: Container) -> str:
    """Write private key (from juju secret) and server cert (from relation data) to the workload container.

    Returns:
        Hash of server cert and private key, to be used as reload sentinel.
    """
    # Common name length must be >= 1 and <= 64, so fqdn is too long.
    common_name = charm.unit.name.replace("/", "-")
    domain = socket.getfqdn()
    csr_attrs = CertificateRequestAttributes(common_name=common_name, sans_dns=frozenset({domain}))
    certificates = TLSCertificatesRequiresV4(
        charm=charm,
        relationship_name="receive-server-cert",
        certificate_requests=[csr_attrs],
        mode=Mode.UNIT,
    )

    # TLSCertificatesRequiresV4 is garbage collected, see the `_reconcile`` docstring for more
    # details. So we need to call _configure() ourselves:
    certificates._configure(None)  # type: ignore[reportArgumentType]

    provider_certificate, private_key = certificates.get_assigned_certificate(
        certificate_request=csr_attrs
    )
    if not provider_certificate or not private_key:
        if not provider_certificate:
            logger.debug("TLS disabled: Certificate is not available")
        if not private_key:
            logger.debug("TLS disabled: Private key is not available")

        # Cleanup, in case this happens is after a "revoked" or "renewal" events.
        container.remove_path(SERVER_CERT_PATH, recursive=True)
        container.remove_path(SERVER_CERT_PRIVATE_KEY_PATH, recursive=True)
        return sha256("")

    existing_cert = (
        container.pull(path=SERVER_CERT_PATH).read()
        if container.exists(path=SERVER_CERT_PATH)
        else ""
    )
    if not existing_cert or provider_certificate.certificate != Certificate.from_string(
        existing_cert
    ):
        container.push(
            path=f"{SERVER_CERT_PATH}",
            source=str(provider_certificate.certificate),
            make_dirs=True,
        )
        logger.info("Pushed certificate pushed to workload")

    existing_key = (
        container.pull(path=SERVER_CERT_PRIVATE_KEY_PATH).read()
        if container.exists(path=SERVER_CERT_PRIVATE_KEY_PATH)
        else ""
    )
    if not existing_key or private_key != PrivateKey.from_string(existing_key):
        container.push(
            path=f"{SERVER_CERT_PRIVATE_KEY_PATH}",
            source=str(private_key),
            make_dirs=True,
        )
        logger.info("Pushed private key to workload")

    return sha256(str(private_key) + str(provider_certificate.certificate))


def is_server_cert_on_disk(container: Container) -> bool:
    """Return True if the server cert and private key are present in the workload container."""
    return container.exists(path=SERVER_CERT_PATH) and container.exists(
        path=SERVER_CERT_PRIVATE_KEY_PATH
    )


class OpenTelemetryCollectorK8sCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Kubernetes."""

    _container_name = "otelcol"
    _metrics_rules_src_path = "src/prometheus_alert_rules"
    _metrics_rules_dest_path = "prometheus_alert_rules"
    _loki_rules_src_path = "src/loki_alert_rules"
    _loki_rules_dest_path = "loki_alert_rules"

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.get_container(self._container_name).can_connect():
            self.unit.status = MaintenanceStatus("Waiting for otelcol to start")
            return

        self.topology = JujuTopology.from_charm(self)
        self.otel_config = Config.default_config()

        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm.

        With this pattern, we do not hold instances as attributes. When using events-based
        libraries, these instances will be garbage collected:
        > Reference to ops.Object at path OpenTelemetryCollectorK8sCharm/INSTANCE has been
        > garbage collected between when the charm was initialised and when the event was emitted.
        """
        container = self.unit.get_container(self._container_name)
        charm_root = self.charm_dir.absolute()
        replan_sentinel: str = ""
        forward_alert_rules = cast(bool, self.config["forward_alert_rules"])
        insecure_skip_verify = cast(bool, self.model.config.get("tls_insecure_skip_verify"))

        # TLS: receive-ca-cert
        replan_sentinel += receive_ca_certs(self, container)

        # TLS: server cert
        replan_sentinel += server_cert(self, container)
        if server_cert_on_disk := is_server_cert_on_disk(container):
            self.otel_config.enable_receiver_tls(SERVER_CERT_PATH, SERVER_CERT_PRIVATE_KEY_PATH)

        # TLS: insecure-skip-verify
        self.otel_config.set_exporter_insecure_skip_verify(
            cast(bool, self.model.config.get("tls_insecure_skip_verify"))
        )

        forward_dashboards(self)

        # Logs setup
        loki_rules_paths = PathMapping(
            src=charm_root.joinpath(*self._loki_rules_src_path.split("/")),
            dest=charm_root.joinpath(*self._loki_rules_dest_path.split("/")),
        )
        loki_provider = LokiPushApiProvider(
            self,
            relation_name="receive-loki-logs",
            port=PORTS.LOKI_HTTP,
            scheme="https" if is_server_cert_on_disk(container) else "http",
        )
        # LokiPushApiConsumer is garbage collected, see the `_reconcile`` docstring for more details
        loki_consumer = LokiPushApiConsumer(
            self,
            relation_name="send-loki-logs",
            alert_rules_path=loki_rules_paths.dest,
            forward_alert_rules=forward_alert_rules,
        )
        _aggregate_alerts(loki_provider.alerts, loki_rules_paths, forward_alert_rules)
        loki_consumer.reload_alerts()
        self._add_log_ingestion(insecure_skip_verify)
        self._add_log_forwarding(loki_consumer.loki_endpoints, insecure_skip_verify)

        # Metrics setup
        metrics_rules_paths = PathMapping(
            src=charm_root.joinpath(*self._metrics_rules_src_path.split("/")),
            dest=charm_root.joinpath(*self._metrics_rules_dest_path.split("/")),
        )
        # MetricsEndpointConsumer is garbage collected, see the `_reconcile`` docstring for more details
        metrics_consumer = MetricsEndpointConsumer(self)
        # Receive alert rules and scrape jobs
        _aggregate_alerts(metrics_consumer.alerts, metrics_rules_paths, forward_alert_rules)
        self._add_self_scrape(insecure_skip_verify)
        self.otel_config.add_prometheus_scrape(
            metrics_consumer.jobs(), self._incoming_metrics, insecure_skip_verify
        )
        # PrometheusRemoteWriteConsumer is garbage collected, see the `_reconcile`` docstring for more details
        remote_write = PrometheusRemoteWriteConsumer(
            self, alert_rules_path=metrics_rules_paths.dest
        )
        # Forward alert rules and scrape jobs to Prometheus
        remote_write.reload_alerts()
        self._add_remote_write(remote_write.endpoints, insecure_skip_verify)

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
        self._add_traces_ingestion(requested_tracing_protocols)
        # Add default processors to traces
        self._add_traces_processing()
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
            self._add_traces_forwarding(
                tracing_otlp_http_endpoint=tracing_requirer.get_endpoint("otlp_http")
            )

        # Enable forwarding telemetry with GrafanaCloudIntegrator
        cloud_integrator = GrafanaCloudConfigRequirer(self, relation_name="cloud-config")
        # We're intentionally not getting the CA cert from Grafana Cloud Integrator;
        # we decided that we should only get certs from receive-ca-cert.
        self._add_cloud_integrator(
            credentials=cloud_integrator.credentials,
            prometheus_url=cloud_integrator.prometheus_url
            if cloud_integrator.prometheus_ready
            else None,
            loki_url=cloud_integrator.loki_url if cloud_integrator.loki_ready else None,
            tempo_url=cloud_integrator.tempo_url if cloud_integrator.tempo_ready else None,
            insecure_skip_verify=insecure_skip_verify,
        )

        # Push the config and Push the config and deploy/update
        container.push(CONFIG_PATH, self.otel_config.yaml, make_dirs=True)
        replan_sentinel += self.otel_config.hash

        container.add_layer(
            self._container_name, self._pebble_layer(replan_sentinel), combine=True
        )
        # TODO Conditionally open ports based on the otelcol config file rather than opening all ports
        self.unit.set_ports(*self.otel_config.ports)

        if bool(self.model.relations.get("receive-server-cert")) and not server_cert_on_disk:
            # A tls relation to a CA was formed, but we didn't get the cert yet.
            container.stop(SERVICE_NAME)
            self.unit.status = WaitingStatus("Waiting for cert")
        else:
            container.replan()
            self.unit.status = ActiveStatus()

    def _pebble_layer(self, sentinel: str) -> Layer:
        """Construct the Pebble layer information.

        Args:
            sentinel: A value indicative of a change that should prompt a replan.
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
                            "_config_hash": sentinel,  # Restarts the service via pebble replan
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
                # TODO If we render TLS config for the extensions::health_check, switch to https
                "http": {"url": f"http://localhost:{PORTS.HEALTH}/health"},
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

    def _add_self_scrape(self, insecure_skip_verify: bool):
        """Configure self-monitoring scrape jobs."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver
        self.otel_config.add_receiver(
            "prometheus",
            {
                "config": {
                    "scrape_configs": [
                        {
                            # This job name is overwritten with "otelcol" when remote-writing
                            "job_name": f"juju_{self.topology.identifier}_self-monitoring",
                            "scrape_interval": "60s",
                            "static_configs": [
                                {
                                    "targets": [f"0.0.0.0:{PORTS.METRICS}"],
                                    "labels": {
                                        "instance": f"{self.topology.identifier}_{self.topology.unit}",
                                        "juju_charm": self.topology.charm_name,
                                        "juju_model": self.topology.model,
                                        "juju_model_uuid": self.topology.model_uuid,
                                        "juju_application": self.topology.application,
                                        "juju_unit": self.topology.unit,
                                    },
                                }
                            ],
                        }
                    ]
                }
            },
            pipelines=["metrics"],
        )

    def _add_remote_write(self, endpoints: List[Dict[str, str]], insecure_skip_verify: bool):
        """Configure forwarding alert rules to prometheus/mimir via remote-write."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/prometheusremotewriteexporter
        for idx, endpoint in enumerate(endpoints):
            self.otel_config.add_exporter(
                f"prometheusremotewrite/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                },
                pipelines=["metrics"],
            )

        # TODO Receive alert rules via remote write
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277

    def _add_log_ingestion(self, insecure_skip_verify: bool):
        """Configure receiving logs, allowing Promtail instances to specify the Otelcol as their lokiAddress."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/lokireceiver

        # For now, the only incoming and outgoing log relations are loki push api,
        # so we don't need to mix and match between them yet.
        if self._incoming_logs:
            self.otel_config.add_receiver(
                "loki",
                {
                    "protocols": {
                        "http": {
                            "endpoint": f"0.0.0.0:{PORTS.LOKI_HTTP}",
                        },
                    },
                    "use_incoming_timestamp": True,
                },
                pipelines=["logs"],
            )

    def _add_log_forwarding(self, endpoints: List[dict], insecure_skip_verify: bool):
        """Configure sending logs to Loki via the Loki push API endpoint.

        The LogRecord format is controlled with the `loki.format` hint.

        The Loki exporter converts OTLP resource and log attributes into Loki labels, which are indexed.
        Configuring hints (e.g. `loki.attribute.labels`) specifies which attributes should be placed as labels.
        The hints are themselves attributes and will be ignored when exporting to Loki.
        """
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.122.0/exporter/lokiexporter
        for idx, endpoint in enumerate(endpoints):
            self.otel_config.add_exporter(
                f"loki/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "default_labels_enabled": {"exporter": False, "job": True},
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                },
                pipelines=["logs"],
            )
        if self._outgoing_logs:
            self.otel_config.add_processor(
                "resource",
                {
                    "attributes": [
                        {
                            "action": "insert",
                            "key": "loki.format",
                            "value": "raw",  # logfmt, json, raw
                        },
                    ]
                },
                pipelines=["logs"],
            ).add_processor(
                "attributes",
                {
                    "actions": [
                        {
                            "action": "upsert",
                            "key": "loki.attribute.labels",
                            # These labels are set in `_scrape_configs` of the `v1.loki_push_api` lib
                            "value": "container, job, filename, juju_application, juju_charm, juju_model, juju_model_uuid, juju_unit",
                        },
                    ]
                },
                pipelines=["logs"],
            )

    def _add_traces_ingestion(self, requested_tracing_protocols: Set[ReceiverProtocol]):
        """Configure the tracing receivers for otel-collector to ingest traces.

        Args:
            requested_tracing_protocols: The tracing protocols for which to enable receivers.
        """
        # TODO: check with the team, do we keep this?
        # TODO: should we just add the otlp protocols always? probably yes
        if not requested_tracing_protocols:
            logger.warning("No tempo receivers enabled: otel-collector cannot ingest traces.")
            return

        if "zipkin" in requested_tracing_protocols:
            self.otel_config.add_receiver(
                name="zipkin",
                receiver_config={"endpoint": f"0.0.0.0:{PORTS.ZIPKIN}"},
                pipelines=["traces"],
            )
        if (
            "jaeger_grpc" in requested_tracing_protocols
            or "jaeger_thrift_http" in requested_tracing_protocols
        ):
            jaeger_config = {"protocols": {}}
            if "jaeger_grpc" in requested_tracing_protocols:
                jaeger_config["protocols"].update(
                    {"grpc": {"endpoint": f"0.0.0.0:{PORTS.JAEGER_GRPC}"}}
                )
            if "jaeger_thrift_http" in requested_tracing_protocols:
                jaeger_config["protocols"].update(
                    {"thrift_http": {"endpoint": f"0.0.0.0:{PORTS.JAEGER_THRIFT_HTTP}"}}
                )
            self.otel_config.add_receiver(
                name="jaeger", receiver_config=jaeger_config, pipelines=["traces"]
            )

    def _add_traces_processing(self):
        """Configure the processors for traces."""
        self.otel_config.add_processor(
            name="tail_sampling", processor_config=self._tracing_sampling, pipelines=["traces"]
        )

    def _add_traces_forwarding(
        self,
        tracing_otlp_http_endpoint: Optional[str],
    ):
        """Configure the tracing exporter for otel-collector to send traces to Tempo."""
        # This only supports one Tempo instance, otherwise we need to add exporters named tempo-x
        # Currently, the tracing relation has limit: 1.
        if tracing_otlp_http_endpoint:
            self.otel_config.add_exporter(
                name="otlphttp/tempo",
                exporter_config={"endpoint": tracing_otlp_http_endpoint},
                pipelines=["traces"],
            )

    def _add_cloud_integrator(
        self,
        credentials: Optional[Credentials],
        prometheus_url: Optional[str],
        loki_url: Optional[str],
        tempo_url: Optional[str],
        insecure_skip_verify: bool,
    ):
        """Configure forwarding telemetry to the endpoints provided by a cloud-integrator charm."""
        exporter_auth_config = {}
        if credentials:
            self.otel_config.add_extension(
                "basicauth/cloud-integrator",
                {
                    "client_auth": {
                        "username": credentials.username,
                        "password": credentials.password,
                    }
                },
            )
            exporter_auth_config = {"auth": {"authenticator": "basicauth/cloud-integrator"}}
        if prometheus_url:
            self.otel_config.add_exporter(
                "prometheusremotewrite/cloud-integrator",
                {
                    "endpoint": prometheus_url,
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                    **exporter_auth_config,
                },
                pipelines=["metrics"],
            )
        if loki_url:
            self.otel_config.add_exporter(
                "loki/cloud-integrator",
                {
                    "endpoint": loki_url,
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                    "default_labels_enabled": {"exporter": False, "job": True},
                    "headers": {"Content-Encoding": "snappy"},  # TODO: check if this is needed
                    **exporter_auth_config,
                },
                pipelines=["logs"],
            )
        if tempo_url:
            self.otel_config.add_exporter(
                name="otlphttp/cloud-integrator",
                exporter_config={
                    "endpoint": tempo_url,
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                    **exporter_auth_config,
                },
                pipelines=["traces"],
            )

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
            return f"{socket.getfqdn()}:{PORTS.OTLP_GRPC}"
        return f"{scheme}://{socket.getfqdn()}:{PORTS.OTLP_HTTP}"

    @property
    def _tracing_sampling(self) -> Dict[str, Any]:
        """The default configuration for the tail sampling processor used by tracing."""
        # policies, as defined by tail sampling processor definition:
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor
        # each of them is evaluated separately and processor decides whether to pass the trace through or not
        # see the description of tail sampling processor above for the full decision tree
        return {
            "policies": [
                {
                    "name": "error-traces-policy",
                    "type": "and",
                    "and": {
                        "and_sub_policy": [
                            {
                                "name": "trace-status-policy",
                                "type": "status_code",
                                "status_code": {"status_codes": ["ERROR"]},
                                # status_code processor is using span_status property of spans within a trace
                                # see https://opentelemetry.io/docs/concepts/signals/traces/#span-status for reference
                            },
                            {
                                "name": "probabilistic-policy",
                                "type": "probabilistic",
                                "probabilistic": {
                                    "sampling_percentage": self.config.get(
                                        "tracing_sample_rate_error"
                                    )
                                },
                            },
                        ]
                    },
                },
                {
                    "name": "charm-traces-policy",
                    "type": "and",
                    "and": {
                        "and_sub_policy": [
                            {
                                "name": "service-name-policy",
                                "type": "string_attribute",
                                "string_attribute": {
                                    "key": "service.name",
                                    "values": [".+-charm"],
                                    "enabled_regex_matching": True,
                                },
                            },
                            {
                                "name": "probabilistic-policy",
                                "type": "probabilistic",
                                "probabilistic": {
                                    "sampling_percentage": self.config.get(
                                        "tracing_sample_rate_charm"
                                    )
                                },
                            },
                        ]
                    },
                },
                {
                    "name": "workload-traces-policy",
                    "type": "and",
                    "and": {
                        "and_sub_policy": [
                            {
                                "name": "service-name-policy",
                                "type": "string_attribute",
                                "string_attribute": {
                                    "key": "service.name",
                                    "values": [".+-charm"],
                                    "enabled_regex_matching": True,
                                    "invert_match": True,
                                },
                            },
                            {
                                "name": "probabilistic-policy",
                                "type": "probabilistic",
                                "probabilistic": {
                                    "sampling_percentage": self.config.get(
                                        "tracing_sample_rate_workload"
                                    )
                                },
                            },
                        ]
                    },
                },
            ]
        }


if __name__ == "__main__":
    main(OpenTelemetryCollectorK8sCharm)
