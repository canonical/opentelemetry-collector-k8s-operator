"""Helper module to build the configuration for OpenTelemetry Collector."""

import hashlib
import logging
from typing import Any, Dict, List, Literal, Optional, Union
from enum import Enum, unique

import yaml

from constants import (
    INTERNAL_LOGS_FILTER_ID,
    INTERNAL_TELEMETRY_SERVICE_NAME,
    NON_LOOPING_EXPORTER_PREFIXES,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
)

logger = logging.getLogger(__name__)


def sha256(hashable: Union[str, bytes]) -> str:
    """Generate a SHA-256 hash of the input.

    This function provides a consistent, repeatable hash value for the input,
    unlike Python's built-in hash() which may vary between Python processes.

    Args:
        hashable: Input to be hashed. If a string, will be encoded to bytes.

    Returns:
        str: A hexadecimal string representing the SHA-256 hash of the input.
    """
    if isinstance(hashable, str):
        hashable = hashable.encode("utf-8")
    return hashlib.sha256(hashable).hexdigest()


# TODO: inherit enum.StrEnum when jammy is no longer supported.
# https://docs.python.org/3/library/enum.html#enum.StrEnum
@unique
class Port(int, Enum):
    """Ports used by the OpenTelemetry Collector."""

    loki_http = 3500
    """HTTP endpoint for Loki log ingestion."""
    otlp_grpc = 4317
    """gRPC endpoint for OTLP protocol"""
    otlp_http = 4318
    """HTTP endpoint for OTLP protocol"""
    metrics = 8888
    """Endpoint for Prometheus metrics scraping"""
    health = 13133
    """Health check endpoint"""
    # Tracing
    jaeger_grpc = 14250
    """gRPC endpoint for Jaeger protocol"""
    jaeger_thrift_http = 14268
    """HTTP endpoint for Jaeger Thrift protocol"""
    zipkin = 9411
    """HTTP endpoint for Zipkin protocol"""


@unique
class Component(str, Enum):
    """Pipeline components of the OpenTelemetry Collector configuration.

    These represent the different types of components that can be part of an
    OpenTelemetry Collector pipeline.

    See https://opentelemetry.io/docs/collector/configuration/#basics for more details.

    Attributes:
        receiver: Components that receive data in various formats (e.g., OTLP, Jaeger, Zipkin).
        processor: Components that process data between reception and export.
        exporter: Components that send data to external systems or services.
        connector: Components that connect pipelines together.

    The enum values correspond to the top-level keys in the collector's config file.
    """

    receiver = "receivers"
    processor = "processors"
    exporter = "exporters"
    connector = "connectors"


class ConfigBuilder:
    """Builder for OpenTelemetry Collector configuration.

    This class handles the assembly of components (receivers, processors, exporters) into a valid
    configuration that can be consumed by the Collector.
    """

    def __init__(
        self,
        unit_name: str,
        global_scrape_interval: str,
        global_scrape_timeout: str,
        receiver_tls: bool = False,
        exporter_skip_verify: bool = False,
        internal_host: str = "localhost",
        topology_labels: Optional[Dict[str, str]] = None,
    ):
        """Generate an empty OpenTelemetry collector config.

        Args:
            unit_name: the name of the unit
            global_scrape_interval: value for `scrape_interval` in all prometheus receivers
            global_scrape_timeout: value for `scrape_timeout` in all prometheus receivers
            receiver_tls: whether to inject TLS config in all receivers on build
            exporter_skip_verify: value for `insecure_skip_verify` in all exporters
            internal_host: the unit FQDN the OTLP receiver's server cert is valid for
            topology_labels: this collector's own deployment topology. Attached to the collector's
                internal telemetry so logs from multiple otelcol apps/units are distinguishable.
        """
        self._config = {
            "extensions": {},
            "receivers": {},
            "exporters": {},
            "connectors": {},
            "processors": {},
            "service": {
                "extensions": [],
                "pipelines": {},
                "telemetry": {},
            },
        }
        self._unit_name = unit_name
        self._topology_labels = dict(topology_labels or {})
        self._receiver_tls = receiver_tls
        self._exporter_skip_verify = exporter_skip_verify
        self._internal_host = internal_host
        self._scrape_interval = global_scrape_interval
        self._scrape_timeout = global_scrape_timeout

    def build(self) -> str:
        """Build the final configuration and return it as a YAML string.

        This method performs several important tasks:
        - Adds debug exporters to pipelines that don't have any exporters
        - Injects TLS configuration to all receivers if enabled
        - Configures TLS verification settings for all exporters

        Returns:
            str: A YAML string representing the complete configuration.
        """
        self._add_missing_nop_exporters()
        self._populate_loop_breaker_filter()
        if self._receiver_tls:
            self._add_tls_to_all_receivers()
        self._set_prometheus_receiver_global_timeout_and_interval(
            self._scrape_interval,
            self._scrape_timeout,
        )
        self._add_exporter_insecure_skip_verify(self._exporter_skip_verify)
        return yaml.safe_dump(self._config)

    def _populate_loop_breaker_filter(self):
        """Populate the internal-telemetry loop-breaker filter's drop conditions.

        The collector self-ingests its own internal logs into the `logs/<unit>` pipeline. Any
        exporter on ANY logs pipeline can recurse: its "Exporting failed" log is itself an internal
        log that re-enters the pipeline and is re-exported. To break the cycle we drop the logs
        emitted by exactly those exporter components for the LOGS signal, matched on
        `otelcol.component.id` AND `otelcol.signal`.

        We enumerate the exporters across EVERY logs pipeline dynamically (at build time, after all
        components and the fallback nop exporter have been added), not just the charm-managed
        `logs/<unit>` pipeline. This is important because a user-supplied config can add its own
        logs pipeline (e.g. `logs/custom`) and/or exporters; those would otherwise fail-and-recurse
        without being covered by the filter. As a result the filter automatically covers EVERY log
        exporter: send-loki-logs, cloud-integrator, send-otlp logs, custom user exporters, and any
        future one. Exporters on the metrics/traces pipelines are never included, so their failure
        logs still reach Loki.

        The auto-injected `nop`/`debug` exporters are excluded: they have no remote endpoint, so
        they cannot fail-and-recurse.
        """
        filter_name = f"filter/{INTERNAL_LOGS_FILTER_ID}/{self._unit_name}"
        if filter_name not in self._config["processors"]:
            return
        # A pipeline is a logs pipeline when its name is `logs` or `logs/<something>`; its type is
        # the segment before the first `/`. Collect exporters across ALL such pipelines, preserving
        # order and de-duplicating (an exporter may be shared by several logs pipelines).
        log_exporter_ids: List[str] = []
        for pipeline_name, pipeline in self._config["service"]["pipelines"].items():
            if pipeline_name.split("/")[0] != "logs":
                continue
            for exporter_id in pipeline.get("exporters", []):
                if (
                    exporter_id.split("/")[0] not in NON_LOOPING_EXPORTER_PREFIXES
                    and exporter_id not in log_exporter_ids
                ):
                    log_exporter_ids.append(exporter_id)
        self._config["processors"][filter_name]["logs"]["log_record"] = [
            f'instrumentation_scope.attributes["otelcol.component.id"] == "{exporter_id}" '
            f'and instrumentation_scope.attributes["otelcol.signal"] == "logs"'
            for exporter_id in log_exporter_ids
        ]

    @property
    def hash(self):
        """Return the config as a SHA256 hash."""
        return sha256(yaml.safe_dump(self.build()))

    def add_default_config(self):
        """Return the default config for OpenTelemetry Collector.

        We always include the OTLP receiver to ensure the config is valid, i.e. there must be at
        least one pipeline, and it must have a valid receiver exporter pair.
        """
        # NOTE: We omit the unit identifier in the receiver name to avoid duplicate OTLP receivers
        #       fighting for port bindings. This is only for relevant for the vm charm
        self.add_component(
            Component.receiver,
            f"otlp/{self._unit_name}",
            {
                "protocols": {
                    "http": {"endpoint": f"0.0.0.0:{Port.otlp_http.value}"},
                    "grpc": {"endpoint": f"0.0.0.0:{Port.otlp_grpc.value}"},
                },
            },
            pipelines=[
                f"logs/{self._unit_name}",
                f"metrics/{self._unit_name}",
                f"traces/{self._unit_name}",
            ],
        )
        # FIXME https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/11780
        # Add TLS config to extensions
        self.add_extension("health_check", {"endpoint": f"0.0.0.0:{Port.health.value}"})
        self._add_internal_telemetry_loop_breaker()
        self.add_telemetry("metrics", {"level": "normal"})

    def _add_internal_telemetry_loop_breaker(self):
        """Configure the loop-breaker and self-ingestion of the collector's internal telemetry.

        We feed the collector's OWN internal logs back into the `logs/<unit>` pipeline, so they
        can be exported (e.g. to Loki) with topology labels. This creates a recursion risk: any
        exporter ATTACHED TO THE LOGS PIPELINE emits an "Exporting failed" log when its endpoint
        is down; that log is itself internal telemetry, so it re-enters the same pipeline, is
        re-exported, fails again; an unbounded feedback loop.

        We add the filter here (unconditionally, on the base config) so it always sits UPSTREAM
        of every log exporter. Its drop conditions are left EMPTY here and are populated at build
        time by `_populate_loop_breaker_filter`, once the full set of exporters on the logs
        pipeline is known.
        """
        self.add_component(
            Component.processor,
            f"filter/{INTERNAL_LOGS_FILTER_ID}/{self._unit_name}",
            {
                "error_mode": "ignore",
                # Populated at build time from the logs-pipeline exporters (see build()).
                "logs": {"log_record": []},
            },
            pipelines=[f"logs/{self._unit_name}"],
        )
        internal_logs_otlp_exporter: Dict[str, Any] = {
            "protocol": "http/protobuf",
            "endpoint": (
                f"https://{self._internal_host}:{Port.otlp_http.value}"
                if self._receiver_tls
                else f"http://localhost:{Port.otlp_http.value}"
            ),
        }
        # Tag ALL of the collector's own telemetry (logs/metrics/traces) with a dedicated
        # `service.name`. The Loki exporter derives its `job` label from
        # `service.namespace/service.name`, so this lands the self-ingested internal logs under
        # `job=otelcol-internal`.
        resource: Dict[str, Any] = {
            "service.name": INTERNAL_TELEMETRY_SERVICE_NAME,
            "loki.format": "logfmt",
        }
        if self._topology_labels:
            resource.update(self._topology_labels)
            # Pin `service.instance.id` to the Juju unit so the Loki `instance` label is stable and
            # correlatable with Juju. Otherwise the collector defaults it to a random per-process
            # UUID that changes on every restart; cardinality churn.
            if "juju_unit" in self._topology_labels:
                resource["service.instance.id"] = self._topology_labels["juju_unit"]
            # Promote ONLY the bounded topology keys to Loki labels via the exporter's
            # `loki.resource.labels` hint.
            resource["loki.resource.labels"] = ", ".join(sorted(self._topology_labels))
        self._config["service"]["telemetry"]["resource"] = resource
        self.add_telemetry(
            "logs",
            {
                "level": "INFO",
                "disable_stacktrace": True,
                "processors": [
                    {
                        "batch": {
                            "exporter": {"otlp": internal_logs_otlp_exporter},
                        }
                    }
                ],
            },
        )

    def add_component(
        self,
        component: Component,
        name: str,
        config: Dict[str, Any],
        pipelines: Optional[List[str]] = None,
    ) -> None:
        """Add a component to the configuration.

        Components are enabled when added to the appropriate "pipelines" within the service section.

        Args:
            component: The type of component to add (receiver, processor, etc.)
            name: Unique identifier for this component instance
            config: Configuration dictionary for the component
            pipelines: List of pipeline types ('logs', 'metrics', 'traces') to add
                     this component to. If None, the component is defined but not
                     added to any pipeline.
        """
        self._config[component.value][name] = config
        if pipelines:
            self._add_to_pipeline(name, component, pipelines)

    def add_extension(self, name: str, extension_config: Dict[str, Any]):
        """Add an extension to the config.

        Extensions are enabled by adding them to the appropriate service section.

        Args:
            name: a string representing the pre-defined extension name.
            extension_config: a (potentially nested) dict representing the config contents.

        Returns:
            Config since this is a builder method.
        """
        if name not in self._config["service"]["extensions"]:
            self._config["service"]["extensions"].append(name)
        self._config["extensions"][name] = extension_config

    def add_telemetry(self, category: Literal["logs", "metrics", "traces"], telem_config: Dict):
        """Add internal telemetry to the config.

        Telemetry is enabled by adding it to the appropriate service section.

        Args:
            category: a string representing the pre-defined internal-telemetry types (logs, metrics, traces).
            telem_config: a dict representing the telemetry config contents.

        Returns:
            Config since this is a builder method.
        """
        # https://opentelemetry.io/docs/collector/internal-telemetry
        self._config["service"]["telemetry"][category] = telem_config

    def _add_to_pipeline(self, name: str, component: Component, pipelines: List[str]):
        """Add a pipeline component to the service::pipelines config.

        Args:
            name: Unique identifier of the component to add
            component: Type of the component (receiver, processor, etc.)
            pipelines: List of pipeline types ('logs', 'metrics', 'traces') to add
                     the component to
        """
        # Create the pipeline dict key chain if it doesn't exist
        for pipeline in pipelines:
            self._config["service"]["pipelines"].setdefault(
                pipeline,
                {
                    component.value: [name],
                },
            )
            # Add to pipeline if it doesn't exist in the list already
            if name not in self._config["service"]["pipelines"][pipeline].setdefault(
                component.value,
                [],
            ):
                self._config["service"]["pipelines"][pipeline][component.value].append(name)

    def _add_missing_nop_exporters(self):
        """Add nopexporter(s) to any pipeline that has no exporters.

        Pipelines require at least one receiver and exporter, otherwise the otelcol service errors.
        To avoid this scenario, we add the nopexporter to each pipeline that has a receiver but no
        exporters.
        """
        nop_exporter_required = False
        for name in self._config["service"]["pipelines"].keys():
            pipeline = self._config["service"]["pipelines"].get(name, {})
            if pipeline:
                if pipeline.get("receivers", []) and not pipeline.get("exporters", []):
                    self._add_to_pipeline(f"nop/{self._unit_name}", Component.exporter, [name])
                    nop_exporter_required = True
        if nop_exporter_required:
            self.add_component(Component.exporter, f"nop/{self._unit_name}", {})

    def _add_tls_to_all_receivers(
        self,
        cert_file: str = SERVER_CERT_PATH,
        key_file: str = SERVER_CERT_PRIVATE_KEY_PATH,
    ):
        """Add TLS configuration to all receivers in the config.

        If a TLS section already exist for a receiver, then it's not updated.

        Ref: https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md#server-configuration
        """
        # NOTE: TLS can't be added to zipkin because it doesn't have a "protocols" section
        for receiver in self._config.get("receivers", {}):
            for protocol in {"http", "grpc", "thrift_http"}:
                try:
                    # TODO: Luca: double check if this actually updates the config
                    section = self._config["receivers"][receiver]["protocols"][protocol]
                except KeyError:
                    continue
                else:
                    section.setdefault("tls", {})
                    section["tls"].setdefault("key_file", key_file)
                    section["tls"].setdefault("cert_file", cert_file)

    def _add_exporter_insecure_skip_verify(self, insecure_skip_verify: bool):
        """Add `tls::insecure_skip_verify` to every exporter's config.

        If the `insecure_skip_verify` key already exists, the value is not updated. The nopexporter
        and debugexporter are skipped, since they have no TLS config.
        """
        for exporter in self._config.get("exporters", {}):
            if exporter.split("/")[0] in ["nop", "debug"]:
                continue
            self._config["exporters"][exporter].setdefault("tls", {}).setdefault(
                "insecure_skip_verify", insecure_skip_verify
            )

    def _set_prometheus_receiver_global_timeout_and_interval(self, interval: str, timeout: str):
        """Set the `scrape_interval` and `scrape_timeout` for all scrape_configs in every prometheus receiver."""
        receivers = self._config.get("receivers", {})
        for name, receiver in receivers.items():
            if name.split("/")[0] == "prometheus":
                scrape_configs = receiver.get("config", {}).get("scrape_configs", [])
                for scrape_cfg in scrape_configs:
                    scrape_cfg["scrape_interval"] = interval
                    scrape_cfg["scrape_timeout"] = timeout
