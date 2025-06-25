"""Helper module to build the configuration for OpenTelemetry Collector."""

import hashlib
import logging
from typing import Any, Dict, List, Optional
from enum import Enum, unique

import yaml

from constants import SERVER_CERT_PATH, SERVER_CERT_PRIVATE_KEY_PATH

logger = logging.getLogger(__name__)


def sha256(hashable) -> str:
    """Use instead of the builtin hash() for repeatable values."""
    if isinstance(hashable, str):
        hashable = hashable.encode("utf-8")
    return hashlib.sha256(hashable).hexdigest()


# TODO: inherit enum.StrEnum when jammy is no longer supported.
# https://docs.python.org/3/library/enum.html#enum.StrEnum
@unique
class Port(int, Enum):
    """Ports used by OpenTelemetry Collector."""

    loki_http = 3500
    otlp_grpc = 4317
    otlp_http = 4318
    metrics = 8888
    health = 13133
    # Tracing
    jaeger_grpc = 14250
    jaeger_thrift_http = 14268
    zipkin = 9411


@unique
class Component(str, Enum):
    """Pipeline components of the OpenTelemetry Collector configuration.

    These are all the component types that can be part of a pipeline:
    https://opentelemetry.io/docs/collector/configuration/#basics

    The value of the enum corresponds to the top-level key under which
    they're placed in the config file.
    """

    receiver = "receivers"
    processor = "processors"
    exporter = "exporters"
    connector = "connectors"


class ConfigBuilder:
    """Configuration builder for OpenTelemetry Collector.

    It takes care of assembling the configuration for the Collector at a low
    level, composing the basic building blocks in the correct way.
    """

    def __init__(self, receiver_tls: bool = False, exporter_skip_verify: bool = False):
        """Generate an empty OpenTelemetry collector config.

        Args:
            receiver_tls: whether to inject TLS config in all receivers on build
            exporter_skip_verify: value for `insecure_skip_verify` in all exporters

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
        self._receiver_tls = receiver_tls
        self._exporter_skip_verify = exporter_skip_verify

    def build(self) -> str:
        """Build the final configuration and return it as YAML.

        This function takes care of adding the missing debug exporters, in
        order to produce a valid config for pipelines that don't have any.

        It also adds TLS information to all receivers, and the proper
        insecure_skip_verify setting to all exporters.
        """
        self._add_missing_debug_exporters()
        if self._receiver_tls:
            self._add_tls_to_all_receivers()
        self._add_exporter_insecure_skip_verify(self._exporter_skip_verify)
        return yaml.safe_dump(self._config)

    @property
    def hash(self):
        """Return the config as a SHA256 hash."""
        return sha256(yaml.safe_dump(self.build()))

    def add_default_config(self):
        """Return the default config for OpenTelemetry Collector."""
        # Currently, we always include the OTLP receiver to ensure the config is valid at all times.
        # We also need these receivers for tracing.
        # There must be at least one pipeline, and it must have a valid receiver exporter pair.
        self.add_component(
            Component.receiver,
            "otlp",
            {
                "protocols": {
                    "http": {"endpoint": f"0.0.0.0:{Port.otlp_http}"},
                    "grpc": {"endpoint": f"0.0.0.0:{Port.otlp_grpc}"},
                },
            },
            pipelines=["logs", "metrics", "traces"],
        )
        # TODO https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/healthcheckextension
        # Add TLS config to extensions
        self.add_extension("health_check", {"endpoint": f"0.0.0.0:{Port.health}"})
        self.add_telemetry("logs", {"level": "DEBUG"})
        self.add_telemetry("metrics", {"level": "normal"})

    def add_component(
        self,
        component: Component,
        name: str,
        config: Dict[str, Any],
        pipelines: Optional[List[str]] = None,
    ):
        """Add a component to the config.

        Components are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            component: the type of Component to add
            name: the component name, top-level key under which the component config is placed
            config: a (potentially nested) dict containing the component config
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the component should be added to
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

    def add_telemetry(self, category: str, telem_config: Any):
        """Add internal telemetry to the config.

        Telemetry is enabled by adding it to the appropriate service section.

        Args:
            category: a string representing the pre-defined internal-telemetry types (logs, metrics, traces).
            telem_config: a list of (potentially nested) dict(s) representing the config contents.

        Returns:
            Config since this is a builder method.
        """
        # https://opentelemetry.io/docs/collector/internal-telemetry
        self._config["service"]["telemetry"].setdefault(category, {})
        self._config["service"]["telemetry"][category] = telem_config

    def _add_to_pipeline(self, name: str, component: Component, pipelines: List[str]):
        """Add a pipeline component to the service::pipelines config.

        Args:
            name: a string, uniquely identifying this pipeline component.
            component: the type of component being added to the pipeline.
            category: a string identifying thy type of pipeline component (receiver, exporter, processor, ...).
            pipelines: a list of strings identifying which signal pipeline type(s) to assign the pipeline component to.

        Returns:
            Config since this is a builder method.
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

    def _add_missing_debug_exporters(self):
        """Add debug exporters to any pipeline that has no exporters.

        Pipelines require at least one receiver and exporter, otherwise the otelcol service errors.
        To avoid this scenario, we add the debug exporter to each pipeline that has a receiver but no
        exporters.
        """
        debug_exporter_required = False
        for signal in ["logs", "metrics", "traces"]:
            pipeline = self._config["service"]["pipelines"].get(signal, {})
            if pipeline:
                if pipeline.get("receivers", []) and not pipeline.get("exporters", []):
                    self._add_to_pipeline("debug", Component.exporter, [signal])
                    debug_exporter_required = True
        if debug_exporter_required:
            self.add_component(Component.exporter, "debug", {"verbosity": "basic"})

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

        If the key already exists, the value is not updated.
        """
        for exporter in self._config.get("exporters", {}):
            if exporter.split("/")[0] == "debug":
                continue
            self._config["exporters"][exporter].setdefault("tls", {}).setdefault(
                "insecure_skip_verify", insecure_skip_verify
            )
