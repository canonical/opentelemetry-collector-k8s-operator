"""Helper module to build the configuration for OpenTelemetry Collector."""

import yaml
from enum import Enum
from typing import Any, Dict, List, Optional


class Ports(Enum):
    """Helper enum for OpenTelemetry Collector ports."""

    OTLP_GRPC = 4317
    METRICS = 8888
    HEALTH = 13133


class Config:
    """Configuration manager for OpenTelemetry Collector."""

    def __init__(self):
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

    @property
    def yaml(self) -> str:
        """Return the config as a string."""
        return yaml.dump(self._config)

    @classmethod
    def default_config(cls) -> "Config":
        """Return the default config for OpenTelemetry Collector."""
        return (
            cls()
            .add_receiver(
                "otlp",
                {"protocols": {"grpc": {"endpoint": f"0.0.0.0:{Ports.OTLP_GRPC.value}"}}},
                pipelines=["metrics"],
            )
            .add_exporter(
                "otlp", {"endpoint": f"otelcol:{Ports.OTLP_GRPC.value}"}, pipelines=["metrics"]
            )
            .add_extension("health_check", {"endpoint": f"0.0.0.0:{Ports.HEALTH.value}"})
            # .add_telemetry("metrics", "level", "normal")  # TODO This line stops the exporter from writing to Prom??? This is supposed to overwrite the default can be removed if default is desired.
        )

    def add_receiver(
        self, name: str, receiver_config: Dict[str, Any], pipelines: Optional[List[str]] = None
    ) -> "Config":
        """Add a receiver to the config.

        Receivers are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined receiver name.
            receiver_config: a (potentially nested) dict representing the config contents.
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the receiver should be added to.

        Returns:
            Config since this is a builder method.
        """
        self._config["receivers"][name] = receiver_config
        if pipelines:
            self._add_to_pipeline(name, "receivers", pipelines)
        return self

    def add_exporter(
        self, name: str, exporter_config: Dict[str, Any], pipelines: Optional[List[str]] = None
    ) -> "Config":
        """Add an exporter to the config.

        Exporters are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined exporter name.
            exporter_config: a (potentially nested) dict representing the config contents.
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the exporter should be added to.

        Returns:
            Config since this is a builder method.
        """
        self._config["exporters"][name] = exporter_config
        if pipelines:
            self._add_to_pipeline(name, "exporters", pipelines)
        return self

    def add_connector(
        self, name: str, connector_config: Dict[str, Any], pipelines: Optional[List[str]] = None
    ) -> "Config":
        """Add a connector to the config.

        Connectors are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined connector name.
            connector_config: a (potentially nested) dict representing the config contents.
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the connector should be added to.

        Returns:
            Config since this is a builder method.
        """
        self._config["connectors"][name] = connector_config
        if pipelines:
            self._add_to_pipeline(name, "connectors", pipelines)
        return self

    def add_processor(
        self, name: str, processor_config: Dict[str, Any], pipelines: Optional[List[str]] = None
    ) -> "Config":
        """Add a processor to the config.

        Processors are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined processor name.
            processor_config: a (potentially nested) dict representing the config contents.
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the processor should be added to.

        Returns:
            Config since this is a builder method.
        """
        self._config["processors"][name] = processor_config
        if pipelines:
            self._add_to_pipeline(name, "processors", pipelines)
        return self

    def add_extension(self, name: str, extension_config: Dict[str, Any]) -> "Config":
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
        return self

    def add_telemetry(
        self, category: str, option: str, telem_config: Any
    ) -> "Config":
        """Add internal telemetry to the config.

        Telemetry is enabled by adding it to the appropriate service section.

        Args:
            category: a string representing the pre-defined internal-telemetry.
            option: a string representing the config key within the specified category to configure.
            telem_config: a list of (potentially nested) dict(s) representing the config contents.

        Returns:
            Config since this is a builder method.
        """
        # https://opentelemetry.io/docs/collector/internal-telemetry
        self._config["service"]["telemetry"].setdefault(category, {})
        self._config["service"]["telemetry"][category][option] = telem_config
        return self

    def _add_to_pipeline(self, name: str, category: str, pipelines: List[str]):
        """Add a pipeline component to the service::pipelines config."""
        # Create the pipeline dict key chain if it doesn't exist
        for pipeline in pipelines:
            self._config["service"]["pipelines"].setdefault(
                pipeline,
                {
                    category: [name],
                },
            )
            # Add to pipeline if it doesn't exist in the list already
            if name not in self._config["service"]["pipelines"][pipeline].setdefault(
                category,
                [],
            ):
                self._config["service"]["pipelines"][pipeline][category].append(name)

    @property
    def ports(self) -> List[int]:
        """Return the ports that are used in the Collector config."""
        return [port.value for port in Ports]

    def add_scrape_job(self, scrape_job: Dict):
        """Update the Prometheus receiver config."""
        # Create the scrape_configs key path if it does not exist
        self._config["receivers"].setdefault("prometheus", {}).setdefault("config", {}).setdefault(
            "scrape_configs", []
        )
        self._config["receivers"]["prometheus"]["config"]["scrape_configs"].append(scrape_job)
        return self
