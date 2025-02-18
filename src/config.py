"""Helper module to build the configuration for OpenTelemetry Collector."""

import yaml
from enum import Enum
from typing import Any, Dict, List, Optional


class Ports(Enum):
    """Helper enum for OpenTelemetry Collector ports."""

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
                "telemetry": {"metrics": {"address": "0.0.0.0:8888", "level": "basic"}},
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
                "prometheus",
                {
                    "config": {
                        "scrape_configs": [
                            {
                                "job_name": "otel-collector",
                                "scrape_interval": "1m",
                                "static_configs": [{"targets": [f"0.0.0.0:{Ports.METRICS}"]}],
                            }
                        ]
                    }
                },
                pipelines=["metrics"],
            )
            .add_extension("health_check", {"endpoint": f"0.0.0.0:{Ports.HEALTH}"})
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
            self._add_to_pipeline(name=name, category="receivers", pipelines=pipelines)
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
            self._add_to_pipeline(name=name, category="exporters", pipelines=pipelines)
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
            self._add_to_pipeline(name=name, category="connectors", pipelines=pipelines)
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
            self._add_to_pipeline(name=name, category="processors", pipelines=pipelines)
        return self

    def add_pipeline(self, name: str, pipeline_config: Dict[str, Any]) -> "Config":
        """Add a pipeline to the config."""
        self._config["service"]["pipelines"][name] = pipeline_config
        return self

    def add_extension(self, name: str, extension_config: Dict[str, Any]) -> "Config":
        """Add an extension to the config."""
        if name not in self._config["service"]["extensions"]:
            self._config["service"]["extensions"].append(name)
        self._config["extensions"][name] = extension_config
        return self

    @property
    def ports(self) -> List[int]:
        """Return the ports that are used in the Collector config."""
        return [port.value for port in Ports]

    def _add_to_pipeline(self, name: str, category: str, pipelines: List[str]):
        for pipeline in pipelines:
            # Create the pipeline dict key chain if it doesn't exist
            self._config["service"]["pipelines"].setdefault(
                pipeline,
                {
                    "receivers": [],
                    "exporters": [],
                    "connectors": [],
                    "processors": [],
                },
            )
            # Add to pipeline if it doesn't exist in the list already
            if name not in self._config["service"]["pipelines"][pipeline][category]:
                self._config["service"]["pipelines"][pipeline][category].append(name)
