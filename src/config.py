"""Helper module to build the configuration for OpenTelemetry Collector."""

import yaml
from typing import Any, Dict, List
import copy


DEFAULT_CONFIG = {
    "extensions": {},
    "receivers": {},
    "exporters": {},
    "connectors": {},
    "processors": {},
    "service": {"extensions": [], "pipelines": {}},
}


class ConfigManager:
    """Configuration manager for OpenTelemetry Collector."""

    _config = copy.deepcopy(DEFAULT_CONFIG)

    @property
    def yaml(self) -> str:
        """Return the config as a string."""
        return yaml.dump(self._config)

    @classmethod
    def default_config(cls) -> "ConfigManager":
        """Return the default config for OpenTelemetry Collector."""
        return (
            cls()
            .add_receiver(
                "otlp",
                {
                    "protocols": {
                        "grpc": {"endpoint": "0.0.0.0:4317"},
                        "http": {"endpoint": "0.0.0.0:4318"},
                    }
                },
            )
            .add_receiver(
                "prometheus",
                {
                    "config": {
                        "scrape_configs": [
                            {
                                "job_name": "otel-collector",
                                "scrape_interval": "1m",
                                "static_configs": [
                                    {"targets": ["0.0.0.0:8888"]}
                                ],  # TODO This works but is missing the static_configs for labels (create an issue for this)
                            }
                        ]
                    }
                },
            )
            .add_processor("batch", {})
            .add_exporter("debug", {"verbosity": "detailed"})
            .add_extension("health_check", {"endpoint": "0.0.0.0:13133"})
            .add_extension("pprof", {"endpoint": "0.0.0.0:1777"})
            .add_extension("zpages", {"endpoint": "0.0.0.0:55679"})
            .add_pipeline(
                "metrics",
                {
                    "receivers": ["otlp", "prometheus"],
                    "processors": ["batch"],
                    "exporters": ["debug"],
                },
            )
            .add_pipeline(
                "logs",
                {
                    "receivers": ["otlp"],
                    "processors": ["batch"],
                    "exporters": ["debug"],
                },
            )
        )

    def add_receiver(self, name: str, receiver_config: Dict[str, Any]) -> "ConfigManager":
        """Add a receiver to the config.

        Receivers are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined receiver name.
            receiver_config: a (potentially nested) dict representing the config contents.

        Returns:
            ConfigManager since this is a builder method.
        """
        self._config["receivers"][name] = receiver_config
        return self

    def add_exporter(self, name: str, exporter_config: Dict[str, Any]):
        """Add an exporter to the config.

        Exporters are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined exporter name.
            exporter_config: a (potentially nested) dict representing the config contents.

        Returns:
            ConfigManager since this is a builder method.
        """
        self._config["exporters"][name] = exporter_config
        return self

    def add_connector(self, name: str, connector_config: Dict[str, Any]):
        """Add a connector to the config.

        Connectors are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined connector name.
            connector_config: a (potentially nested) dict representing the config contents.

        Returns:
            ConfigManager since this is a builder method.
        """
        self._config["connectors"][name] = connector_config
        return self

    def add_processor(self, name: str, processor_config: Dict[str, Any]):
        """Add a processor to the config.

        Processors are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined processor name.
            processor_config: a (potentially nested) dict representing the config contents.

        Returns:
            ConfigManager since this is a builder method.
        """
        self._config["processors"][name] = processor_config
        return self

    def add_pipeline(self, name: str, pipeline_config: Dict[str, Any]):
        """Add a pipeline to the config."""
        self._config["service"]["pipelines"][name] = pipeline_config
        return self

    def add_to_pipeline_component(self, name: str, pipelines: List[str], category: str):
        """Add a pipeline component to the config."""
        # Create the pipeline dict key chain if it doesn't exist
        for pipeline in pipelines:
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
        return self

    def add_extension(self, name: str, extension_config: Dict[str, Any]):
        """Add an extension to the config."""
        if name not in self._config["service"]["extensions"]:
            self._config["service"]["extensions"].append(name)
        self._config["extensions"][name] = extension_config
        return self

    @property
    def ports(self) -> List[int]:
        """Return the ports that are used in the Collector config."""
        ports = [
            8888,  # self-monitoring metrics,
            13133,  # health check
        ]
        return ports

    def add_scrape_job(self, scrape_job: Dict):
        """Update the Prometheus receiver config."""
        # Create the scrape_configs key path if it does not exist
        self._config["receivers"].setdefault("prometheus", {}).setdefault("config", {}).setdefault(
            "scrape_configs", []
        )
        self._config["receivers"]["prometheus"]["config"]["scrape_configs"].append(scrape_job)
        return self
