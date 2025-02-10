"""Helper module to build the configuration for OpenTelemetry Collector."""

from typing import List

import yaml


class OpenTelemetryCollectorConfig:
    """Configuration manager for OpenTelemetry Collector."""

    def build_config(self) -> str:
        """String."""
        config = {
            "extensions": {
                "health_check": {"endpoint": "0.0.0.0:13133"},
                "pprof": {"endpoint": "0.0.0.0:1777"},
                "zpages": {"endpoint": "0.0.0.0:55679"},
            },
            "receivers": {
                "otlp": {
                    "protocols": {
                        "grpc": {"endpoint": "0.0.0.0:4317"},
                        "http": {"endpoint": "0.0.0.0:4318"},
                    }
                },
                "opencensus": {"endpoint": "0.0.0.0:55678"},
                "prometheus": {
                    "config": {
                        "scrape_configs": [
                            {
                                "job_name": "otel-collector",
                                "scrape_interval": "1m",
                                "static_configs": [{"targets": ["0.0.0.0:8888"]}],
                            }
                        ]
                    }
                },
                "jaeger": {
                    "protocols": {
                        "grpc": {"endpoint": "0.0.0.0:14250"},
                        "thrift_binary": {"endpoint": "0.0.0.0:6832"},
                        "thrift_compact": {"endpoint": "0.0.0.06831"},
                        "thrift_http": {"endpoint": "0.0.0.0:14268"},
                    }
                },
                "zipkin": {"endpoint": "0.0.0.0:9411"},
            },
            "processors": {"batch:": None},
            "exporters": {"debug": {"verbosity": "detailed"}},
            "service": {
                "pipelines": {
                    "traces": {
                        "receivers": ["otlp", "opencensus", "jaeger", "zipkin"],
                        "processors": ["batch"],
                        "exporters": ["debug"],
                    },
                    "metrics": {
                        "receivers": ["otlp", "opencensus", "prometheus"],
                        "processors": ["batch"],
                        "exporters": ["debug"],
                    },
                    "logs": {
                        "receivers": ["otlp"],
                        "processors": ["batch"],
                        "exporters": ["debug"],
                    },
                },
                "extensions": ["health_check", "pprof", "zpages"],
            },
        }
        return yaml.dump(config)

    @property
    def ports(self) -> List[int]:
        """Return the ports that are used in the Collector config."""
        ports = [
            8888,  # self-monitoring metrics,
            13133,  # health check
        ]
        return ports
