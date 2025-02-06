"""Helper module to build the configuration for OpenTelemetry Collector."""


class OpenTelemetryCollectorConfig:
    """class."""  # TODO: add docstring

    config = """
# To limit exposure to denial of service attacks, change the host in endpoints below from 0.0.0.0 to a specific network interface.
# See https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/security-best-practices.md#safeguards-against-denial-of-service-attacks

extensions:
  health_check:
    endpoint: 0.0.0.0:13133
  pprof:
    endpoint: 0.0.0.0:1777
  zpages:
    endpoint: 0.0.0.0:55679

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

  opencensus:
    endpoint: 0.0.0.0:55678

  # Collect own metrics
  prometheus:
    config:
      scrape_configs:
      - job_name: 'otel-collector'
        scrape_interval: 10s
        static_configs:
        - targets: ['0.0.0.0:8888']
      - job_name: 'node-exporter'
        metrics_path: "/metrics"
        static_configs:
          - targets: ['node-exporter:9100']
      # remote_write:
        # https://github.com/prometheus/prometheus/blob/v2.28.1/docs/configuration/configuration.md#remote_write

  jaeger:
    protocols:
      grpc:
        endpoint: 0.0.0.0:14250
      thrift_binary:
        endpoint: 0.0.0.0:6832
      thrift_compact:
        endpoint: 0.0.0.0:6831
      thrift_http:
        endpoint: 0.0.0.0:14268

  zipkin:
    endpoint: 0.0.0.0:9411

processors:
  batch:

exporters:
  debug:
    verbosity: detailed
  prometheusremotewrite:
    endpoint: "http://prometheus:9090/api/v1/write"

service:

  pipelines:

    traces:
      receivers: [otlp, opencensus, jaeger, zipkin]
      processors: [batch]
      exporters: [debug]

    metrics:
      receivers: [otlp, opencensus, prometheus]
      processors: [batch]
      exporters: [debug, prometheusremotewrite]

    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]

  extensions: [health_check, pprof, zpages]
    """

    def build_config(self) -> str:
        """String."""
        return self.config
