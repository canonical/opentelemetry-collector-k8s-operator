"""Helper module to build the configuration for OpenTelemetry Collector."""

import logging
from typing import Any, Optional, Dict, List, Literal, Set

import yaml

from config_builder import Component, ConfigBuilder, Port

logger = logging.getLogger(__name__)


def tail_sampling_config(
    tracing_sampling_rate_charm: float,
    tracing_sampling_rate_workload: float,
    tracing_sampling_rate_error: float,
) -> Dict[str, Any]:
    """The default configuration for the tail sampling processor used by tracing."""
    # policies, as defined by tail sampling processor definition:
    # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor
    # each of them is evaluated separately and processor decides whether to pass the trace through or not
    # see the description of tail sampling processor above for the full decision tree
    return yaml.safe_load(
        f"""
        policies:
          - name: error-traces-policy
            type: and
            and:
              and_sub_policy:
                # status_code processor is using span_status property of spans within a trace
                # see https://opentelemetry.io/docs/concepts/signals/traces/#span-status for reference
                - name: trace-status-policy
                  type: status_code
                  status_code:
                    status_codes:
                    - ERROR
                - name: probabilistic-policy
                  type: probabilistic
                  probabilistic:
                    sampling_percentage: {tracing_sampling_rate_error}
          - name: charm-traces-policy
            type: and
            and:
              and_sub_policy:
                - name: service-name-policy
                  type: string_attribute
                  string_attribute:
                    key: service.name
                    values:
                    - ".+-charm"
                    enabled_regex_matching: true
                - name: probabilistic-policy
                  type: probabilistic
                  probabilistic:
                    sampling_percentage: {tracing_sampling_rate_charm}
          # NOTE: this is the exact inverse match of the charm tracing policy
          - name: workload-traces-policy
            type: and
            and:
              and_sub_policy:
                - name: service-name-policy
                  type: string_attribute
                  string_attribute:
                    key: service.name
                    values:
                    - ".+-charm"
                    enabled_regex_matching: true
                    invert_match: true
                - name: probabilistic-policy
                  type: probabilistic
                  probabilistic:
                    sampling_percentage: {tracing_sampling_rate_workload}
        """
    )


class ConfigManager:
    """Configuration manager for OpenTelemetry Collector.

    It abstracts multiple low-level configuration operations into
    feature-oriented methods.
    """

    def __init__(self, receiver_tls: bool = False, insecure_skip_verify: bool = False):
        """Generate a default OpenTelemetry collector ConfigManager.

        The base configuration is our opinionated default.

        Args:
            receiver_tls: whether to inject TLS config in all receivers on build
            insecure_skip_verify: value for `insecure_skip_verify` in all exporters
        """
        self._insecure_skip_verify = insecure_skip_verify
        self.config = ConfigBuilder(
            receiver_tls=receiver_tls,
            exporter_skip_verify=insecure_skip_verify,
        )
        self.config.add_default_config()

    def add_log_ingestion(self):
        """Configure receiving logs, allowing Promtail instances to specify the Otelcol as their lokiAddress.

        https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/lokireceiver
        """
        self.config.add_component(
            Component.receiver,
            "loki",
            {
                "protocols": {
                    "http": {
                        "endpoint": f"0.0.0.0:{Port.loki_http}",
                    },
                },
                "use_incoming_timestamp": True,
            },
            pipelines=["logs"],
        )

    def add_log_forwarding(self, endpoints: List[dict], insecure_skip_verify: bool):
        """Configure sending logs to Loki via the Loki push API endpoint.

        The LogRecord format is controlled with the `loki.format` hint.

        The Loki exporter converts OTLP resource and log attributes into Loki labels, which are indexed.
        Configuring hints (e.g. `loki.attribute.labels`) specifies which attributes should be placed as labels.
        The hints are themselves attributes and will be ignored when exporting to Loki.

        https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.122.0/exporter/lokiexporter
        """
        for idx, endpoint in enumerate(endpoints):
            self.config.add_component(
                Component.exporter,
                f"loki/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "default_labels_enabled": {"exporter": False, "job": True},
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                },
                pipelines=["logs"],
            )
        # TODO: Luca: this was gated by having outgoing logs. Do we need that?
        self.config.add_component(
            Component.processor,
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
        )
        self.config.add_component(
            Component.processor,
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

    def add_self_scrape(self, identifier: str, labels: Dict):
        """Configure self-monitoring scrape jobs."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver
        self.config.add_component(
            Component.receiver,
            "prometheus",
            {
                "config": {
                    "scrape_configs": [
                        {
                            # This job name is overwritten with "otelcol" when remote-writing
                            "job_name": f"juju_{identifier}_self-monitoring",
                            "scrape_interval": "60s",
                            "static_configs": [
                                {
                                    "targets": [f"0.0.0.0:{Port.metrics}"],
                                    "labels": labels,
                                }
                            ],
                        }
                    ]
                }
            },
            pipelines=["metrics"],
        )

    def add_prometheus_scrape_jobs(self, jobs: List):
        """Update the Prometheus receiver config with scrape jobs."""
        # create the scrape_configs key path if it does not exist
        if jobs:
            self.config._config["receivers"].setdefault("prometheus", {}).setdefault(
                "config", {}
            ).setdefault("scrape_configs", [])
        for scrape_job in jobs:
            # Otelcol acts as a client and scrapes the metrics-generating server, so we enable
            # toggling of skipping the validation of the server certificate
            scrape_job.update({"tls_config": {"insecure_skip_verify": self._insecure_skip_verify}})
            self.config._config["receivers"]["prometheus"]["config"]["scrape_configs"].append(
                scrape_job
            )
        return self

    def add_remote_write(self, endpoints: List[Dict[str, str]]):
        """Configure forwarding alert rules to prometheus/mimir via remote-write."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/prometheusremotewriteexporter
        for idx, endpoint in enumerate(endpoints):
            self.config.add_component(
                Component.exporter,
                f"prometheusremotewrite/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "tls": {"insecure_skip_verify": self._insecure_skip_verify},
                },
                pipelines=["metrics"],
            )

        # TODO Receive alert rules via remote write
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277

    def add_traces_ingestion(
        self,
        requested_tracing_protocols: Set[Literal["zipkin", "jaeger_grpc", "jaeger_thrift_http"]],
    ):
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
            self.config.add_component(
                component=Component.receiver,
                name="zipkin",
                config={"endpoint": f"0.0.0.0:{Port.zipkin}"},
                pipelines=["traces"],
            )
        if (
            "jaeger_grpc" in requested_tracing_protocols
            or "jaeger_thrift_http" in requested_tracing_protocols
        ):
            jaeger_config = {"protocols": {}}
            if "jaeger_grpc" in requested_tracing_protocols:
                jaeger_config["protocols"].update(
                    {"grpc": {"endpoint": f"0.0.0.0:{Port.jaeger_grpc}"}}
                )
            if "jaeger_thrift_http" in requested_tracing_protocols:
                jaeger_config["protocols"].update(
                    {"thrift_http": {"endpoint": f"0.0.0.0:{Port.jaeger_thrift_http}"}}
                )
            self.config.add_component(
                component=Component.receiver,
                name="jaeger",
                config=jaeger_config,
                pipelines=["traces"],
            )

    def add_traces_processing(
        self,
        sampling_rate_charm: float,
        sampling_rate_workload: float,
        sampling_rate_error: float,
    ):
        """Configure the processors for traces."""
        self.config.add_component(
            component=Component.processor,
            name="tail_sampling",
            config=tail_sampling_config(
                tracing_sampling_rate_charm=sampling_rate_charm,
                tracing_sampling_rate_workload=sampling_rate_workload,
                tracing_sampling_rate_error=sampling_rate_error,
            ),
            pipelines=["traces"],
        )

    def add_traces_forwarding(self, endpoint: str):
        """Configure the Tempo exporter to forward traces to and endpoint.

        The limit of adding only one endpoint is currently a Tempo charm limitation.
        """
        self.config.add_component(
            component=Component.exporter,
            name="otlphttp/tempo",
            config={"endpoint": endpoint},
            pipelines=["traces"],
        )

    def add_cloud_integrator(
        self,
        username: Optional[str],
        password: Optional[str],
        prometheus_url: Optional[str],
        loki_url: Optional[str],
        tempo_url: Optional[str],
    ):
        """Configure forwarding telemetry to the endpoints provided by a cloud-integrator charm."""
        exporter_auth_config = {}
        if username and password:
            self.config.add_extension(
                "basicauth/cloud-integrator",
                {
                    "client_auth": {
                        "username": username,
                        "password": password,
                    }
                },
            )
            exporter_auth_config = {"auth": {"authenticator": "basicauth/cloud-integrator"}}
        if prometheus_url:
            self.config.add_component(
                Component.exporter,
                "prometheusremotewrite/cloud-integrator",
                {
                    "endpoint": prometheus_url,
                    "tls": {"insecure_skip_verify": self._insecure_skip_verify},
                    **exporter_auth_config,
                },
                pipelines=["metrics"],
            )
        if loki_url:
            self.config.add_component(
                Component.exporter,
                "loki/cloud-integrator",
                {
                    "endpoint": loki_url,
                    "tls": {"insecure_skip_verify": self._insecure_skip_verify},
                    "default_labels_enabled": {"exporter": False, "job": True},
                    "headers": {"Content-Encoding": "snappy"},  # TODO: check if this is needed
                    **exporter_auth_config,
                },
                pipelines=["logs"],
            )
        if tempo_url:
            self.config.add_component(
                component=Component.exporter,
                name="otlphttp/cloud-integrator",
                config={
                    "endpoint": tempo_url,
                    "tls": {"insecure_skip_verify": self._insecure_skip_verify},
                    **exporter_auth_config,
                },
                pipelines=["traces"],
            )
