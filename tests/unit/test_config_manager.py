# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

from src.config_manager import ConfigManager
from charmlibs.interfaces.otlp import OtlpEndpoint
import copy

import pytest


def test_add_prometheus_scrape():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="otelcol/0",
        global_scrape_interval="15s",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

    # WHEN a scrape job is added to the config
    first_job = [
        {
            "metrics_path": "/metrics",
            "static_configs": [{"targets": ["*:9001"]}],
            "job_name": "first_job",
            "scrape_interval": "15s",
        }
    ]
    expected_prom_recv_cfg = {
        "config": {
            "scrape_configs": [
                {
                    "metrics_path": "/metrics",
                    "static_configs": [{"targets": ["*:9001"]}],
                    "job_name": "first_job",
                    "scrape_interval": "15s",
                    # Added dynamically by add_prometheus_scrape
                    "tls_config": {"insecure_skip_verify": True},
                },
            ],
        }
    }
    config_manager.add_prometheus_scrape_jobs(first_job)
    # THEN it exists in the prometheus receiver config
    # AND insecure_skip_verify is injected into the config
    assert (
        config_manager.config._config["receivers"]["prometheus/metrics-endpoint/otelcol/0"]
        == expected_prom_recv_cfg
    )

    # AND WHEN more scrape jobs are added to the config
    more_jobs = [
        {
            "metrics_path": "/metrics",
            "job_name": "second_job",
        },
        {
            "metrics_path": "/metrics",
            "job_name": "third_job",
        },
    ]
    config_manager.add_prometheus_scrape_jobs(more_jobs)
    # THEN the original scrape job was overwritten and the newly added scrape jobs were added
    job_names = [
        job["job_name"]
        for job in config_manager.config._config["receivers"][
            "prometheus/metrics-endpoint/otelcol/0"
        ]["config"]["scrape_configs"]
    ]
    assert job_names == ["second_job", "third_job"]


def test_add_log_ingestion():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="otelcol/0",
        global_scrape_interval="",
        global_scrape_timeout="",
    )
    # WHEN a loki receiver is added to the config
    expected_loki_ingestion_cfg = {
        "protocols": {"http": {"endpoint": "0.0.0.0:3500"}},
        "use_incoming_timestamp": True,
    }
    config_manager.add_log_ingestion()
    # THEN it exists in the loki receiver config
    config = dict(
        sorted(
            config_manager.config._config["receivers"]["loki/receive-loki-logs/otelcol/0"].items()
        )
    )
    expected_config = dict(sorted(expected_loki_ingestion_cfg.items()))
    assert config == expected_config


def test_add_log_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="otelcol/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )
    # WHEN a loki exporter is added to the config
    expected_loki_forwarding_cfg = {
        "default_labels_enabled": {
            "exporter": False,
            "job": True,
        },
        "endpoint": "http://192.168.1.244/cos-loki-0/loki/api/v1/push",
        "retry_on_failure": {
            "max_elapsed_time": "5m",
        },
        "sending_queue": {"enabled": True, "queue_size": 1000, "storage": "file_storage"},
        "tls": {
            "insecure_skip_verify": False,
        },
    }
    config_manager.add_log_forwarding(
        endpoints=[{"url": "http://192.168.1.244/cos-loki-0/loki/api/v1/push"}],
        insecure_skip_verify=False,
    )
    # THEN it exists in the loki exporter config
    config = dict(
        sorted(config_manager.config._config["exporters"]["loki/send-loki-logs/0"].items())
    )
    expected_config = dict(sorted(expected_loki_forwarding_cfg.items()))
    assert config == expected_config


def test_add_traces_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="otelcol/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

    # WHEN a single traces exporter is added to the config
    expected_traces_forwarding_cfg = {
        "endpoint": "http://192.168.1.244:4318",
        "retry_on_failure": {
            "max_elapsed_time": "5m",
        },
        "sending_queue": {"enabled": True, "queue_size": 1000, "storage": "file_storage"},
    }
    config_manager.add_traces_forwarding(
        endpoint="http://192.168.1.244:4318",
        identifier="0",
    )
    # THEN it exists in the traces exporter config under a uniquely named key
    config = dict(
        sorted(config_manager.config._config["exporters"]["otlphttp/send-traces-0"].items())
    )
    expected_config = dict(sorted(expected_traces_forwarding_cfg.items()))
    assert config == expected_config


def test_add_traces_forwarding_multiple_endpoints():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="otelcol/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

    # WHEN two traces exporters are added to the config (one per Tempo backend)
    config_manager.add_traces_forwarding(
        endpoint="http://tempo1.example.com:4318",
        identifier="0",
    )
    config_manager.add_traces_forwarding(
        endpoint="http://tempo2.example.com:4318",
        identifier="1",
    )

    exporters = config_manager.config._config["exporters"]

    # THEN two distinct exporters exist
    assert "otlphttp/send-traces-0" in exporters
    assert "otlphttp/send-traces-1" in exporters
    assert exporters["otlphttp/send-traces-0"]["endpoint"] == "http://tempo1.example.com:4318"
    assert exporters["otlphttp/send-traces-1"]["endpoint"] == "http://tempo2.example.com:4318"

    # AND both exporters are wired into the traces pipeline
    pipeline_exporters = config_manager.config._config["service"]["pipelines"][
        "traces/otelcol/0"
    ]["exporters"]
    assert "otlphttp/send-traces-0" in pipeline_exporters
    assert "otlphttp/send-traces-1" in pipeline_exporters


def test_add_remote_write():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="otelcol/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

    # WHEN a remote write exporter is added to the config
    expected_remote_write_cfg = {
        "endpoint": "http://192.168.1.244/cos-prometheus-0/api/v1/write",
        "add_metric_suffixes": False,
        "tls": {
            "insecure_skip_verify": True,
        },
        "retry_on_failure": {
            "max_elapsed_time": "5m",
        },
        "remote_write_queue": {"enabled": True, "queue_size": 1000},
    }
    config_manager.add_remote_write(
        endpoints=[{"url": "http://192.168.1.244/cos-prometheus-0/api/v1/write"}],
    )
    # THEN it exists in the remote write exporter config
    config = dict(
        sorted(
            config_manager.config._config["exporters"][
                "prometheusremotewrite/send-remote-write/0"
            ].items()
        )
    )
    expected_config = dict(sorted(expected_remote_write_cfg.items()))
    assert config == expected_config


@pytest.mark.parametrize(
    "enabled_pipelines,expected_pipelines",
    [
        (
            {"logs": False, "metrics": False, "traces": False},
            {
                "logs/otelcol/0": {"receivers": ["otlp/otelcol/0"], "exporters": []},
                "metrics/otelcol/0": {"receivers": ["otlp/otelcol/0"], "exporters": []},
                "traces/otelcol/0": {"receivers": ["otlp/otelcol/0"], "exporters": []},
            },
        ),
        (
            {"logs": True, "metrics": True, "traces": True},
            {
                "logs/otelcol/0": {
                    "receivers": ["otlp/otelcol/0"],
                    # The loop-breaker filter is always present on the self-ingested logs pipeline
                    "processors": ["filter/internal-telemetry-loop-breaker/otelcol/0"],
                    "exporters": ["debug/juju-config-enabled"],
                },
                "metrics/otelcol/0": {
                    "receivers": ["otlp/otelcol/0"],
                    "exporters": ["debug/juju-config-enabled"],
                },
                "traces/otelcol/0": {
                    "receivers": ["otlp/otelcol/0"],
                    "exporters": ["debug/juju-config-enabled"],
                },
            },
        ),
        (
            {"logs": True, "metrics": False, "traces": True},
            {
                "logs/otelcol/0": {
                    "receivers": ["otlp/otelcol/0"],
                    # The loop-breaker filter is always present on the self-ingested logs pipeline
                    "processors": ["filter/internal-telemetry-loop-breaker/otelcol/0"],
                    "exporters": ["debug/juju-config-enabled"],
                },
                "metrics/otelcol/0": {"receivers": ["otlp/otelcol/0"]},
                "traces/otelcol/0": {
                    "receivers": ["otlp/otelcol/0"],
                    "exporters": ["debug/juju-config-enabled"],
                },
            },
        ),
    ],
)
def test_add_debug_exporters(enabled_pipelines, expected_pipelines):
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "", "")
    initial_cfg = copy.copy(config_manager.config._config)

    # WHEN debug exporters are added to the config
    config_manager.add_debug_exporters(**enabled_pipelines)

    # THEN the config remains unchanged if no pipelines are enabled
    if not any(enabled_pipelines.values()):
        assert initial_cfg == config_manager.config._config
        return

    # AND only one debug exporter is added to the list of exporters
    assert 1 == sum(
        "debug/juju-config-enabled" in key for key in config_manager.config._config["exporters"]
    )
    # AND there are no additional pipelines configured
    assert list(config_manager.config._config["service"]["pipelines"].keys()) == [
        "logs/otelcol/0",
        "metrics/otelcol/0",
        "traces/otelcol/0",
    ]
    # AND the debug exporter is only attached to the enabled pipelines
    # AND there is an OTLP receiver in each pipeline
    assert expected_pipelines == config_manager.config._config["service"]["pipelines"]


def test_add_otlp_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="otelcol/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

    # WHEN the OTLP providers for multiple relations have provided the preferred protocols
    unit_name = "otelcol/0"
    config_manager.add_otlp_forwarding(
        relation_map={
            0: OtlpEndpoint(
                **{
                    "protocol": "grpc",
                    "endpoint": "1.2.3.4:grpc-port",
                    "telemetries": ["metrics", "traces"],
                    "insecure": False,
                }
            ),
            1: OtlpEndpoint(
                **{
                    "protocol": "http",
                    "endpoint": "http://host-1:http-port",
                    "telemetries": ["logs"],
                    "insecure": True,
                }
            ),
            2: OtlpEndpoint(
                **{
                    "protocol": "grpc",
                    "endpoint": "host-2:grpc-port",
                    "telemetries": ["logs", "traces"],
                    "insecure": True,
                }
            ),
        }
    )

    # THEN the exporter config contains appropriate "otlp" and "otlphttp" exporters
    expected_exporters = {
        f"otlp/rel-0/{unit_name}": {
            "endpoint": "1.2.3.4:grpc-port",
            "tls": {"insecure": False, "insecure_skip_verify": True},
            "retry_on_failure": {"max_elapsed_time": "5m"},
            "sending_queue": {"enabled": True, "queue_size": 1000, "storage": "file_storage"},
        },
        f"otlphttp/rel-1/{unit_name}": {
            "endpoint": "http://host-1:http-port",
            "tls": {"insecure": True, "insecure_skip_verify": True},
            "retry_on_failure": {"max_elapsed_time": "5m"},
            "sending_queue": {"enabled": True, "queue_size": 1000, "storage": "file_storage"},
        },
        f"otlp/rel-2/{unit_name}": {
            "endpoint": "host-2:grpc-port",
            "tls": {"insecure": True, "insecure_skip_verify": True},
            "retry_on_failure": {"max_elapsed_time": "5m"},
            "sending_queue": {"enabled": True, "queue_size": 1000, "storage": "file_storage"},
        },
    }
    # AND the exporters are added to the appropriate pipelines
    expected_pipelines = {
        "logs/otelcol/0": {
            "receivers": ["otlp/otelcol/0"],
            # The loop-breaker filter is always present on the self-ingested logs pipeline, so any
            # log exporter (here an OTLP-logs exporter) is guarded against the recursion.
            "processors": ["filter/internal-telemetry-loop-breaker/otelcol/0"],
            "exporters": [f"otlphttp/rel-1/{unit_name}", f"otlp/rel-2/{unit_name}"],
        },
        "metrics/otelcol/0": {
            "receivers": ["otlp/otelcol/0"],
            "exporters": [f"otlp/rel-0/{unit_name}"],
        },
        "traces/otelcol/0": {
            "receivers": ["otlp/otelcol/0"],
            "exporters": [f"otlp/rel-0/{unit_name}", f"otlp/rel-2/{unit_name}"],
        },
    }
    assert config_manager.config._config["exporters"] == expected_exporters
    assert config_manager.config._config["service"]["pipelines"] == expected_pipelines


def test_self_ingest_loop_breaker_invariant_all_log_exporters():
    """INVARIANT: every exporter on the self-ingested logs pipeline is covered by the loop-breaker.

    The collector self-ingests its own internal logs into `logs/<unit>` and exports them. Any
    exporter on THAT pipeline can recurse when its endpoint is down. The loop-breaker filter's drop
    conditions are enumerated dynamically at build time from the logs-pipeline exporters, so it
    covers EVERY log exporter automatically. This test enables every feature that attaches a log
    exporter -- Loki forwarding, cloud-integrator Loki, AND a `send-otlp` LOGS exporter -- plus a
    NON-log exporter (Mimir remote-write on the metrics pipeline), then asserts:
      1. every log-pipeline exporter is covered by an exact component-id condition, and
      2. the non-log (Mimir) exporter is NOT covered (its failure logs still reach Loki).
    If a future log exporter is wired into the logs pipeline, (1) covers it with no code change;
    if the dynamic enumeration regresses, this test fails.
    """
    import yaml

    unit_name = "otelcol/0"
    filter_name = f"filter/internal-telemetry-loop-breaker/{unit_name}"
    config_manager = ConfigManager(
        unit_name=unit_name,
        global_scrape_interval="",
        global_scrape_timeout="",
    )
    # WHEN every LOG-exporting feature is enabled ...
    config_manager.add_log_forwarding(
        endpoints=[{"url": "http://loki/loki/api/v1/push"}],
        insecure_skip_verify=False,
    )
    config_manager.add_cloud_integrator(
        username=None,
        password=None,
        prometheus_url=None,
        loki_url="http://cloud-loki/loki/api/v1/push",
        tempo_url=None,
    )
    # ... including a `send-otlp` LOGS exporter (the previously-unguarded loop path) ...
    config_manager.add_otlp_forwarding(
        relation_map={
            0: OtlpEndpoint(
                protocol="http",
                endpoint="http://otlp-logs:4318",
                telemetries=["logs"],
                insecure=True,
            ),
        }
    )
    # ... AND a NON-log exporter (remote-write to Mimir), whose failure logs must NOT be dropped
    # (they cannot recurse while the log path is up and are the most useful logs).
    config_manager.add_remote_write(endpoints=[{"url": "http://mimir/api/v1/push"}])

    built = yaml.safe_load(config_manager.config.build())
    pipelines = built["service"]["pipelines"]
    logs_pipeline = pipelines[f"logs/{unit_name}"]
    conditions = built["processors"][filter_name]["logs"]["log_record"]
    # THEN the filter is present on the self-ingested logs pipeline.
    # NOTE: internal telemetry is only self-ingested for the `logs` signal today. If a future
    # change self-ingests `metrics`/`traces`, extend the filter/build() to those pipelines too.
    assert filter_name in logs_pipeline.get("processors", [])

    # AND every non-nop/debug exporter on the logs pipeline is covered by an exact-id condition
    for exporter_id in logs_pipeline.get("exporters", []):
        if exporter_id.split("/")[0] in ("nop", "debug"):
            continue
        expected = f'attributes["otelcol.component.id"] == "{exporter_id}"'
        assert expected in conditions, (
            f"log exporter '{exporter_id}' on the self-ingested pipeline is NOT covered by the "
            "loop-breaker filter (see ConfigBuilder._populate_loop_breaker_filter)"
        )

    # AND the send-otlp LOGS exporter specifically is covered (the previously-unguarded path)
    assert any("otlphttp/rel-" in cond for cond in conditions)

    # AND the NON-log Mimir exporter is NOT covered, so its failure logs still reach Loki
    assert not any("prometheusremotewrite" in cond for cond in conditions)
