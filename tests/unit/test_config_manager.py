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
    """INVARIANT: every log exporter on the self-ingested pipeline is covered by the loop-breaker.

    The collector self-ingests its own internal logs into `logs/<unit>` and exports them. Only the
    LOG exporter(s) those internal logs loop through can recurse when their endpoint is down. The
    filter drops exactly those exporters' failure logs, keyed on their `otelcol.component.id`
    prefix (LOOPABLE_LOG_EXPORTER_ID_PREFIXES). This test enables every feature that attaches a
    LOG exporter to the pipeline (Loki forwarding + cloud-integrator Loki) and asserts:
      1. the filter is present on the logs pipeline, and
      2. EVERY log exporter's id is matched by one of the filter conditions.
    If a future log exporter is wired into the logs pipeline without adding its id prefix to
    LOOPABLE_LOG_EXPORTER_ID_PREFIXES, assertion (2) fails at authoring time.
    """
    from src.constants import LOOPABLE_LOG_EXPORTER_ID_PREFIXES

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
    # ... AND a NON-log exporter is also enabled (remote-write to Mimir), whose failure logs must
    # NOT be dropped (they cannot recurse while the log path is up and are the most useful logs).
    config_manager.add_remote_write(endpoints=[{"url": "http://mimir/api/v1/push"}])

    config = config_manager.config._config
    pipelines = config["service"]["pipelines"]
    logs_pipeline = pipelines[f"logs/{unit_name}"]
    # THEN the loop-breaker filter is present on the self-ingested logs pipeline.
    # NOTE: internal telemetry is only self-ingested for the `logs` signal today. If a future
    # change self-ingests `metrics`/`traces`, extend this invariant (and the filter) accordingly.
    assert filter_name in logs_pipeline.get("processors", [])

    # AND every LOG exporter on the pipeline is matched by one of the filter's id-prefix conditions
    prefixes = LOOPABLE_LOG_EXPORTER_ID_PREFIXES
    for exporter_id in logs_pipeline.get("exporters", []):
        assert any(exporter_id.startswith(prefix) for prefix in prefixes), (
            f"log exporter '{exporter_id}' on the self-ingested pipeline is NOT covered by the "
            f"loop-breaker filter; add its id prefix to LOOPABLE_LOG_EXPORTER_ID_PREFIXES"
        )

    # AND the NON-log Mimir exporter is NOT covered by the filter, so its "Exporting failed" logs
    # would pass through to Loki (visibility of cross-signal export failures is preserved).
    mimir_id = next(
        e for e in config["exporters"] if e.startswith("prometheusremotewrite/send-remote-write/")
    )
    assert not any(mimir_id.startswith(prefix) for prefix in prefixes), (
        f"non-log exporter '{mimir_id}' must NOT be covered by the loop-breaker filter; its "
        "failure logs are the most useful logs and cannot recurse while the log path is up"
    )
