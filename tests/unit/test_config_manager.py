# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

from src.config_manager import ConfigManager
from src.otlp import OtlpEndpoint


def test_add_prometheus_scrape():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="fake/0",
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
        config_manager.config._config["receivers"]["prometheus/metrics-endpoint/fake/0"]
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
            "prometheus/metrics-endpoint/fake/0"
        ]["config"]["scrape_configs"]
    ]
    assert job_names == ["second_job", "third_job"]


def test_add_log_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="fake/0",
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
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

    # WHEN a traces exporter is added to the config
    expected_traces_forwarding_cfg = {
        "endpoint": "http://192.168.1.244:4318",
        "retry_on_failure": {
            "max_elapsed_time": "5m",
        },
        "sending_queue": {"enabled": True, "queue_size": 1000, "storage": "file_storage"},
    }
    config_manager.add_traces_forwarding(
        endpoint="http://192.168.1.244:4318",
    )
    # THEN it exists in the traces exporter config
    config = dict(
        sorted(config_manager.config._config["exporters"]["otlphttp/send-traces"].items())
    )
    expected_config = dict(sorted(expected_traces_forwarding_cfg.items()))
    assert config == expected_config


def test_add_remote_write():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

    # WHEN a remote write exporter is added to the config
    expected_remote_write_cfg = {
        "endpoint": "http://192.168.1.244/cos-prometheus-0/api/v1/write",
        "tls": {
            "insecure_skip_verify": True,
        },
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


def test_add_otlp_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager(
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

    # WHEN an OTLP exporters (of gRPC and HTTP protocols) are added to the config
    config_manager.add_otlp_forwarding(
        {
            "0": OtlpEndpoint(**{"protocol": "grpc", "endpoint": "http://host-1:grpc-port", "telemetries": ["logs"]}),
            "1": OtlpEndpoint(**{"protocol": "http", "endpoint": "http://host-2:http-port", "telemetries": ["metrics", "traces"]}),
        }
    )

    # THEN they exists in the exporter config
    # AND the grpc protocol created an "otlp" exporter, while the "http" protocol created an
    # "otlphttp" exporter
    # TODO: This test is duplicating test_otlp Scenario test
    expected_otlp_cfg = {
        "otlp/rel-0": {"endpoint": "http://host-1:grpc-port", "tls": {"insecure": True}},
        "otlphttp/rel-1": {"endpoint": "http://host-2:http-port", "tls": {"insecure": True}},
    }
    assert config_manager.config._config["exporters"] == expected_otlp_cfg
