# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

from config_manager import ConfigManager


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


def test_add_syslog_forwarding_single_endpoint():
    """Test configuring a single syslog endpoint with plaintext TCP."""
    from unittest.mock import MagicMock

    # GIVEN an empty config and mock charm/container
    config_manager = ConfigManager(
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )
    mock_charm = MagicMock()
    mock_container = MagicMock()

    # WHEN a single syslog exporter is added to the config
    config_manager.add_syslog_forwarding(
        endpoints=[
            {
                "endpoint": "rsyslog.example.com:514",
                "protocol": "rfc5424",
                "network": "tcp",
                "tls_enabled": False,
            }
        ],
        charm=mock_charm,
        container=mock_container,
    )

    # THEN the syslog exporter exists in the config
    assert "syslog/send-syslog/0" in config_manager.config._config["exporters"]
    exporter_config = config_manager.config._config["exporters"]["syslog/send-syslog/0"]

    # AND endpoint is split into host and port (syslog exporter requirement)
    assert exporter_config["endpoint"] == "rsyslog.example.com"
    assert exporter_config["port"] == 514
    assert exporter_config["protocol"] == "rfc5424"
    assert exporter_config["network"] == "tcp"

    # AND TLS is explicitly disabled for plaintext
    assert exporter_config["tls"] == {"insecure": True}

    # AND retry/queue settings are configured
    assert exporter_config["retry_on_failure"]["max_elapsed_time"] == "5m"
    assert exporter_config["sending_queue"]["enabled"] is True

    # AND the transform processor is added for OTLP → syslog field mapping
    assert "transform/prepare-for-syslog" in config_manager.config._config["processors"]


def test_add_syslog_forwarding_multiple_endpoints():
    """Test configuring multiple syslog endpoints."""
    from unittest.mock import MagicMock

    # GIVEN an empty config and mock charm/container
    config_manager = ConfigManager(
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )
    mock_charm = MagicMock()
    mock_container = MagicMock()

    # WHEN multiple syslog exporters are added to the config
    config_manager.add_syslog_forwarding(
        endpoints=[
            {
                "endpoint": "rsyslog1.example.com:514",
                "protocol": "rfc5424",
                "network": "tcp",
                "tls_enabled": False,
            },
            {
                "endpoint": "rsyslog2.example.com:6514",
                "protocol": "rfc5424",
                "network": "tcp",
                "tls_enabled": False,
            },
            {
                "endpoint": "rsyslog3.example.com:1514",
                "protocol": "rfc5424",
                "network": "tcp",
                "tls_enabled": False,
            },
        ],
        charm=mock_charm,
        container=mock_container,
    )

    # THEN all three syslog exporters exist in the config
    assert "syslog/send-syslog/0" in config_manager.config._config["exporters"]
    assert "syslog/send-syslog/1" in config_manager.config._config["exporters"]
    assert "syslog/send-syslog/2" in config_manager.config._config["exporters"]

    # AND each exporter has the correct host and port (separated)
    assert config_manager.config._config["exporters"]["syslog/send-syslog/0"]["endpoint"] == "rsyslog1.example.com"
    assert config_manager.config._config["exporters"]["syslog/send-syslog/0"]["port"] == 514

    assert config_manager.config._config["exporters"]["syslog/send-syslog/1"]["endpoint"] == "rsyslog2.example.com"
    assert config_manager.config._config["exporters"]["syslog/send-syslog/1"]["port"] == 6514

    assert config_manager.config._config["exporters"]["syslog/send-syslog/2"]["endpoint"] == "rsyslog3.example.com"
    assert config_manager.config._config["exporters"]["syslog/send-syslog/2"]["port"] == 1514


def test_add_syslog_forwarding_rfc3164_udp():
    """Test configuring legacy RFC3164 syslog with UDP transport."""
    from unittest.mock import MagicMock

    # GIVEN an empty config and mock charm/container
    config_manager = ConfigManager(
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )
    mock_charm = MagicMock()
    mock_container = MagicMock()

    # WHEN a syslog exporter is added with RFC3164 protocol and UDP network
    config_manager.add_syslog_forwarding(
        endpoints=[
            {
                "endpoint": "legacy-rsyslog.example.com:514",
                "protocol": "rfc3164",
                "network": "udp",
                "tls_enabled": False,
            }
        ],
        charm=mock_charm,
        container=mock_container,
    )

    # THEN the exporter has RFC3164 protocol and UDP network
    exporter_config = config_manager.config._config["exporters"]["syslog/send-syslog/0"]
    assert exporter_config["protocol"] == "rfc3164"
    assert exporter_config["network"] == "udp"
    assert exporter_config["endpoint"] == "legacy-rsyslog.example.com"
    assert exporter_config["port"] == 514
