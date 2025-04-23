# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

from copy import deepcopy

import pytest
import yaml

from src.config import Config


@pytest.mark.parametrize("pipelines", ([], ["logs", "metrics", "traces"]))
@pytest.mark.parametrize("pipeline_component", ("receiver", "exporter", "connector", "processor"))
def test_add_pipeline_component(pipelines, pipeline_component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    Pipeline names can follow the type[/name] format, valid for e.g. logs, metrics, traces, logs/2, ...

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    method_name = f"add_{pipeline_component}"
    category = f"{pipeline_component}s"
    # GIVEN an empty config
    cfg = Config()
    # WHEN adding a pipeline component with a nested config
    sample_config = {"a": {"b": "c"}}
    callable_method = getattr(cfg, method_name)  # Dynamically get the add_* method from Config
    callable_method("foo", sample_config, pipelines)  # Execute the add_* method
    # THEN the nested config is added to the config
    assert "foo" in cfg._config[category]
    assert sample_config == cfg._config[category]["foo"]
    # AND the pipeline is not added if none were specified
    if not pipelines:
        assert not cfg._config["service"]["pipelines"]
    # AND the pipelines are added to the service::pipelines config if specified
    for pipeline in pipelines:
        assert "foo" in cfg._config["service"]["pipelines"][pipeline][category]


@pytest.mark.parametrize("pipelines", ([], ["logs", "metrics", "traces"]))
@pytest.mark.parametrize("pipeline_component", ("receiver", "exporter", "connector", "processor"))
def test_add_to_pipeline(pipelines, pipeline_component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    category = f"{pipeline_component}s"
    # GIVEN an empty config
    cfg = Config()
    # WHEN adding a pipeline component
    cfg._add_to_pipeline("foo", category, pipelines)
    # THEN the pipeline component is added to the pipeline config
    if not pipelines:
        assert not cfg._config["service"]["pipelines"]
    for pipeline in pipelines:
        assert "foo" in cfg._config["service"]["pipelines"][pipeline][category]


def test_add_extension():
    # GIVEN an empty config
    cfg = Config()
    # WHEN adding a pipeline with a config
    sample_config = {"a": {"b": "c"}}
    cfg.add_extension("foo", sample_config)
    # THEN the extension is added to the top-level extensions config
    assert sample_config == cfg._config["extensions"]["foo"]
    # AND the extension is added to the service::extensions config
    assert "foo" in cfg._config["service"]["extensions"]


def test_add_telemetry():
    # GIVEN an empty config
    cfg = Config()
    # WHEN adding a pipeline with a config
    sample_config = [{"a": {"b": "c"}}]
    cfg.add_telemetry("logs", {"level": "INFO"})
    cfg.add_telemetry("metrics", {"level": "normal"})
    cfg.add_telemetry("metrics", {"some_config": sample_config})
    # THEN the respective telemetry sections are added to the service::telemetry config
    assert ["logs", "metrics"] == list(cfg._config["service"]["telemetry"].keys())
    # AND the telemetry is added to the service::telemetry config
    assert cfg._config["service"]["telemetry"]["metrics"] == {"some_config": sample_config}
    assert cfg._config["service"]["telemetry"]["logs"] == {"level": "INFO"}


def test_add_prometheus_scrape():
    # GIVEN an empty config
    cfg = Config()
    # WHEN attempting to add scrape jobs without incoming metrics
    cfg.add_prometheus_scrape([{"foo": "bar"}], incoming_metrics=False)
    # THEN the prometheus receiver config is not added (or updated if existing config)
    with pytest.raises(KeyError):
        cfg._config["receivers"]["prometheus"]

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
                    # Added by add_prometheus_scrape
                    "tls_config": {"insecure_skip_verify": True},
                },
            ],
        }
    }
    cfg.add_prometheus_scrape(first_job, True, insecure_skip_verify=True)
    # THEN it exists in the prometheus receiver config
    # AND insecure_skip_verify is injected into the config
    assert cfg._config["receivers"]["prometheus"] == expected_prom_recv_cfg

    # WHEN more scrape jobs are added to the config
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
    cfg.add_prometheus_scrape(more_jobs, True)
    # THEN the original scrape job wasn't overwritten and the newly added scrape jobs were added
    job_names = [
        job["job_name"]
        for job in cfg._config["receivers"]["prometheus"]["config"]["scrape_configs"]
    ]
    assert job_names == ["first_job", "second_job", "third_job"]


def test_rendered_default_is_valid():
    # GIVEN a default config
    # WHEN the config is rendered
    cfg = yaml.safe_load(Config.default_config().yaml)
    # THEN a debug exporter is added for each pipeline missing one
    pipelines = [cfg["service"]["pipelines"][p] for p in cfg["service"]["pipelines"]]
    pairs = [(len(p["receivers"]) > 0, len(p["exporters"]) > 0) for p in pipelines]
    # AND each pipeline has at least one receiver-exporter pair
    assert all(all(condition for condition in pair) for pair in pairs)


def test_insecure_skip_verify():
    # GIVEN an empty config without exporters
    cfg = Config()
    cfg_copy = deepcopy(cfg)
    # WHEN updating the tls::insecure_skip_verify exporter configuration
    config_dict = cfg.add_exporter_insecure_skip_verify(cfg._config, False)
    # THEN it has no effect on the rendered config
    assert config_dict == cfg_copy._config
    # WHEN multiple exporters are added
    cfg.add_exporter("foo", {"endpoint": "foo"})
    cfg.add_exporter(
        "bar",
        {
            "endpoint": "bar",
            "tls": {"insecure_skip_verify": True},
        },
    )
    # AND the tls::insecure_skip_verify configuration is added
    config_dict = cfg.add_exporter_insecure_skip_verify(cfg._config, False)
    # THEN tls::insecure_skip_verify is set for each exporter which was missing this configuration
    assert config_dict["exporters"]["foo"]["tls"]["insecure_skip_verify"] is False
    # AND any existing tls::insecure_skip_verify configuration is untouched
    assert config_dict["exporters"]["bar"]["tls"]["insecure_skip_verify"] is True


def test_debug_exporter_no_tls_config():
    # GIVEN an empty config without exporters
    cfg = Config()
    # WHEN multiple debug exporters are added
    cfg.add_exporter("debug", {"config": {"foo": "bar"}})
    cfg.add_exporter("debug/descriptor", {"config": {"foo": "bar"}})
    # AND the tls::insecure_skip_verify configuration is added
    config_dict = cfg.add_exporter_insecure_skip_verify(cfg._config, True)
    # THEN tls::insecure_skip_verify is not set for debug exporters
    assert all("tls" not in exp.keys() for exp in config_dict["exporters"].values())
