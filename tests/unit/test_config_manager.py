# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import pytest

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
    # GIVEN a default Config
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
    # AND the pipelines are added to the services:pipelines config if specified
    for pipeline in pipelines:
        assert "foo" in cfg._config["service"]["pipelines"][pipeline][category]


@pytest.mark.parametrize("pipelines", ([], ["logs", "metrics", "traces"]))
@pytest.mark.parametrize("pipeline_component", ("receiver", "exporter", "connector", "processor"))
def test_add_to_pipeline(pipelines, pipeline_component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    category = f"{pipeline_component}s"
    # GIVEN a default Config
    cfg = Config()
    # WHEN adding a pipeline component
    cfg._add_to_pipeline("foo", category, pipelines)
    # THEN the pipeline component is added to the pipeline config
    if not pipelines:
        assert not cfg._config["service"]["pipelines"]
    for pipeline in pipelines:
        assert "foo" in cfg._config["service"]["pipelines"][pipeline][category]


def test_add_extension():
    # GIVEN a default Config
    cfg = Config()
    # WHEN adding a pipeline with a config
    sample_config = {"a": {"b": "c"}}
    cfg.add_extension("foo", sample_config)
    # THEN the extension is added to the top-level extensions config
    assert sample_config == cfg._config["extensions"]["foo"]
    # AND the extension is added to the services:extensions config
    assert "foo" in cfg._config["service"]["extensions"]


def test_add_scrape_job():
    # GIVEN a default Config
    cfg = Config()
    # WHEN adding a scrape job config
    sample_config = {
        "job_name": "foo",
        "metrics_path": "/metrics",
        "relabel_configs": [{}],
        "static_configs": [{}],
    }
    cfg.add_scrape_job(sample_config)
    # THEN the scrape job is added to the prometheus:receiver:scrape_configs
    assert [sample_config] == cfg._config["receivers"]["prometheus"]["config"][
        "scrape_configs"
    ]
    # AND add another scrape job
    cfg.add_scrape_job(sample_config)
    # THEN both scrape jobs exist in the prometheus:receiver:scrape_configs
    assert [sample_config, sample_config] == cfg._config["receivers"]["prometheus"]["config"][
        "scrape_configs"
    ]
