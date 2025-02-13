# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import pytest

from src.config import ConfigManager


@pytest.mark.parametrize("pipeline_component", ("receiver", "exporter", "connector", "processor"))
def test_add_pipeline_component(pipeline_component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    method_name = f"add_{pipeline_component}"
    cfg_mgr = ConfigManager()
    # GIVEN a default ConfigManager
    callable_method = getattr(cfg_mgr, method_name)  # Dynamically get the method from the object
    # WHEN adding a pipeline component with a nested config
    sample_config = {"a": {"b": "c"}}
    cfg_mgr = callable_method("foo", sample_config)  # Execute the method
    # THEN the nested config is added to the ConfigManager's config
    assert "foo" in cfg_mgr._config[f"{pipeline_component}s"]
    assert sample_config == cfg_mgr._config[f"{pipeline_component}s"]["foo"]


@pytest.mark.parametrize("pipeline", ("logs", "metrics", "traces"))
@pytest.mark.parametrize("pipeline_component", ("receiver", "exporter", "connector", "processor"))
def test_add_to_pipeline_component(pipeline, pipeline_component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    # GIVEN a default ConfigManager
    cfg_mgr = ConfigManager()
    # WHEN adding a pipeline component
    cfg_mgr = cfg_mgr.add_to_pipeline_component("foo", [pipeline], f"{pipeline_component}s")
    # THEN the pipeline component is added to the ConfigManager's pipeline config
    assert "foo" in cfg_mgr._config["service"]["pipelines"][pipeline][f"{pipeline_component}s"]


@pytest.mark.parametrize("pipeline", ("logs", "metrics", "traces"))
def test_add_pipeline(pipeline):
    # GIVEN a default ConfigManager
    cfg_mgr = ConfigManager()
    # WHEN adding a pipeline with a config
    sample_config = {
        "receivers": ["a"],
        "exporters": ["b"],
        "connectors": ["c"],
        "processors": ["d"],
    }
    cfg_mgr = cfg_mgr.add_pipeline(pipeline, sample_config)
    # THEN the pipeline is added to the ConfigManager's pipeline config
    assert sample_config == cfg_mgr._config["service"]["pipelines"][pipeline]


def test_add_extension():
    # GIVEN a default ConfigManager
    cfg_mgr = ConfigManager()
    # WHEN adding a pipeline with a config
    sample_config = {"a": {"b": "c"}}
    cfg_mgr = cfg_mgr.add_extension("foo", sample_config)
    # THEN the pipeline is added to the ConfigManager's pipeline config
    assert "foo" in cfg_mgr._config["service"]["extensions"]
    assert sample_config == cfg_mgr._config["extensions"]["foo"]


def test_add_scrape_job():
    # GIVEN a default ConfigManager
    cfg_mgr = ConfigManager()
    # WHEN adding a scrape job config
    sample_config = {
        "job_name": "foo",
        "metrics_path": "/metrics",
        "relabel_configs": [{}],
        "static_configs": [{}],
    }
    cfg_mgr = cfg_mgr.add_scrape_job(sample_config)
    # THEN the scrape job is added to the ConfigManager's prometheus:receiver:scrape_configs
    assert [sample_config] == cfg_mgr._config["receivers"]["prometheus"]["config"][
        "scrape_configs"
    ]
    # AND add another scrape job
    cfg_mgr = cfg_mgr.add_scrape_job(sample_config)
    # THEN both scrape jobs exist in the ConfigManager's prometheus:receiver:scrape_configs
    assert [sample_config, sample_config] == cfg_mgr._config["receivers"]["prometheus"]["config"][
        "scrape_configs"
    ]
