# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from config import Config
import pytest


@pytest.mark.parametrize("pipeline_component", ("receiver", "exporter", "connector", "processor"))
def test_add_pipeline_component(pipeline_component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    method_name = f"add_{pipeline_component}"
    # GIVEN a default Config object
    method = getattr(Config(), method_name)  # Get the add_* method and call it
    # WHEN adding an exporter with a nested config
    sample_config = {"a": {"b": "c"}}
    config = method("foo", sample_config)._config
    # THEN the nested config is added to the Config object's config
    assert "foo" in config[f"{pipeline_component}s"]
    assert sample_config == config[f"{pipeline_component}s"]["foo"]


@pytest.mark.parametrize("pipeline_component", ("receiver", "exporter", "connector", "processor"))
def test_add_pipeline_component_to_pipelines(pipeline_component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    method_name = f"add_{pipeline_component}"
    # GIVEN a default Config object
    method = getattr(Config(), method_name)  # Get the add_* method and call it
    # WHEN adding an exporter with a config and multiple pipelines
    sample_config = {"a": {"b": "c"}}
    config = method("foo", sample_config, pipelines=["logs", "metrics"])._config
    # THEN the config is added to the Config object's config
    assert "foo" in config[f"{pipeline_component}s"]
    # AND the config pipelines are updated
    for k, v in config["service"]["pipelines"].items():
        assert ["foo"] == v[f"{pipeline_component}s"]
