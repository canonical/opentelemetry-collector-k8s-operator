#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Opentelemetry-collector config builder."""

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


def test_default_rendered_config_is_valid():
    # GIVEN a default config
    # WHEN the config is rendered
    cfg = yaml.safe_load(Config.default_config().yaml)
    # THEN a debug exporter is added for each pipeline missing one
    pipelines = [cfg["service"]["pipelines"][p] for p in cfg["service"]["pipelines"]]
    pairs = [(len(p["receivers"]) > 0, len(p["exporters"]) > 0) for p in pipelines]
    # AND each pipeline has at least one receiver-exporter pair
    assert all(all(condition for condition in pair) for pair in pairs)
