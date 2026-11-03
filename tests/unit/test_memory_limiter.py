# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: otelcol always protects itself from running out of memory."""

import logging

import pytest
import yaml
from helpers import get_otelcol_file
from ops import BlockedStatus
from ops.testing import State

from config_manager import ConfigManager, memory_limiter_mib
from constants import CONFIG_PATH


def _limiter_configs(config: dict) -> dict:
    return {
        name: conf
        for name, conf in config["processors"].items()
        if name.split("/")[0] == "memory_limiter"
    }


@pytest.mark.parametrize(
    "memory, expected",
    [
        ("1Gi", (819, 204)),
        ("512Mi", (409, 102)),
        ("1G", (762, 190)),  # decimal gigabyte
        ("500M", (381, 95)),
        ("0.8Gi", (655, 163)),  # a fractional quantity, as K8s normalizes it: 858993459200m
        ("858993459200m", (655, 163)),
    ],
)
def test_limits_are_a_percentage_of_the_memory_quantity(memory, expected):
    # GIVEN a K8s memory quantity
    # WHEN converting it to memory_limiter limits
    # THEN the hard limit is 80%, and the spike is 20%, rounded down to whole MiB
    assert memory_limiter_mib(memory) == expected


@pytest.mark.parametrize("memory", ["abc", "1 Gi", "-1Gi", "0", "1Ki"])
def test_unusable_memory_quantity_is_rejected(memory):
    # GIVEN a value that is not a K8s quantity, or that is not a usable amount of memory
    # WHEN converting it to memory_limiter limits
    # THEN it is rejected
    with pytest.raises(ValueError):
        memory_limiter_mib(memory)


def test_limiter_follows_the_cgroup_limit_when_memory_is_unset(config_manager: ConfigManager):
    # GIVEN no memory config
    # WHEN adding the default memory limiter
    valid = config_manager.add_default_memory_limiter(None)
    # THEN the limits are percentages, which otelcol resolves against its own cgroup limit
    built = yaml.safe_load(config_manager.config.build())
    assert valid
    assert list(_limiter_configs(built).values()) == [
        {"check_interval": "1s", "limit_percentage": 80, "spike_limit_percentage": 20}
    ]


def test_limiter_uses_the_memory_config(config_manager: ConfigManager):
    # GIVEN a memory config
    # WHEN adding the default memory limiter
    valid = config_manager.add_default_memory_limiter("1Gi")
    # THEN the limits are absolute
    built = yaml.safe_load(config_manager.config.build())
    assert valid
    assert list(_limiter_configs(built).values()) == [
        {"check_interval": "1s", "limit_mib": 819, "spike_limit_mib": 204}
    ]


def test_invalid_memory_config_falls_back_to_the_cgroup_limit(config_manager: ConfigManager):
    # GIVEN an invalid memory config
    # WHEN adding the default memory limiter
    valid = config_manager.add_default_memory_limiter("lots")
    # THEN the problem is reported to the caller
    assert not valid
    # AND otelcol is still protected, by percentage limits
    built = yaml.safe_load(config_manager.config.build())
    assert list(_limiter_configs(built).values()) == [
        {"check_interval": "1s", "limit_percentage": 80, "spike_limit_percentage": 20}
    ]


@pytest.mark.parametrize("name", ["memory_limiter", "memory_limiter/mine"])
def test_custom_memory_limiter_replaces_the_default(config_manager: ConfigManager, name):
    # GIVEN a memory limiter in the processors config option
    config_manager.add_custom_processors(yaml.safe_dump({name: {"limit_mib": 4000}}))
    # WHEN adding the default memory limiter
    valid = config_manager.add_default_memory_limiter("1Gi")
    # THEN only the custom one is rendered
    built = yaml.safe_load(config_manager.config.build())
    assert valid
    assert [c["limit_mib"] for c in _limiter_configs(built).values()] == [4000]


def test_limiter_is_the_first_processor_of_every_pipeline(config_manager: ConfigManager):
    # GIVEN custom processors, and the default limiter added after them
    config_manager.add_custom_processors(yaml.safe_dump({"batch": {}}))
    config_manager.add_default_memory_limiter(None)
    # WHEN the config is built
    built = yaml.safe_load(config_manager.config.build())
    # THEN every pipeline starts with the limiter, ahead of the other processors
    pipelines = built["service"]["pipelines"]
    assert pipelines
    for name, pipeline in pipelines.items():
        processors = pipeline["processors"]
        assert processors[0].split("/")[0] == "memory_limiter", name
        assert len(processors) > 1, name


def test_limiter_is_rendered_by_the_charm(ctx, otelcol_container):
    # GIVEN a charm without any memory or processors config
    state_in = State(containers=otelcol_container)
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the default limiter is rendered
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert len(_limiter_configs(cfg)) == 1
    # AND is the first processor of every pipeline that has any
    for pipeline in cfg["service"]["pipelines"].values():
        if pipeline.get("processors"):
            assert pipeline["processors"][0].split("/")[0] == "memory_limiter"


def test_invalid_memory_config_blocks_the_charm(ctx, otelcol_container):
    # GIVEN an invalid memory config
    state_in = State(containers=otelcol_container, config={"memory": "lots"})
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the unit is blocked
    assert isinstance(state_out.unit_status, BlockedStatus)
    # AND otelcol is still running with a limiter
    assert len(_limiter_configs(get_otelcol_file(state_out, ctx, CONFIG_PATH))) == 1


def test_cpu_config_is_deprecated_and_ignored(ctx, otelcol_container, caplog):
    # GIVEN a charm with the deprecated cpu config
    state_in = State(containers=otelcol_container, config={"cpu": "1"})
    # WHEN any event executes the reconciler
    with caplog.at_level(logging.WARNING):
        state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the charm warns that the option does nothing
    assert any(r.levelno == logging.WARNING and "'cpu'" in r.getMessage() for r in caplog.records)
    # AND is not otherwise affected
    assert not isinstance(state_out.unit_status, BlockedStatus)
    get_otelcol_file(state_out, ctx, CONFIG_PATH)
