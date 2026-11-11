# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: otelcol always protects itself from running out of memory."""

import warnings

import pytest
import yaml
from helpers import get_otelcol_file
from ops import BlockedStatus
from ops.testing import Container, Mount, Relation, State

from config_manager import ConfigManager
from constants import CONFIG_PATH
from utils import MemoryDetectionError, quantity_to_mib


def _limiters(config: dict) -> dict:
    """Return the memory_limiter processors of an otelcol config, by name."""
    return {
        name: conf
        for name, conf in config["processors"].items()
        if name.split("/")[0] == "memory_limiter"
    }


def _limit_mib(config: dict) -> int:
    """Return the limit of the one and only memory_limiter of an otelcol config."""
    (limiter,) = _limiters(config).values()
    return limiter["limit_mib"]


@pytest.mark.parametrize(
    "memory, mib",
    [
        ("1Gi", 1024),
        ("512Mi", 512),
        ("1G", 953),  # 10^9 bytes, rounded down to whole MiB
        ("500M", 476),
        ("0.8Gi", 819),
        ("858993459200m", 819),  # 0.8Gi, as K8s normalizes it
    ],
)
def test_memory_quantity_is_converted_to_mib(memory, mib):
    # GIVEN a K8s memory quantity
    # WHEN converting it to MiB
    # THEN it is rounded down to whole MiB
    assert quantity_to_mib(memory) == mib


@pytest.mark.parametrize("memory", ["abc", "1 Gi", "-1Gi", "0", "512Ki"])
def test_invalid_memory_quantity_is_rejected(memory):
    # GIVEN something that is not a K8s quantity, or that is less than 1 MiB
    # WHEN converting it to MiB
    # THEN it is rejected
    with pytest.raises(ValueError):
        quantity_to_mib(memory)


@pytest.mark.parametrize("total_mib", [1024, 4096])
def test_limit_is_80_percent_of_the_memory(config_manager: ConfigManager, total_mib):
    # GIVEN the memory available to otelcol
    # WHEN adding the default memory limiter
    config_manager.add_default_memory_limiter(total_mib)
    # THEN its limit is 80% of that memory
    built = yaml.safe_load(config_manager.config.build())
    assert _limit_mib(built) == int(0.8 * total_mib)


def test_limit_is_never_zero(config_manager: ConfigManager):
    # GIVEN so little memory that 80% of it is less than 1 MiB
    # WHEN adding the default memory limiter
    config_manager.add_default_memory_limiter(1)
    # THEN the limit is still positive, as the processor requires
    built = yaml.safe_load(config_manager.config.build())
    assert _limit_mib(built) == 1


@pytest.mark.parametrize("name", ["memory_limiter", "memory_limiter/mine"])
def test_custom_memory_limiter_replaces_the_default(config_manager: ConfigManager, name):
    # GIVEN a memory limiter in the processors config option
    config_manager.add_custom_processors(yaml.safe_dump({name: {"limit_mib": 4000}}))
    # WHEN adding the default memory limiter
    config_manager.add_default_memory_limiter(1024)
    # THEN only the custom one is rendered
    built = yaml.safe_load(config_manager.config.build())
    assert _limit_mib(built) == 4000


def test_limiter_is_the_first_processor_of_every_pipeline(config_manager: ConfigManager):
    # GIVEN custom processors, and the default limiter added after them
    config_manager.add_custom_processors(yaml.safe_dump({"batch": {}}))
    config_manager.add_default_memory_limiter(1024)
    # WHEN the config is built
    built = yaml.safe_load(config_manager.config.build())
    # THEN every pipeline starts with the limiter, ahead of the other processors
    pipelines = built["service"]["pipelines"]
    assert pipelines
    for name, pipeline in pipelines.items():
        processors = pipeline["processors"]
        assert len(processors) > 1, f"pipeline '{name}' has no other processor than the limiter"
        assert processors[0].split("/")[0] == "memory_limiter", (
            f"the first processor of pipeline '{name}' must be 'memory_limiter'"
        )


def test_custom_memory_limiter_is_the_first_processor_of_every_pipeline(
    config_manager: ConfigManager,
):
    # GIVEN a memory limiter in the processors config option, listed after another processor
    config_manager.add_custom_processors(
        yaml.safe_dump({"batch": {}, "memory_limiter": {"limit_mib": 4000}})
    )
    # WHEN the config is built
    built = yaml.safe_load(config_manager.config.build())
    # THEN every pipeline starts with the limiter
    for name, pipeline in built["service"]["pipelines"].items():
        processors = pipeline["processors"]
        assert len(processors) > 1, f"pipeline '{name}' has no other processor than the limiter"
        assert processors[0].split("/")[0] == "memory_limiter", (
            f"the first processor of pipeline '{name}' must be 'memory_limiter'"
        )


def test_limiter_is_added_to_the_profiles_pipeline_when_configured(
    config_manager: ConfigManager,
):
    # GIVEN a profiles pipeline, and custom processors, which do not apply to profiles
    config_manager.add_profile_ingestion()
    config_manager.add_custom_processors(yaml.safe_dump({"batch": {}}))
    # WHEN adding the default memory limiter
    config_manager.add_default_memory_limiter(1024, profiles=True)
    # THEN the profiles pipeline starts with the limiter
    built = yaml.safe_load(config_manager.config.build())
    processors = built["service"]["pipelines"]["profiles/test/0"]["processors"]
    assert processors[0].split("/")[0] == "memory_limiter"


def test_no_profiles_pipeline_is_created_for_the_limiter(config_manager: ConfigManager):
    # GIVEN no profiles pipeline
    # WHEN adding the default memory limiter
    config_manager.add_default_memory_limiter(1024)
    # THEN no pipeline is created for profiles
    built = yaml.safe_load(config_manager.config.build())
    assert not any(name.startswith("profiles/") for name in built["service"]["pipelines"])


def test_charm_limits_memory_to_what_the_container_has(ctx, otelcol_container, container_memory):
    # GIVEN a charm without memory config, whose workload container has 2048 MiB
    container_memory.return_value = 2048
    state_in = State(containers=otelcol_container)
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the memory limiter is the first processor of every pipeline, with 80% of that memory
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert _limit_mib(cfg) == int(0.8 * 2048)
    for pipeline in cfg["service"]["pipelines"].values():
        assert pipeline["processors"][0].split("/")[0] == "memory_limiter"


def test_memory_config_takes_precedence_over_the_container_memory(
    ctx, otelcol_container, container_memory
):
    # GIVEN a memory config, and a workload container with a different amount of memory
    container_memory.return_value = 2048
    state_in = State(containers=otelcol_container, config={"memory": "1Gi"})
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the limit is based on the memory config
    assert _limit_mib(get_otelcol_file(state_out, ctx, CONFIG_PATH)) == int(0.8 * 1024)
    assert not isinstance(state_out.unit_status, BlockedStatus)


def test_invalid_memory_config_blocks_the_charm(ctx, otelcol_container, container_memory):
    # GIVEN an invalid memory config
    container_memory.return_value = 2048
    state_in = State(containers=otelcol_container, config={"memory": "lots"})
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the unit is blocked
    assert isinstance(state_out.unit_status, BlockedStatus)
    # AND otelcol still runs, with a limit based on the memory of its container
    assert _limit_mib(get_otelcol_file(state_out, ctx, CONFIG_PATH)) == int(0.8 * 2048)


def test_memory_config_is_capped_to_the_container_memory(ctx, otelcol_container, container_memory):
    # GIVEN a memory config higher than the memory of the workload container
    container_memory.return_value = 512
    state_in = State(containers=otelcol_container, config={"memory": "1Gi"})
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the limit is based on the memory of the container
    assert _limit_mib(get_otelcol_file(state_out, ctx, CONFIG_PATH)) == int(0.8 * 512)
    assert not isinstance(state_out.unit_status, BlockedStatus)


def test_undetectable_memory_blocks_the_charm(ctx, otelcol_container, container_memory):
    # GIVEN a workload container whose memory cannot be detected
    container_memory.side_effect = MemoryDetectionError("no way")
    state_in = State(containers=otelcol_container)
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the unit is blocked, rather than erroring out
    assert isinstance(state_out.unit_status, BlockedStatus)
    # AND otelcol still runs, without the default limiter
    assert not _limiters(get_otelcol_file(state_out, ctx, CONFIG_PATH))


def test_memory_config_is_used_if_the_container_memory_is_undetectable(
    ctx, otelcol_container, container_memory
):
    # GIVEN a memory config, and a workload container whose memory cannot be detected
    container_memory.side_effect = MemoryDetectionError("no way")
    state_in = State(containers=otelcol_container, config={"memory": "1Gi"})
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the limit is based on the memory config
    assert _limit_mib(get_otelcol_file(state_out, ctx, CONFIG_PATH)) == int(0.8 * 1024)
    assert not isinstance(state_out.unit_status, BlockedStatus)


@pytest.fixture
def container_with_files(execs, tmp_path):
    """A workload container whose /sys/fs/cgroup and /proc contain the given files."""

    def make(cgroup_memory_max=None, meminfo=None) -> Container:
        mounts = {}
        for location, files in (
            ("/sys/fs/cgroup", {"memory.max": cgroup_memory_max}),
            ("/proc", {"meminfo": meminfo}),
        ):
            source = tmp_path / location.strip("/").replace("/", "-")
            source.mkdir()
            for name, content in files.items():
                if content is not None:
                    (source / name).write_text(content)
            mounts[source.name] = Mount(location=location, source=source)
        return Container("otelcol", can_connect=True, execs=execs, mounts=mounts)

    return make


NODE_MEMINFO = "MemTotal:        4194304 kB\nMemFree:         1000000 kB\n"


@pytest.mark.parametrize(
    "cgroup_memory_max, expected_mib",
    [
        # A container with a limit: that limit
        ("536870912\n", 512),
        # A container without a limit, or on a node with cgroup v1: the memory of the node
        ("max\n", 4096),
        (None, 4096),
    ],
)
@pytest.mark.real_container_memory
def test_container_memory_is_read_from_the_container(
    ctx, container_with_files, cgroup_memory_max, expected_mib
):
    # GIVEN a workload container with the given cgroup memory limit, on a node with 4096 MiB
    container = container_with_files(cgroup_memory_max, NODE_MEMINFO)
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), State(containers=[container]))
    # THEN the limit is based on the memory of the container
    assert _limit_mib(get_otelcol_file(state_out, ctx, CONFIG_PATH)) == int(0.8 * expected_mib)


def test_cpu_config_is_deprecated_and_ignored(ctx, otelcol_container):
    # GIVEN a charm with the deprecated cpu config
    state_in = State(containers=otelcol_container, config={"cpu": "1"})
    # WHEN the config changes
    # THEN the charm warns that the option is deprecated
    with pytest.warns(DeprecationWarning, match="'cpu'"):
        state_out = ctx.run(ctx.on.config_changed(), state_in)
    # AND otelcol is running, unaffected
    assert not isinstance(state_out.unit_status, BlockedStatus)
    assert state_out.get_container("otelcol").services["otelcol"].is_running()


def test_cpu_config_warning_is_only_for_config_changes(ctx, otelcol_container):
    # GIVEN a charm with the deprecated cpu config
    state_in = State(containers=otelcol_container, config={"cpu": "1"})
    # WHEN any other event executes the reconciler
    # THEN the charm does not warn about it again
    with warnings.catch_warnings():
        warnings.filterwarnings("error", message=".*'cpu'", category=DeprecationWarning)
        ctx.run(ctx.on.update_status(), state_in)


def test_invalid_memory_config_is_reported_along_with_other_blocked_reasons(
    ctx, otelcol_container, container_memory
):
    # GIVEN an invalid memory config, and a source relation without a sink
    container_memory.return_value = 2048
    state_in = State(
        containers=otelcol_container,
        config={"memory": "lots"},
        relations=[Relation("metrics-endpoint")],
    )
    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN the status reports both reasons
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert "Invalid memory config value" in state_out.unit_status.message
    assert "] for metrics-endpoint" in state_out.unit_status.message
