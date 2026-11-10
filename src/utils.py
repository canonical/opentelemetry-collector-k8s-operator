# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions to work out how much memory otelcol has."""

import logging
import re

from charmlibs.pathops import ContainerPath
from lightkube.utils.quantity import parse_quantity
from ops import Container, pebble

logger = logging.getLogger(__name__)

_BYTES_PER_MIB = 1024 * 1024
CGROUP_MEMORY_MAX_PATH = "/sys/fs/cgroup/memory.max"
MEMINFO_PATH = "/proc/meminfo"


class MemoryDetectionError(Exception):
    """Raised when the memory available to a workload container cannot be determined."""


def quantity_to_mib(memory: str) -> int:
    """Convert a K8s memory quantity, such as "1Gi" or "500M", to whole MiB.

    Raises:
        ValueError: if `memory` is not a K8s quantity, or is less than 1 MiB.
    """
    quantity = parse_quantity(memory)
    if quantity is None or quantity < _BYTES_PER_MIB:
        raise ValueError(f"'{memory}' is not a memory quantity of at least 1 MiB.")
    return int(quantity // _BYTES_PER_MIB)


def container_memory_mib(container: Container) -> int:
    """Return the memory available to the processes of a workload container, in MiB.

    This is the memory limit of the container, as set by the Juju `mem` constraint. If the
    container has no limit, which is the case unless a constraint was set, this is the memory of
    the whole node.

    Only cgroup v2 is supported, as Kubernetes has deprecated cgroup v1.

    Raises:
        MemoryDetectionError: if neither the limit of the container nor the memory of the node
            can be read.
    """
    try:
        limit = ContainerPath(CGROUP_MEMORY_MAX_PATH, container=container).read_text().strip()
        if limit != "max":
            return int(limit) // _BYTES_PER_MIB
        logger.warning(
            "The workload container has no memory limit, so the memory of the whole node is used. "
            "Set one with `juju deploy --constraints mem=<size>`."
        )
    except (OSError, ValueError, pebble.ConnectionError) as e:
        logger.warning(
            "Cannot read the memory limit of the workload container from %s (cgroup v2 is "
            "required), so the memory of the whole node is used: %s",
            CGROUP_MEMORY_MAX_PATH,
            e,
        )
    # Unlike the cgroup limit, /proc/meminfo is not namespaced: it is the memory of the node.
    try:
        meminfo = ContainerPath(MEMINFO_PATH, container=container).read_text()
    except (OSError, pebble.ConnectionError) as e:
        raise MemoryDetectionError(f"Cannot read {MEMINFO_PATH}: {e}") from e
    match = re.search(r"^MemTotal:\s+(\d+) kB$", meminfo, re.MULTILINE)
    if not match:
        raise MemoryDetectionError(f"No MemTotal in {MEMINFO_PATH}.")
    return int(match.group(1)) // 1024
