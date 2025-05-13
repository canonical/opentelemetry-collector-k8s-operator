#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for integration tests."""

import logging
import os
import subprocess
from collections import defaultdict
from typing import Dict

import pytest
import yaml
from pytest_jubilant import pack_charm

logger = logging.getLogger(__name__)

store = defaultdict(str)


# pytest-jubilant has a module-level fixture which replaces the need for creating a jubilant fixture

@pytest.fixture(scope="module")
def charm() -> str:
    """Charm used for integration testing."""
    if charm_file := os.environ.get("CHARM_PATH"):
        return str(charm_file)

    # Intermittent issue where charmcraft fails to build the charm for an unknown reason.
    # Retry building the charm
    for _ in range(2):
        logger.info("packing...")
        try:
            pth = str(pack_charm().charm.absolute())
        except subprocess.CalledProcessError:
            logger.warning("Failed to build charm. Trying again!")
            continue
        os.environ["CHARM_PATH"] = pth
        return pth
    raise RuntimeError("Failed to build the charm after 2 attempts.")


@pytest.fixture(scope="module")
def charm_resources(metadata_file="charmcraft.yaml") -> Dict[str, str]:
    # TODO pytest_jubilant.pack_charm has a `resources` attribute we can use
    with open(metadata_file, "r") as file:
        metadata = yaml.safe_load(file)
    resources = {}
    for res, data in metadata["resources"].items():
        resources[res] = data["upstream-source"]
    return resources
