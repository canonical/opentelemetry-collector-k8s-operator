#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for integration tests."""

import logging
import os
import sh
from collections import defaultdict
from typing import Dict

import pytest
import yaml
import jubilant

logger = logging.getLogger(__name__)

store = defaultdict(str)


@pytest.fixture(scope="module")
def charm() -> str:
    """Charm used for integration testing."""
    if charm_file := os.environ.get("CHARM_PATH"):
        return str(charm_file)

    charm = sh.charmcraft.pack()  # type: ignore
    assert charm
    return str(charm)


@pytest.fixture(scope="module")
def charm_resources(metadata_file="charmcraft.yaml") -> Dict[str, str]:
    with open(metadata_file, "r") as file:
        metadata = yaml.safe_load(file)
    resources = {}
    for res, data in metadata["resources"].items():
        resources[res] = data["upstream-source"]
    return resources


@pytest.fixture(scope="module")
def juju():
    keep_models: bool = os.environ.get("KEEP_MODELS") is not None
    with jubilant.temp_model(keep=keep_models) as juju:
        yield juju
