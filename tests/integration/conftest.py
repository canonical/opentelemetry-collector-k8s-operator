#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for integration tests."""

import functools
import glob
import logging
import os
import sh
from collections import defaultdict
from datetime import datetime
from typing import Dict

import pytest
import yaml
import jubilant

logger = logging.getLogger(__name__)

store = defaultdict(str)


def timed_memoizer(func):
    """Cache the result of a function."""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        fname = func.__qualname__
        logger.info("Started: %s" % fname)
        start_time = datetime.now()
        if fname in store.keys():
            ret = store[fname]
        else:
            logger.info("Return for {} not cached".format(fname))
            ret = await func(*args, **kwargs)
            store[fname] = ret
        logger.info("Finished: {} in: {} seconds".format(fname, datetime.now() - start_time))
        return ret

    return wrapper


@pytest.fixture(scope="module")
@timed_memoizer
async def charm() -> str:
    """Charm used for integration testing."""
    if charm_file := os.environ.get("CHARM_PATH"):
        charm = str(charm_file)
        return charm

    # Build charm
    # although charmcraft packs the charm, sh returns an empty string.
    sh.charmcraft.pack()  # type: ignore

    # Find the charm file
    current_dir = os.getcwd()
    charms = glob.glob(os.path.join(current_dir, "*.charm"))
    charm = charms[0]
    assert charm
    return charm


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
