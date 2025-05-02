#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for integration tests."""

import functools
import logging
import os
from collections import defaultdict
from datetime import datetime
from typing import Dict

import pytest
import yaml
from pytest_jubilant import pack_charm

logger = logging.getLogger(__name__)

store = defaultdict(str)


# TODO Luca: do we need this since CI only packs once and in local testing ...
def timed_memoizer(func):
    """Cache the result of a function."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        fname = func.__qualname__
        logger.info("Started: %s" % fname)
        start_time = datetime.now()
        if fname in store.keys():
            ret = store[fname]
        else:
            logger.info("Return for {} not cached".format(fname))
            ret = func(*args, **kwargs)
            store[fname] = ret
        logger.info("Finished: {} in: {} seconds".format(fname, datetime.now() - start_time))
        return ret

    return wrapper


@pytest.fixture(scope="module")
@timed_memoizer
def charm():
    """Charm used for integration testing."""
    if charm_file := os.environ.get("CHARM_PATH"):
        return str(charm_file), None

    result = pack_charm()
    return str(result.charm)


@pytest.fixture(scope="module")
def charm_resources(metadata_file="charmcraft.yaml") -> Dict[str, str]:
    with open(metadata_file, "r") as file:
        metadata = yaml.safe_load(file)
    resources = {}
    for res, data in metadata["resources"].items():
        resources[res] = data["upstream-source"]
    return resources
