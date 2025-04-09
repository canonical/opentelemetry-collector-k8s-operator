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
from pytest_operator.plugin import OpsTest
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
async def charm(ops_test: OpsTest) -> str:
    """Charm used for integration testing."""
    if charm_file := os.environ.get("CHARM_PATH"):
        return str(charm_file)

    charm = await ops_test.build_charm(".")
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


@pytest.fixture(scope='module')
def juju():
    with jubilant.temp_model() as juju:
        yield juju
