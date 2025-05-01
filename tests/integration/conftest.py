#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for integration tests."""

import functools
import logging
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import jubilant
import pytest
from pytest_jubilant import _Result, pack_charm

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
def packed_charm() -> _Result:
    """Charm used for integration testing."""
    if charm_file := os.environ.get("CHARM_PATH"):
        return str(charm_file)

    return pack_charm()


@pytest.fixture(scope="module")
def charm(packed_charm) -> Path:
    return packed_charm.charm


@pytest.fixture(scope="module")
def resources(packed_charm) -> Optional[Dict[str, str]]:
    return packed_charm.resources


# TODO The main purpose of pytest-jubilant is the Juju fixture, can comment fixture below
@pytest.fixture(scope="module")
def juju():
    keep_models: bool = os.environ.get("KEEP_MODELS") is not None
    with jubilant.temp_model(keep=keep_models) as juju:
        yield juju
