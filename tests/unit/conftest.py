#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for unit tests."""

import pytest
from config import ConfigManager, DEFAULT_CONFIG
import copy


@pytest.fixture
def default_config_mgr():
    yield ConfigManager()
    ConfigManager._config = copy.deepcopy(DEFAULT_CONFIG)
