#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for unit tests."""

import pytest
from config import ConfigManager


@pytest.fixture()
def default_config():
    return ConfigManager().default_config()._config
