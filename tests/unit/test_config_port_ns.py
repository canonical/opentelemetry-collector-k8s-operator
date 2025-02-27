#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
# TODO Update this summary
"""Feature: Opentelemetry-collector exposes ports dynamically.

Scenario: Add/remove a port to/from the config
    When the otelcol config has a port defined in the config
    Then the ports exposed on the charm unit should contain only those in the config
"""

import pytest
from src.config import PortNamespace

PORTS = PortNamespace(
    FOO=1,
    BAR=2,
)


def test_get_value_raises():
    # GIVEN no ports were previously configured
    PORTS.clear_ports()
    # WHEN trying to retrieve the value for an attribute that does not exist
    # THEN a KeyError is raised
    with pytest.raises(KeyError):
        PORTS.get_value("NOT_AN_ATTRIBUTE")


def test_incorrect_attribute():
    # GIVEN no ports were previously configured
    PORTS.clear_ports()
    # WHEN trying to access an attribute that does not exist
    # THEN an AttributeError is raised
    with pytest.raises(AttributeError):
        PORTS.NOT_AN_ATTRIBUTE
    # AND the port is not in the active_ports
    assert not PORTS.active_ports()


def test_get_value():
    # GIVEN no ports were previously configured
    PORTS.clear_ports()
    # WHEN getting the value from an attribute key
    PORTS.get_value("FOO")
    # THEN that port is not in the active_ports
    assert PORTS.get_value("FOO") not in PORTS.active_ports()


def test_modifying_ports():
    # GIVEN no ports were previously configured
    PORTS.clear_ports()
    # WHEN ports are set
    PORTS.FOO
    PORTS.BAR
    # THEN the port is tracked in active_ports
    assert PORTS.active_ports() == [PORTS.get_value("FOO"), PORTS.get_value("BAR")]
    PORTS.clear_ports()
    assert not PORTS.active_ports()


def test_add_duplicate_ports():
    # GIVEN no ports were previously configured
    PORTS.clear_ports()
    # WHEN duplicate ports are set
    PORTS.FOO
    PORTS.FOO
    # THEN the port is tracked in active_ports only once
    assert PORTS.active_ports() == [PORTS.get_value("FOO")]
