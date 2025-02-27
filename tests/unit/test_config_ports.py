#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: Opentelemetry-collector exposes ports dynamically.

Scenario: Add/remove a port to/from the config
    When the otelcol config has a port defined in the config
    Then the ports exposed on the charm unit should contain only those in the config
"""

# from src.config import Config


def test_set_port():
    pass
    # GIVEN a default Config
    # cfg = Config()
    # WHEN a port is set in the config
    # THEN the port is tracked in active_ports

def test_clear_ports():
    pass
    # GIVEN a default Config
    # cfg = Config()
    # WHEN the ports are cleared in the config
    # THEN active_ports is empty

def test_add_duplicate_ports():
    pass
    # GIVEN a default Config
    # cfg = Config()
    # WHEN duplicate ports are added to the config
    # THEN active_ports contains each port only once
