#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pytest_operator.plugin import OpsTest

log = logging.getLogger(__name__)

# pyright: reportOptionalMemberAccess = false


async def get_application_ip(ops_test: OpsTest, app_name: str) -> str:
    """Get the application IP address."""
    status = await ops_test.model.get_status()
    app = status["applications"][app_name]
    return app.public_address
