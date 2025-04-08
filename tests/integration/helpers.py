#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pytest_operator.plugin import OpsTest
import sh
from typing import List, Optional

logger = logging.getLogger(__name__)

# pyright: reportOptionalMemberAccess = false

# This is needed for sh.juju
# pyright: reportAttributeAccessIssue = false

async def get_application_ip(ops_test: OpsTest, app_name: str) -> str:
    """Get the application IP address."""
    status = await ops_test.model.get_status()
    app = status["applications"][app_name]
    return app.public_address

def wait_for_idle(model_name: str, app_names: Optional[List[str]] = None):
    if app_names is None:
        app_names = []
    logger.info(f"Waiting for model {model_name} to become idle...")
    sh.juju("wait-for", "model", model_name, query='forEach(units, unit => unit.agent-status == "idle") && forEach(applications, app => app.status != "error")', timeout="10m")
    for app in app_names:
        logger.info(f"Waiting for app {app} to become idle...")
        sh.juju("wait-for", "application", app, query='status == "active" && len(units) > 0', m=model_name, timeout="10m")
        logger.info(f"App {app} is idle!")
    sh.juju("wait-for", "model", model_name, query='forEach(units, unit => unit.agent-status == "idle") && forEach(applications, app => app.status != "error")', timeout="10m")
    logger.info(f"Model {model_name} is idle!")
