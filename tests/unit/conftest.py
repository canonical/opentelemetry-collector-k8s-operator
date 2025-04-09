from unittest.mock import patch

import pytest
from ops.testing import Context, Exec

from charm import OpenTelemetryCollectorK8sCharm


@pytest.fixture
def ctx():
    yield Context(OpenTelemetryCollectorK8sCharm)


@pytest.fixture
def execs():
    yield {Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout="")}
