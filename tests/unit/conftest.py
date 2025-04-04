import pytest
from ops.testing import Context

from charm import OpenTelemetryCollectorK8sCharm


@pytest.fixture
def ctx():
    yield Context(OpenTelemetryCollectorK8sCharm)
