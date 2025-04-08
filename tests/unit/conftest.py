from unittest.mock import patch

import pytest

from src.charm import OpenTelemetryCollectorK8sCharm


@pytest.fixture
def otelcol_charm(tmp_path):
    with patch("socket.getfqdn", new=lambda *args: "fqdn"):
        yield OpenTelemetryCollectorK8sCharm
