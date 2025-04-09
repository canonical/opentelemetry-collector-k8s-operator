from unittest.mock import patch

import pytest

from src.charm import OpenTelemetryCollectorK8sCharm
from ops.testing import Context


@pytest.fixture
def otelcol_charm(tmp_path):
    with patch("socket.getfqdn", new=lambda *args: "fqdn"):
        yield OpenTelemetryCollectorK8sCharm


@pytest.fixture(scope="function")
def context(otelcol_charm, tmp_path):
    src_dirs = ["grafana_dashboards", "loki_alert_rules", "prometheus_alert_rules"]
    # Create a virtual charm_root so Scenario respects the `src_dirs`
    # Related to https://github.com/canonical/operator/issues/1673
    for src_dir in src_dirs:
        sub_dir = tmp_path / "src" / src_dir
        sub_dir.mkdir(parents=True, exist_ok=True)
    return Context(charm_type=otelcol_charm, charm_root=tmp_path)
