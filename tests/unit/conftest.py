from pathlib import Path
from shutil import copytree

import pytest
from ops.testing import Context, Exec

from charm import OpenTelemetryCollectorK8sCharm


@pytest.fixture
def ctx(tmp_path):
    src_dirs = ["grafana_dashboards", "loki_alert_rules", "prometheus_alert_rules"]
    # Create a virtual charm_root so Scenario respects the `src_dirs`
    # Related to https://github.com/canonical/operator/issues/1673
    for src_dir in src_dirs:
        source_path = Path('src') / src_dir
        target_path = tmp_path / "src" / src_dir
        copytree(source_path, target_path, dirs_exist_ok=True)
    yield Context(OpenTelemetryCollectorK8sCharm, charm_root=tmp_path)


@pytest.fixture
def execs():
    yield {Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout="")}
