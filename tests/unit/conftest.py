from pathlib import Path
from shutil import copytree
import pytest
from ops.testing import Context, Exec, Container

from charm import OpenTelemetryCollectorK8sCharm

@pytest.fixture
def ctx(tmp_path):
    src_dirs = ["grafana_dashboards", "loki_alert_rules", "prometheus_alert_rules"]
    # Create a virtual charm_root so Scenario respects the `src_dirs`
    # Related to https://github.com/canonical/operator/issues/1673
    for src_dir in src_dirs:
        source_path = Path("src") / src_dir
        target_path = tmp_path / "src" / src_dir
        copytree(source_path, target_path, dirs_exist_ok=True)
    yield Context(OpenTelemetryCollectorK8sCharm, charm_root=tmp_path)

@pytest.fixture(scope="function")
def otelcol_container(execs):
    return [Container(
    name="otelcol",
    can_connect=True,
    execs=execs,
)]

@pytest.fixture
def execs():
    yield {Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout="")}


@pytest.fixture
def cert():
    return "mocked_certificate"


@pytest.fixture
def private_key():
    return "mocked_private_key"


class MockCertificate:
    def __init__(self, certificate):
        self.certificate = certificate


@pytest.fixture
def cert_obj(cert):
    return MockCertificate(cert)
