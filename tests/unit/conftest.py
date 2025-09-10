from pathlib import Path
from unittest.mock import MagicMock, patch
from shutil import copytree
import pytest
from ops.testing import Container, Context, Exec
from ops import ActiveStatus

from charm import OpenTelemetryCollectorK8sCharm

CHARM_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture
def ctx(tmp_path):
    src_dirs = ["grafana_dashboards", "loki_alert_rules", "prometheus_alert_rules"]
    # Create a virtual charm_root so Scenario respects the `src_dirs`
    # Related to https://github.com/canonical/operator/issues/1673
    for src_dir in src_dirs:
        source_path = CHARM_ROOT / "src" / src_dir
        target_path = tmp_path / "src" / src_dir
        copytree(source_path, target_path, dirs_exist_ok=True)
    yield Context(OpenTelemetryCollectorK8sCharm, charm_root=tmp_path)


@pytest.fixture(scope="function")
def otelcol_container(execs):
    return [
        Container(
            name="otelcol",
            can_connect=True,
            execs=execs,
        )
    ]


@pytest.fixture(autouse=True)
def k8s_resource_multipatch():
    with patch.multiple(
        "charms.observability_libs.v0.kubernetes_compute_resources_patch.KubernetesComputeResourcesPatch",
        _namespace="test-namespace",
        _patch=lambda *_a, **_kw: True,
        is_ready=lambda *_a, **_kw: True,
        get_status=lambda _: ActiveStatus(),
    ):
        with patch("lightkube.core.client.GenericSyncClient", new=MagicMock()):
            yield


@pytest.fixture
def execs():
    yield {
        Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout=""),
        Exec(["/usr/bin/otelcol", "--version"], return_code=0, stdout="0.0.0"),
    }


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
