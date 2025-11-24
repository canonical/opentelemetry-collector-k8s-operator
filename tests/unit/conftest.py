from pathlib import Path
from unittest.mock import MagicMock, patch
from shutil import copytree
import pytest
from ops.testing import Container, Context, Exec
from ops import ActiveStatus
from dataclasses import dataclass


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
def server_cert():
    return "mocked_server_certificate"


@pytest.fixture
def ca_cert():
    return "mocked_ca_certificate"


@pytest.fixture
def private_key():
    return "mocked_private_key"


@dataclass
class Certificate:
    raw: str


class MockCertificate:
    def __init__(self, server_cert, ca_cert):
        self.certificate = Certificate(server_cert)
        self.ca = Certificate(ca_cert)
        # TODO: remove this comment certificates.certificate.raw, certificates.ca.raw


@pytest.fixture
def cert_obj(cert):
    return MockCertificate(cert)


@pytest.fixture
def sample_ca_cert():
    """Sample CA certificate content for testing (real cert format)."""
    from textwrap import dedent
    return dedent("""\
        -----BEGIN CERTIFICATE-----
        MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
        BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
        aWRnaXRzIFB0eUzMkQwHhcNMTMwOTEyMjE1MjAyWhcNMTQwOTEyMjE1MjAyWjBF
        MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
        ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
        CgKCAQEAwxKxPqB/NBOOfJUA9t4gCjGcNnHvEjQc8g8MJp8qN3lqf8d4d8d4d8d4
        d8d4d8d4d8d4d8d4d8d4d8d4d8d4d8d4d8d8d4d8d4d8d4d8d4d8d4d8d4d8d4d8d4d8d4d8d4d
        -----END CERTIFICATE-----""").strip()


@pytest.fixture
def second_ca_cert():
    """Second sample CA certificate for testing multiple certificates."""
    from textwrap import dedent
    return dedent("""\
        -----BEGIN CERTIFICATE-----
        MIIDXjCCAkYCCQCCKpT1rYK7pzANBgkqhkiG9w0BAQFADCBiDELMAkGA1UEBhMC
        -----END CERTIFICATE-----""").strip()


@pytest.fixture
def mock_container():
    """Create a mock container for testing."""
    container = MagicMock()
    container.can_connect.return_value = True
    container.exec.return_value.wait.return_value = None
    container.make_dir = MagicMock()
    # By default, directory exists to avoid mkdir calls in unrelated tests
    # Certificate tests will override this as needed
    container.exists.return_value = True
    return container


@pytest.fixture
def disconnected_container():
    """Create a mock container that cannot connect."""
    container = MagicMock()
    container.can_connect.return_value = False
    container.exec.return_value.wait.return_value = None
    return container


@pytest.fixture
def config_manager():
    """Create a ConfigManager instance for testing."""
    from config_manager import ConfigManager
    return ConfigManager(
        unit_name="test/0",
        global_scrape_interval="15s",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )

def cert_obj(server_cert, ca_cert):
    return MockCertificate(server_cert, ca_cert)
