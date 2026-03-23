from dataclasses import dataclass
from pathlib import Path
from shutil import copytree
from textwrap import dedent
from unittest.mock import MagicMock, patch

import pytest
from ops import ActiveStatus
from ops.testing import Container, Context, Exec

from src.charm import OpenTelemetryCollectorK8sCharm
from src.config_manager import ConfigManager

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


@pytest.fixture
def cert_obj(server_cert, ca_cert):
    return MockCertificate(server_cert, ca_cert)


@pytest.fixture
def sample_ca_cert():
    """Sample CA certificate content for testing (real cert format)."""
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
    return ConfigManager(
        unit_name="test/0",
        global_scrape_interval="15s",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )


@pytest.fixture
def promql_bundled_rule_count():
    return len(list((CHARM_ROOT / "src" / "prometheus_alert_rules").glob("*.rules")))


@pytest.fixture
def logql_bundled_rule_count():
    return len(list((CHARM_ROOT / "src" / "loki_alert_rules").glob("*.rules")))


@pytest.fixture
def otelcol_metadata():
    return {
        "application": "opentelemetry-collector-k8s",
        "charm_name": "opentelemetry-collector-k8s",
        "model": "otelcol",
        "model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
        "unit": "opentelemetry-collector-k8s/0",
    }


@pytest.fixture
def logql_alert_rule():
    return {
        "name": "otelcol_f4d59020_charm_x_foo_alerts",
        "rules": [
            {
                "alert": "HighLogVolume",
                "expr": 'count_over_time({job=~".+"}[30s]) > 100',
                "labels": {"severity": "high"},
            },
        ],
    }


@pytest.fixture
def logql_record_rule():
    return {
        "name": "otelcol_f4d59020_charm_x_foobar_alerts",
        "rules": [
            {
                "record": "log:error_rate:rate5m",
                "expr": 'sum by (service) (rate({job=~".+"} | json | level="error" [5m]))',
                "labels": {"severity": "high"},
            }
        ],
    }


@pytest.fixture
def promql_alert_rule():
    return {
        "name": "otelcol_f4d59020_charm_x_bar_alerts",
        "rules": [
            {
                "alert": "Workload Missing",
                "expr": 'up{job=~".+"} == 0',
                "for": "0m",
                "labels": {"severity": "critical"},
            },
        ],
    }


@pytest.fixture
def promql_record_rule():
    return {
        "name": "otelcol_f4d59020_charm_x_barfoo_alerts",
        "rules": [
            {
                "record": "code:prometheus_http_requests_total:sum",
                "expr": 'sum by (code) (prometheus_http_requests_total{job=~".+"})',
                "labels": {"severity": "high"},
            }
        ],
    }


@pytest.fixture
def all_rules(logql_alert_rule, logql_record_rule, promql_alert_rule, promql_record_rule):
    return {
        "logql": {"groups": [logql_alert_rule, logql_record_rule]},
        "promql": {"groups": [promql_alert_rule, promql_record_rule]},
    }
