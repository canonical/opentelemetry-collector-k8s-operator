"""Unit tests for certificate handling functionality."""

import pytest
from unittest.mock import MagicMock, patch

from charm import OpenTelemetryCollectorK8sCharm


# Test fixtures - specific fixtures for certificate tests
@pytest.fixture
def mock_charm():
    """Create a mock charm instance for testing."""
    with patch('charm.OpenTelemetryCollectorK8sCharm.__init__', lambda *args: None):
        return OpenTelemetryCollectorK8sCharm(MagicMock())


# Tests for _write_tls_certificates_to_disk method - CA cert scenarios
@pytest.mark.parametrize(
    "jobs,expected_results,expected_push_count",
    [
        (
            [
                {
                    "job_name": "juju-controller",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",
                        "insecure_skip_verify": False
                    }
                }
            ],
            {"juju-controller": {"ca": "/etc/otelcol/certs/otel_juju_controller_ca.pem"}},
            1
        ),
        (
            [
                {
                    "job_name": "test/job with spaces-and-dashes",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",
                        "insecure_skip_verify": False
                    }
                }
            ],
            {"test/job with spaces-and-dashes": {"ca": "/etc/otelcol/certs/otel_test_job_with_spaces_and_dashes_ca.pem"}},
            1
        ),
        (
            [
                {
                    "job_name": "job-1",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",
                        "insecure_skip_verify": False
                    }
                },
                {
                    "job_name": "job-2",
                    "tls_config": {
                        "ca_file": "second_ca_cert",
                        "insecure_skip_verify": False
                    }
                }
            ],
            {
                "job-1": {"ca": "/etc/otelcol/certs/otel_job_1_ca.pem"},
                "job-2": {"ca": "/etc/otelcol/certs/otel_job_2_ca.pem"}
            },
            2
        ),
    ],
)
def test_write_certificates_to_disk_ca_cert_scenarios(mock_charm, mock_container, sample_ca_cert, second_ca_cert, jobs, expected_results, expected_push_count):
    """Test various scenarios for writing inline CA certs from ca_file to disk."""
    cert_mapping = {"sample_ca_cert": sample_ca_cert, "second_ca_cert": second_ca_cert}

    for job in jobs:
        ca_key = job["tls_config"]["ca_file"]
        job["tls_config"]["ca_file"] = cert_mapping[ca_key]

    mock_container.exists.return_value = False
    mock_charm._ensure_certs_dir(mock_container)
    result = mock_charm._write_tls_certificates_to_disk(jobs, mock_container)

    assert len(result) == len(expected_results)
    for job_name, expected_paths in expected_results.items():
        assert job_name in result
        assert result[job_name] == expected_paths

    mock_container.make_dir.assert_called()
    assert mock_container.push.call_count == expected_push_count


@pytest.mark.parametrize(
    "job_name,container_fixture,expected_result",
    [
        ("test-job", "mock_container", {}),
        ("test-job-with-file-path", "mock_container", {}),
        ("test-job", "disconnected_container", {}),
    ],
)
def test_write_certificates_to_disk_no_work(mock_charm, job_name, container_fixture, expected_result, request):
    """Test cases where no certificates should be processed."""
    container = request.getfixturevalue(container_fixture)

    if job_name == "test-job-with-file-path":
        jobs = [
            {
                "job_name": job_name,
                "tls_config": {
                    "ca_file": "/existing/path/to/cert.pem",
                    "insecure_skip_verify": False
                }
            }
        ]
    else:
        jobs = [
            {
                "job_name": job_name,
                "tls_config": {
                    "insecure_skip_verify": True
                }
            }
        ]

    result = mock_charm._write_tls_certificates_to_disk(jobs, container)

    assert result == expected_result
    container.push.assert_not_called()


# Tests for _write_tls_certificates_to_disk - key and cert scenarios
@pytest.mark.parametrize(
    "jobs,expected_job_paths",
    [
        (
            [
                {
                    "job_name": "mtls-job",
                    "tls_config": {
                        "ca_file": "dummy_ca",
                        "key_file": "dummy_key",
                        "cert_file": "dummy_cert",
                        "insecure_skip_verify": False
                    }
                }
            ],
            {
                "mtls-job": {
                    "ca": "/etc/otelcol/certs/otel_mtls_job_ca.pem",
                    "key": "/etc/otelcol/certs/otel_mtls_job_key.pem",
                    "cert": "/etc/otelcol/certs/otel_mtls_job_cert.pem",
                }
            },
        ),
        (
            [
                {
                    "job_name": "cert-only",
                    "tls_config": {
                        "cert_file": "dummy_cert",
                        "insecure_skip_verify": False
                    }
                }
            ],
            {
                "cert-only": {
                    "cert": "/etc/otelcol/certs/otel_cert_only_cert.pem",
                }
            },
        ),
        (
            [
                {
                    "job_name": "all-three",
                    "tls_config": {
                        "ca_file": "dummy_ca",
                        "key_file": "dummy_key",
                        "cert_file": "dummy_cert",
                    }
                }
            ],
            {
                "all-three": {
                    "ca": "/etc/otelcol/certs/otel_all_three_ca.pem",
                    "key": "/etc/otelcol/certs/otel_all_three_key.pem",
                    "cert": "/etc/otelcol/certs/otel_all_three_cert.pem",
                }
            },
        ),
    ],
)
def test_write_tls_certificates_to_disk_key_cert(mock_charm, mock_container, sample_ca_cert, sample_private_key, sample_client_cert, jobs, expected_job_paths):
    """Test writing key and client certificate to disk alongside CA from *_file keys."""
    cert_mapping = {"dummy_ca": sample_ca_cert, "dummy_key": sample_private_key, "dummy_cert": sample_client_cert}

    for job in jobs:
        tls_config = job["tls_config"]
        for field in ("ca_file", "key_file", "cert_file"):
            if field in tls_config:
                tls_config[field] = cert_mapping[tls_config[field]]

    mock_container.exists.return_value = False
    mock_charm._ensure_certs_dir(mock_container)
    result = mock_charm._write_tls_certificates_to_disk(jobs, mock_container)

    assert len(result) == len(expected_job_paths)
    for job_name, expected_paths in expected_job_paths.items():
        assert job_name in result
        assert result[job_name] == expected_paths

    total_expected = sum(len(v) for v in expected_job_paths.values())
    assert mock_container.push.call_count == total_expected

    # Verify key file is pushed with 0o600 permissions
    for job_name in expected_job_paths:
        if "key" in expected_job_paths[job_name]:
            key_path = expected_job_paths[job_name]["key"]
            found = any(
                call_args[0] == key_path and call_kwargs.get("permissions") == 0o600
                for call_args, call_kwargs in mock_container.push.call_args_list
            )
            assert found, f"Key file {key_path} not pushed with 0o600 permissions"


# Tests for update_jobs_with_cert_paths method
@pytest.mark.parametrize(
    "jobs,cert_paths,expected_results",
    [
        (
            [
                {
                    "job_name": "job-with-ca",
                    "tls_config": {
                        "ca_file": "original_cert_content",
                        "insecure_skip_verify": False
                    }
                },
                {
                    "job_name": "job-without-cert",
                    "tls_config": {
                        "insecure_skip_verify": True
                    }
                }
            ],
            {"job-with-ca": {"ca": "/etc/otelcol/certs/otel_job_with_ca_ca.pem"}},
            [
                {
                    "job_name": "job-with-ca",
                    "tls_config": {
                        "ca_file": "/etc/otelcol/certs/otel_job_with_ca_ca.pem",
                        "insecure_skip_verify": False
                    }
                },
                {
                    "job_name": "job-without-cert",
                    "tls_config": {
                        "insecure_skip_verify": True
                    }
                }
            ]
        ),
        (
            [{"job_name": "test-job"}],
            {"test-job": {"ca": "/etc/otelcol/certs/otel_test_job_ca.pem"}},
            [
                {
                    "job_name": "test-job",
                    "tls_config": {
                        "ca_file": "/etc/otelcol/certs/otel_test_job_ca.pem"
                    }
                }
            ]
        ),
        (
            [
                {
                    "job_name": "mtls-job",
                    "tls_config": {
                        "ca_file": "original_ca",
                        "key_file": "original_key",
                        "cert_file": "original_cert",
                    }
                }
            ],
            {
                "mtls-job": {
                    "ca": "/etc/otelcol/certs/otel_mtls_job_ca.pem",
                    "key": "/etc/otelcol/certs/otel_mtls_job_key.pem",
                    "cert": "/etc/otelcol/certs/otel_mtls_job_cert.pem",
                }
            },
            [
                {
                    "job_name": "mtls-job",
                    "tls_config": {
                        "ca_file": "/etc/otelcol/certs/otel_mtls_job_ca.pem",
                        "key_file": "/etc/otelcol/certs/otel_mtls_job_key.pem",
                        "cert_file": "/etc/otelcol/certs/otel_mtls_job_cert.pem",
                    }
                }
            ]
        ),
        (
            [
                {
                    "job_name": "partial-job",
                    "tls_config": {
                        "key_file": "original_key",
                    }
                }
            ],
            {
                "partial-job": {
                    "key": "/etc/otelcol/certs/otel_partial_job_key.pem",
                }
            },
            [
                {
                    "job_name": "partial-job",
                    "tls_config": {
                        "key_file": "/etc/otelcol/certs/otel_partial_job_key.pem",
                    }
                }
            ]
        ),
    ],
)
def test_update_jobs_with_cert_paths_various_scenarios(config_manager, jobs, cert_paths, expected_results):
    """Test various scenarios for updating jobs with certificate paths."""
    result = config_manager.update_jobs_with_cert_paths(jobs, cert_paths)

    assert len(result) == len(expected_results)
    for i, expected_job in enumerate(expected_results):
        assert result[i]["job_name"] == expected_job["job_name"]
        if "tls_config" in expected_job:
            assert "tls_config" in result[i]
            assert result[i]["tls_config"] == expected_job["tls_config"]
        else:
            assert "tls_config" not in result[i]


@pytest.mark.parametrize(
    "job_name,cert_paths",
    [
        ("test-job", {"test-job": {"ca": "/etc/otelcol/certs/otel_test_job_ca.pem"}}),
        ("default", {"default": {"ca": "/etc/otelcol/certs/otel_default_ca.pem"}}),
    ],
)
def test_update_jobs_with_cert_paths_matching(config_manager, job_name, cert_paths):
    """Test that matching jobs get updated correctly."""
    jobs = [
        {
            "job_name": job_name,
            "tls_config": {
                "ca_file": "original_cert_content",
                "insecure_skip_verify": False
            }
        }
    ]

    result = config_manager.update_jobs_with_cert_paths(jobs, cert_paths)

    assert len(result) == 1
    for key, file_key in [("ca", "ca_file"), ("key", "key_file"), ("cert", "cert_file")]:
        if key in cert_paths[job_name]:
            assert result[0]["tls_config"][file_key] == cert_paths[job_name][key]
        else:
            assert file_key not in result[0]["tls_config"]


# Tests for _validate_private_key
def test_validate_private_key_rsa(mock_charm, sample_private_key):
    """Test validation of RSA private key."""
    assert mock_charm._validate_private_key(sample_private_key) is True


def test_validate_private_key_ec(mock_charm):
    """Test validation of EC private key."""
    ec_key = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDkCvlF2i1OTqMfR7fR9b8X8X8X8X8X8X8X8X8X8X8X8X8X8X8X8X8
-----END EC PRIVATE KEY-----"""
    assert mock_charm._validate_private_key(ec_key) is True


def test_validate_private_key_invalid(mock_charm):
    """Test validation of invalid private key."""
    assert mock_charm._validate_private_key("not-a-key") is False
    assert mock_charm._validate_private_key("") is False
    assert mock_charm._validate_private_key("-----BEGIN CERTIFICATE-----\nfoobar\n-----END CERTIFICATE-----") is False
