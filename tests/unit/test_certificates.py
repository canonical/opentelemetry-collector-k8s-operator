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


# Tests for _write_ca_certificates_to_disk method
@pytest.mark.parametrize(
    "jobs,expected_results,expected_push_count",
    [
        # Single job with simple name
        (
            [
                {
                    "job_name": "juju-controller",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",  # Will be replaced in test
                        "insecure_skip_verify": False
                    }
                }
            ],
            {"juju-controller": "/etc/ssl/certs/otel_juju_controller_ca.pem"},
            1
        ),
        # Single job with filename sanitization
        (
            [
                {
                    "job_name": "test/job with spaces-and-dashes",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",  # Will be replaced in test
                        "insecure_skip_verify": False
                    }
                }
            ],
            {"test/job with spaces-and-dashes": "/etc/ssl/certs/otel_test_job_with_spaces_and_dashes_ca.pem"},
            1
        ),
        # Multiple jobs with different certificates
        (
            [
                {
                    "job_name": "job-1",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",  # Will be replaced in test
                        "insecure_skip_verify": False
                    }
                },
                {
                    "job_name": "job-2",
                    "tls_config": {
                        "ca_file": "second_ca_cert",  # Will be replaced in test
                        "insecure_skip_verify": False
                    }
                }
            ],
            {
                "job-1": "/etc/ssl/certs/otel_job_1_ca.pem",
                "job-2": "/etc/ssl/certs/otel_job_2_ca.pem"
            },
            2
        ),
    ],
)
def test_write_certificates_to_disk_scenarios(mock_charm, mock_container, sample_ca_cert, second_ca_cert, jobs, expected_results, expected_push_count):
    """Test various scenarios for writing CA certificates to disk."""
    # Replace certificate placeholders with actual fixtures
    cert_mapping = {"sample_ca_cert": sample_ca_cert, "second_ca_cert": second_ca_cert}

    for job in jobs:
        ca_file_key = job["tls_config"]["ca_file"]
        job["tls_config"]["ca_file"] = cert_mapping[ca_file_key]

    # Execute
    result = mock_charm._write_ca_certificates_to_disk(jobs, mock_container)

    # Verify results
    assert len(result) == len(expected_results)
    for job_name, expected_path in expected_results.items():
        assert job_name in result
        assert result[job_name] == expected_path

    # Verify container operations
    # mkdir is now called only once regardless of number of certificates
    mock_container.exec.assert_called_once_with(["mkdir", "-p", "/etc/ssl/certs/"])
    assert mock_container.push.call_count == expected_push_count

    # Verify specific push calls for single job scenarios
    if expected_push_count == 1:
        # Single job scenarios
        job_name = list(expected_results.keys())[0]
        expected_path = list(expected_results.values())[0]
        expected_cert = cert_mapping["sample_ca_cert"]

        mock_container.push.assert_called_once_with(
            expected_path,
            expected_cert,
            permissions=0o644
        )
    # Multiple jobs scenarios: call count already verified above
    # (Order of calls may vary and isn't critical for functionality)


@pytest.mark.parametrize(
    "job_name,container_fixture,expected_result",
    [
        # Jobs without certificate content - should return empty (connected container)
        ("test-job", "mock_container", {}),
        ("test-job-with-file-path", "mock_container", {}),
        # Container not connected - should return empty
        ("test-job", "disconnected_container", {}),
    ],
)
def test_write_certificates_to_disk_no_work(mock_charm, job_name, container_fixture, expected_result, request):
    """Test cases where no certificates should be processed."""
    # Get the appropriate container fixture
    container = request.getfixturevalue(container_fixture)

    # Test data
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

    # Execute
    result = mock_charm._write_ca_certificates_to_disk(jobs, container)

    # Verify - no certificates should be processed
    assert result == expected_result
    container.exec.assert_not_called()
    container.push.assert_not_called()


# Tests for update_jobs_with_ca_paths method
@pytest.mark.parametrize(
    "jobs,cert_paths,expected_results",
    [
        # Jobs with matching names should get updated
        (
            [
                {
                    "job_name": "job-with-cert",
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
            {"job-with-cert": "/etc/ssl/certs/otel_job_with_cert_ca.pem"},
            [
                {
                    "job_name": "job-with-cert",
                    "tls_config": {
                        "ca_file": "/etc/ssl/certs/otel_job_with_cert_ca.pem",
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
        # Jobs without tls_config should get config added
        (
            [{"job_name": "test-job"}],
            {"test-job": "/etc/ssl/certs/otel_test_job_ca.pem"},
            [
                {
                    "job_name": "test-job",
                    "tls_config": {
                        "ca_file": "/etc/ssl/certs/otel_test_job_ca.pem"
                    }
                }
            ]
        ),
    ],
)
def test_update_jobs_with_ca_paths_various_scenarios(config_manager, jobs, cert_paths, expected_results):
    """Test various scenarios for updating jobs with certificate paths."""
    # Execute
    result = config_manager.update_jobs_with_ca_paths(jobs, cert_paths)

    # Verify
    assert len(result) == len(expected_results)
    for i, expected_job in enumerate(expected_results):
        assert result[i]["job_name"] == expected_job["job_name"]
        if "tls_config" in expected_job:
            assert "tls_config" in result[i]
            assert result[i]["tls_config"] == expected_job["tls_config"]
        else:
            assert "tls_config" not in result[i]


@pytest.mark.parametrize(
    "job_name,cert_paths,expected_ca_file",
    [
        # No matching cert path - should remain unchanged
        ("test-job", {"different-job": "/path/to/cert.pem"}, "original_cert_content"),
        # Empty cert paths - should remain unchanged
        ("test-job", {}, "original_cert_content"),
        # Default job name with matching cert - should be updated
        ("default", {"default": "/etc/ssl/certs/otel_default_ca.pem"}, "/etc/ssl/certs/otel_default_ca.pem"),
    ],
)
def test_update_jobs_with_ca_paths_no_changes(config_manager, job_name, cert_paths, expected_ca_file):
    """Test cases where jobs should remain unchanged."""
    # Test data
    jobs = [
        {
            "job_name": job_name,
            "tls_config": {
                "ca_file": "original_cert_content",
                "insecure_skip_verify": False
            }
        }
    ]

    # Execute
    result = config_manager.update_jobs_with_ca_paths(jobs, cert_paths)

    # Verify - job should remain unchanged
    assert len(result) == 1
    assert result[0]["tls_config"]["ca_file"] == expected_ca_file
