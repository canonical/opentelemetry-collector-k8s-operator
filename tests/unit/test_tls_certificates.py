"""Feature: Otelcol server can run in HTTPS mode."""

def test_no_tls_certificates_relation():
    """Scenario: Otelcol deployed without tls-certificates relation."""
    # GIVEN otelcol deployed in isolation
    # THEN config file doesn't include "key_file" nor "cert_file"

    # AND WHEN telemetry sources (e.g. avalanche) and sinks (e.g. prometheus) join
    # THEN config file doesn't include "key_file" nor "cert_file"


def test_transition_from_http_to_https():
    """Scenario: a tls-certificates relation joined, but we didn't get the cert yet."""
    # GIVEN otelcol deployed in isolation
    # WHEN a tls-certificates relation joins but the CA didn't reply with a cert yet
    # THEN the otelcol pebble service is stopped

    # AND WHEN the cert is received
    # THEN the otelcol pebble service is running
    # AND config file includes "key_file" and "cert_file" for all receivers
    # AND the cert and private key files were written to disk
    # TODO: should we trust the CA that signed us? Add neg/pos assertion accordingly.


def test_transition_from_https_to_http():
    """Scenario: the tls-certificates relation is removed."""
    # GIVEN otelcol deployed in TLS mode
    # THEN the otelcol pebble service is running
    # AND config file includes "key_file" and "cert_file" for all receivers
    # AND the cert and private key files were written to disk

    # WHEN the tls-certificates relation is removed
    # THEN the otelcol pebble service is running
    # AND config file doesn't include "key_file" nor "cert_file" for all receivers
    # AND the cert and private key files are not on disk
    # TODO: should we trust the CA that signed us? Add neg/pos assertion accordingly.
