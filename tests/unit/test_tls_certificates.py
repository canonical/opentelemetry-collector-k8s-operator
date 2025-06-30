# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can run in HTTPS mode."""

import json
from unittest.mock import patch

import pytest
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    TLSCertificatesRequiresV4,
)
from helpers import get_otelcol_file
from ops.testing import Container, Relation, State

from constants import CONFIG_PATH, SERVER_CERT_PATH, SERVER_CERT_PRIVATE_KEY_PATH


def no_certs_in_receivers(otelcol_config: dict):
    return not any(
        ("key_file" in protocol.get("tls", {}) or "cert_file" in protocol.get("tls", {}))
        for receiver in otelcol_config["receivers"].values()
        for protocol in receiver.get("protocols", {}).values()
    )


def test_no_tls_certificates_relation(ctx, execs):
    """Scenario: Otelcol deployed without tls-certificates relation."""
    # GIVEN otelcol deployed in isolation
    container = Container(name="otelcol", can_connect=True, execs=execs)
    state_out = ctx.run(ctx.on.update_status(), State(containers=[container]))
    # THEN the config file doesn't include "key_file" nor "cert_file"
    assert no_certs_in_receivers(get_otelcol_file(state_out, ctx, CONFIG_PATH))
    # AND WHEN telemetry sources (e.g. flog) join to create a receiver
    data_source = Relation(
        endpoint="receive-loki-logs",
        interface="loki_push_api",
    )
    state_in = State(
        relations=[data_source],
        containers=[container],
    )
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN receivers in the config file don't include "key_file" nor "cert_file"
    assert no_certs_in_receivers(get_otelcol_file(state_out, ctx, CONFIG_PATH))


def test_waiting_for_cert(ctx, execs):
    """Scenario: a tls-certificates relation joined, but we didn't get the cert yet."""
    # GIVEN otelcol deployed in isolation
    container = Container(name="otelcol", can_connect=True, execs=execs)
    # WHEN a tls-certificates relation joins but the CA didn't reply with a cert yet
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    state_in = State(relations=[ssc], containers=[container])
    state_out = ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the otelcol pebble service is stopped
    assert not state_out.get_container("otelcol").services["otelcol"].is_running()


def test_transitioned_from_http_to_https_to_http(ctx, execs, cert, cert_obj, private_key):
    """Scenario: a tls-certificates relation joins and is later removed."""
    # GIVEN otelcol has received a cert
    container = Container(name="otelcol", can_connect=True, execs=execs)
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    data_sink = Relation(
        endpoint="send-loki-logs",
        interface="loki_push_api",
        remote_units_data={
            0: {"endpoint": '{"url": "http://fqdn-0:3100/loki/api/v1/push"}'},
        },
    )
    state_in = State(relations=[ssc, data_sink], containers=[container])
    # Note: We patch the cert creation process on disk since it requires a dynamic cert, CSR, CA,
    # and cert chain in the remote app databag
    with patch.object(
        TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None
    ), patch.object(
        TLSCertificatesRequiresV4, "get_assigned_certificate", return_value=(cert_obj, private_key)
    ), patch.object(Certificate, "from_string", return_value=cert_obj):
        state_out = ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the cert and private key files were written to disk
    assert cert == get_otelcol_file(state_out, ctx, SERVER_CERT_PATH)
    assert private_key == get_otelcol_file(state_out, ctx, SERVER_CERT_PRIVATE_KEY_PATH)
    otelcol_config = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # AND config file includes "key_file" and "cert_file" for receivers with a "protocols" section
    protocols = otelcol_config["receivers"]["otlp"]["protocols"]
    for protocol in protocols:
        assert protocols[protocol]["tls"]["cert_file"] == SERVER_CERT_PATH
        assert protocols[protocol]["tls"]["key_file"] == SERVER_CERT_PRIVATE_KEY_PATH
    # WHEN the tls-certificates relation is removed
    state_in = State(relations=[data_sink], containers=[container])
    state_out = ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the config file doesn't include "key_file" nor "cert_file" for all receivers
    otelcol_config = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert no_certs_in_receivers(get_otelcol_file(state_out, ctx, CONFIG_PATH))
    # AND the cert and private key files are not on disk
    with pytest.raises(AssertionError, match="file does not exist"):
        get_otelcol_file(state_out, ctx, SERVER_CERT_PATH)
    with pytest.raises(AssertionError, match="file does not exist"):
        get_otelcol_file(state_out, ctx, SERVER_CERT_PRIVATE_KEY_PATH)


@pytest.mark.skip(reason="https://github.com/canonical/operator/issues/1858")
def test_https_endpoint_is_provided(ctx, execs, cert, cert_obj, private_key):
    """Scenario: Otelcol provides other charms its TLS endpoint."""
    # GIVEN otelcol is in TLS mode
    container = Container(name="otelcol", can_connect=True, execs=execs)
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    data_source = Relation(
        endpoint="receive-loki-logs",
        interface="loki_push_api",
    )
    state_in = State(relations=[ssc, data_source], containers=[container])
    # WHEN a relation_changed event on the "receive-loki-logs" endpoint fires
    with patch.object(
        TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None
    ), patch.object(
        TLSCertificatesRequiresV4, "get_assigned_certificate", return_value=(cert_obj, private_key)
    ), patch.object(Certificate, "from_string", return_value=cert_obj):
        state_out = ctx.run(ctx.on.relation_changed(data_source), state=state_in)
    # THEN Otelcol provides its TLS endpoint in the databag
    for relation in state_out.relations:
        if relation.endpoint == "receive-loki-logs":
            assert "https" in json.loads(relation.local_unit_data["endpoint"])["url"]
