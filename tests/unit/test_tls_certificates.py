# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can run in HTTPS mode."""

import json
from unittest.mock import patch

import pytest
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    PrivateKey,
    TLSCertificatesRequiresV4,
    generate_csr,
)
from conftest import MockCertificate
from helpers import IssuedCertificate, get_otelcol_file, trust_stamp_after_reconcile
from ops.testing import Relation, State

from constants import (
    CONFIG_PATH,
    SERVER_CA_CERT_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
)


def no_certs_in_receivers(otelcol_config: dict):
    return not any(
        ("key_file" in protocol.get("tls", {}) or "cert_file" in protocol.get("tls", {}))
        for receiver in otelcol_config["receivers"].values()
        for protocol in receiver.get("protocols", {}).values()
    )


def test_no_tls_certificates_relation(ctx, otelcol_container):
    """Scenario: Otelcol deployed without tls-certificates relation."""
    # GIVEN otelcol deployed in isolation
    state_out = ctx.run(ctx.on.update_status(), State(containers=otelcol_container))
    # THEN the config file doesn't include "key_file" nor "cert_file"
    assert no_certs_in_receivers(get_otelcol_file(state_out, ctx, CONFIG_PATH))
    # AND WHEN telemetry sources (e.g. flog) join to create a receiver
    data_source = Relation(
        endpoint="receive-loki-logs",
        interface="loki_push_api",
    )
    state_in = State(
        relations=[data_source],
        containers=otelcol_container,
    )
    state_out = ctx.run(ctx.on.update_status(), state_in)
    # THEN receivers in the config file don't include "key_file" nor "cert_file"
    assert no_certs_in_receivers(get_otelcol_file(state_out, ctx, CONFIG_PATH))


def test_waiting_for_cert(ctx, otelcol_container):
    """Scenario: a tls-certificates relation joined, but we didn't get the cert yet."""
    # GIVEN otelcol deployed in isolation
    # WHEN a tls-certificates relation joins but the CA didn't reply with a cert yet
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    state_in = State(relations=[ssc], containers=otelcol_container)
    state_out = ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the otelcol pebble service is stopped
    assert not state_out.get_container("otelcol").services["otelcol"].is_running()


def test_transitioned_from_http_to_https_to_http(
    ctx, otelcol_container, cert_obj, private_key, server_cert, ca_cert
):
    """Scenario: a tls-certificates relation joins and is later removed."""
    # GIVEN otelcol has received a cert
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
    state_in = State(relations=[ssc, data_sink], containers=otelcol_container)
    # Note: We patch the cert creation process on disk since it requires a dynamic cert, CSR, CA,
    # and cert chain in the remote app databag
    with (
        patch.object(TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None),
        patch.object(
            TLSCertificatesRequiresV4,
            "get_assigned_certificate",
            return_value=(cert_obj, private_key),
        ),
        patch.object(Certificate, "from_string", return_value=cert_obj),
    ):
        state_out = ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the cert and private key files were written to disk
    assert private_key == get_otelcol_file(state_out, ctx, SERVER_CERT_PRIVATE_KEY_PATH)
    assert server_cert == get_otelcol_file(state_out, ctx, SERVER_CERT_PATH)
    assert ca_cert == get_otelcol_file(state_out, ctx, SERVER_CA_CERT_PATH)
    otelcol_config = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    # AND config file includes "key_file" and "cert_file" for receivers with a "protocols" section
    unit_name = "opentelemetry-collector-k8s/0"
    protocols = otelcol_config["receivers"][f"otlp/{unit_name}"]["protocols"]
    for protocol in protocols:
        assert protocols[protocol]["tls"]["cert_file"] == SERVER_CERT_PATH
        assert protocols[protocol]["tls"]["key_file"] == SERVER_CERT_PRIVATE_KEY_PATH
    # WHEN the tls-certificates relation is removed
    state_in = State(relations=[data_sink], containers=otelcol_container)
    state_out = ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the config file doesn't include "key_file" nor "cert_file" for all receivers
    otelcol_config = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert no_certs_in_receivers(get_otelcol_file(state_out, ctx, CONFIG_PATH))
    # AND the cert and private key files are not on disk
    with pytest.raises(AssertionError, match="file does not exist"):
        get_otelcol_file(state_out, ctx, SERVER_CERT_PATH)
    with pytest.raises(AssertionError, match="file does not exist"):
        get_otelcol_file(state_out, ctx, SERVER_CA_CERT_PATH)
    with pytest.raises(AssertionError, match="file does not exist"):
        get_otelcol_file(state_out, ctx, SERVER_CERT_PRIVATE_KEY_PATH)


def test_ca_only_rotation_refreshes_trust_stamp(
    ctx, otelcol_container, cert_obj, private_key, server_cert
):
    """Scenario: the issuing CA rotates while the server cert and private key stay the same."""
    # GIVEN a tls-certificates relation with an assigned cert, key and CA
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    state_in = State(relations=[ssc], containers=otelcol_container)

    # WHEN a reconcile refreshes the trust store with the current CA
    stamp_before = trust_stamp_after_reconcile(ctx, state_in, cert_obj, private_key)
    # AND nothing changes, the trust store is left untouched
    assert trust_stamp_after_reconcile(ctx, state_in, cert_obj, private_key) == stamp_before
    # WHEN only the CA rotates (same server cert and private key)
    rotated = MockCertificate(server_cert, "rotated_ca_certificate")
    stamp_after = trust_stamp_after_reconcile(ctx, state_in, rotated, private_key)
    # THEN the trust store is refreshed again
    assert stamp_after != stamp_before


@pytest.mark.skip(reason="https://github.com/canonical/operator/issues/1858")
def test_https_endpoint_is_provided(ctx, otelcol_container, cert_obj, private_key):
    """Scenario: Otelcol provides other charms its TLS endpoint."""
    # GIVEN otelcol is in TLS mode
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    data_source = Relation(
        endpoint="receive-loki-logs",
        interface="loki_push_api",
    )
    state_in = State(relations=[ssc, data_source], containers=otelcol_container)
    # WHEN a relation_changed event on the "receive-loki-logs" endpoint fires
    with (
        patch.object(TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None),
        patch.object(
            TLSCertificatesRequiresV4,
            "get_assigned_certificate",
            return_value=(cert_obj, private_key),
        ),
        patch.object(Certificate, "from_string", return_value=cert_obj),
    ):
        state_out = ctx.run(ctx.on.relation_changed(data_source), state=state_in)
    # THEN Otelcol provides its TLS endpoint in the databag
    for relation in state_out.relations:
        if relation.endpoint == "receive-loki-logs":
            assert "https" in json.loads(relation.local_unit_data["endpoint"])["url"]


FQDN = "otelcol-0.otelcol-endpoints.otel.svc.cluster.local"
CHARM_NAME = "opentelemetry-collector-k8s"


@patch("socket.getfqdn", new=lambda *args: FQDN)
def test_csr_requests_both_the_pod_and_the_service_name(ctx, otelcol_container):
    """Scenario: otelcol asks the CA for a certificate valid for the K8s Service too.

    Remote charms are handed the Kubernetes Service name, and any unit may terminate that
    connection, so every unit's certificate must be valid for it.
    """
    # GIVEN a tls-certificates relation
    ssc = Relation(endpoint="receive-server-cert", interface="tls-certificate")
    state_in = State(relations=[ssc], containers=otelcol_container, leader=True)

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the CSR sent to the CA lists both the pod name and the K8s Service name
    csrs = json.loads(
        state_out.get_relation(ssc.id).local_unit_data["certificate_signing_requests"]
    )
    assert csrs
    sans = CertificateSigningRequest.from_string(csrs[0]["certificate_signing_request"]).sans_dns
    assert sans == {FQDN, f"{CHARM_NAME}.{state_out.model.name}.svc.cluster.local"}


@patch("socket.getfqdn", new=lambda *args: FQDN)
def test_service_name_advertised_only_once_the_certificate_covers_it(ctx, otelcol_container):
    """Scenario: a charm refreshed from an older revision still holds a pod-only certificate.

    Advertising the Kubernetes Service name while serving a certificate that does not list it
    would break hostname verification for every client, so otelcol keeps advertising the pod
    name until the CA hands back a certificate that covers the Service name.
    """
    ssc = Relation(endpoint="receive-server-cert", interface="tls-certificate")
    receive_logs = Relation(endpoint="receive-loki-logs", interface="loki_push_api")
    state_in = State(relations=[ssc, receive_logs], containers=otelcol_container, leader=True)
    service = f"{CHARM_NAME}.{state_in.model.name}.svc.cluster.local"

    def advertised_url(issued) -> str:
        with (
            patch.object(
                TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None
            ),
            patch.object(
                TLSCertificatesRequiresV4,
                "get_assigned_certificate",
                return_value=(issued, issued.private_key),
            ),
        ):
            state_out = ctx.run(ctx.on.update_status(), state=state_in)
        logs_out = state_out.get_relation(receive_logs.id)
        return json.loads(logs_out.local_unit_data["endpoint"])["url"]

    # GIVEN the certificate on disk predates this feature and only covers the pod name
    # THEN the pod name is advertised, so that TLS clients can still verify the server
    assert FQDN in advertised_url(IssuedCertificate("otelcol-0", frozenset({FQDN})))

    # WHEN the CA issues the widened certificate
    # THEN the K8s Service name is advertised, so traffic is load-balanced across units
    widened = IssuedCertificate("otelcol-0", frozenset({FQDN, service}))
    assert service in advertised_url(widened)


def test_service_name_advertised_when_tls_is_disabled(ctx, otelcol_container):
    """Scenario: without TLS there is no certificate to satisfy, so no reason to hold back."""
    # GIVEN otelcol with no tls-certificates relation
    receive_logs = Relation(endpoint="receive-loki-logs", interface="loki_push_api")
    state_in = State(relations=[receive_logs], containers=otelcol_container, leader=True)

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the K8s Service name is advertised immediately
    url = json.loads(state_out.get_relation(receive_logs.id).local_unit_data["endpoint"])["url"]
    assert f"{CHARM_NAME}.{state_out.model.name}.svc.cluster.local" in url


@patch("socket.getfqdn", new=lambda *args: FQDN)
def test_refresh_replaces_a_pod_only_csr(ctx, otelcol_container):
    """Scenario: refreshing from a revision that only ever asked for the pod name.

    The certificate request is reconciled on every hook, so an existing narrow request is
    withdrawn and replaced without operator intervention. This is what makes a plain
    `juju refresh` enough to pick up the fix.
    """
    # GIVEN a tls-certificates relation carrying a CSR from the older revision
    stale_key = PrivateKey.generate()
    stale_csr = generate_csr(
        private_key=stale_key, common_name="otelcol-0", sans_dns=frozenset({FQDN})
    )
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
        local_unit_data={
            "certificate_signing_requests": json.dumps(
                [{"certificate_signing_request": str(stale_csr)}]
            )
        },
    )
    state_in = State(relations=[ssc], containers=otelcol_container, leader=True)

    # WHEN the refreshed charm executes the reconciler
    state_out = ctx.run(ctx.on.upgrade_charm(), state=state_in)

    # THEN the narrow request is gone, replaced by one that also covers the K8s Service name
    csrs = json.loads(
        state_out.get_relation(ssc.id).local_unit_data["certificate_signing_requests"]
    )
    all_sans = {
        san
        for csr in csrs
        for san in CertificateSigningRequest.from_string(
            csr["certificate_signing_request"]
        ).sans_dns
    }
    service = f"{CHARM_NAME}.{state_out.model.name}.svc.cluster.local"
    assert service in all_sans
    assert str(stale_csr) not in [csr["certificate_signing_request"] for csr in csrs]
