# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: otelcol advertises a reachable, load-balanced address when Traefik fronts it.

The tests below are one progressive scenario over a single model, in order.
"""

import logging
import subprocess

import jubilant
import pytest
from helpers import (
    assert_health_reachable_through_ingress,
    assert_loki_logs_accepted_through_ingress,
    assert_no_tls_verification_errors,
    assert_otlp_accepted_through_ingress,
    assert_otlp_logs_reach_pipeline_through_ingress,
    ingress_url,
    otlp_exporter,
    otlp_exporter_endpoint,
    wait_settled,
)
from src.config_builder import Port

logger = logging.getLogger(__name__)

# gRPC wire format: one byte for the compression flag, four bytes for the message length,
# then the message. An empty OTLP ExportLogsServiceRequest is a zero-length protobuf message.
GRPC_EMPTY_MESSAGE = b"\x00\x00\x00\x00\x00"
OTLP_LOGS_EXPORT_PATH = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"

# pyright: reportAttributeAccessIssue = false


@pytest.mark.usefixtures("sender_and_sink")
def test_traefik_ingress_advertises_the_external_host(juju: jubilant.Juju):
    """Scenario: an ingressed otelcol advertises Traefik's host, not the in-cluster Service."""
    # GIVEN otelcol is fronted by Traefik
    juju.deploy("traefik-k8s", "traefik", channel="latest/stable", trust=True)
    juju.integrate("otelcol:ingress", "traefik")
    wait_settled(juju, "otelcol", "traefik")

    # THEN the sender targets Traefik's external host over gRPC, not the in-cluster Service
    endpoint = otlp_exporter_endpoint(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" not in endpoint, (
        f"expected the ingress host in {endpoint!r}, got the in-cluster Service"
    )
    assert endpoint.endswith(f":{Port.otlp_grpc.value}"), (
        f"expected the gRPC endpoint advertised through Traefik, got {endpoint!r}"
    )


def _curl_supports_http2() -> bool:
    """Return whether the local curl can speak cleartext HTTP/2."""
    result = subprocess.run(["curl", "--version"], capture_output=True, check=False)
    return b"HTTP2" in result.stdout


@pytest.mark.usefixtures("sender_and_sink")
def test_otlp_grpc_is_reachable_through_traefik_ingress(juju: jubilant.Juju):
    """Scenario: a cleartext gRPC request reaches otelcol through Traefik."""
    # GIVEN Traefik fronts otelcol, and the local curl can speak HTTP/2
    if not _curl_supports_http2():
        pytest.skip("curl is not built with HTTP/2 support")

    # WHEN a cleartext gRPC request hits the otlp-grpc entrypoint
    url = ingress_url(juju, "traefik")
    if url.startswith("https://"):
        pytest.skip("this test targets the cleartext h2c entrypoint")
    target = f"{url}:{Port.otlp_grpc.value}{OTLP_LOGS_EXPORT_PATH}"
    result = subprocess.run(
        [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--http2-prior-knowledge",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/grpc",
            "-H",
            "TE: trailers",
            "--data-binary",
            "@-",
            target,
        ],
        input=GRPC_EMPTY_MESSAGE,
        capture_output=True,
        check=False,
    )

    # THEN the request reached the collector over gRPC rather than failing at the protocol hop
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout.decode().strip() == "200", (
        f"expected HTTP 200 from {target}, got {result.stdout!r} "
        f"(stderr: {result.stderr.decode()!r})"
    )


@pytest.mark.usefixtures("sender_and_sink")
def test_receivers_are_reachable_through_traefik_ingress(juju: jubilant.Juju):
    """Scenario: every receiver otelcol exposes answers through the ingress."""
    # GIVEN otelcol ingests Loki logs, and writes what it receives to its own log
    juju.integrate("sender:send-loki-logs", "otelcol:receive-loki-logs")
    juju.config("otelcol", {"debug_exporter_for_logs": True})
    wait_settled(juju, "otelcol", "traefik", "sender")

    # THEN the health endpoint answers through the ingress
    assert_health_reachable_through_ingress(juju, "traefik")
    # AND a Loki-format push is accepted
    assert_loki_logs_accepted_through_ingress(juju, "traefik")
    # AND an OTLP push comes out of otelcol's pipeline. Asserting on content requires a single
    # unit, so this must run before the scaling test.
    assert_otlp_logs_reach_pipeline_through_ingress(juju, "traefik")


@pytest.mark.usefixtures("sender_and_sink")
def test_scaling_behind_traefik_ingress(juju: jubilant.Juju):
    """Scenario: a scaled, ingressed otelcol still targets one, reachable address."""
    # GIVEN the ingressed otelcol from the previous tests
    endpoint_before_scaling = otlp_exporter_endpoint(juju, "sender")

    # WHEN otelcol is scaled out
    juju.add_unit("otelcol", num_units=2)
    wait_settled(juju, "otelcol", "traefik")

    # THEN the sender's config is unchanged: still one endpoint, so scaling out does not
    # multiply what is sent
    assert otlp_exporter_endpoint(juju, "sender") == endpoint_before_scaling

    # AND telemetry pushed at that endpoint is accepted by every unit that answers it
    assert_otlp_accepted_through_ingress(juju, "traefik")


@pytest.mark.usefixtures("sender_and_sink")
def test_scaling_behind_traefik_ingress_with_tls(juju: jubilant.Juju):
    """Scenario: every otelcol unit behind Traefik must serve TLS for the address Traefik dials.

    Traefik verifies the hostname of its backend and dials the Kubernetes Service, which
    answers from an arbitrary unit, so every unit's certificate must cover the Service name.
    """
    # GIVEN the scaled, Traefik-ingressed otelcol from the previous test, now serving TLS
    juju.deploy("self-signed-certificates", "ssc")
    juju.integrate("otelcol:receive-server-cert", "ssc:certificates")
    juju.integrate("sender:receive-ca-cert", "ssc:send-ca-cert")
    # AND Traefik trusts otelcol's CA, otherwise it cannot verify the backend it dials
    juju.integrate("traefik:receive-ca-cert", "ssc:send-ca-cert")
    wait_settled(juju, "otelcol", "traefik", "ssc", "sender")

    # THEN the plaintext-only health endpoint still answers through the ingress
    assert_health_reachable_through_ingress(juju, "traefik")

    # AND the sender still targets Traefik over gRPC, and still in plaintext: Traefik serves
    # HTTPS only once Traefik itself has a certificate, so a TLS backend must not change what
    # senders get
    exporter = otlp_exporter(juju, "sender")
    endpoint = exporter["endpoint"]
    assert f"otelcol.{juju.model}.svc.cluster.local" not in endpoint, (
        f"expected the ingress host in {endpoint!r}, got the in-cluster Service"
    )
    assert endpoint.endswith(f":{Port.otlp_grpc.value}"), (
        f"expected the gRPC endpoint advertised through Traefik, got {endpoint!r}"
    )
    assert exporter["tls"]["insecure"] is True, (
        f"expected the sender to reach Traefik in plaintext, got {exporter['tls']}"
    )

    # AND every push is accepted, whichever unit answers: Traefik dials the Service, so a
    # certificate covering only one pod fails hostname verification for all the others
    assert_otlp_accepted_through_ingress(juju, "traefik")


@pytest.mark.usefixtures("sender_and_sink")
def test_removing_traefik_ingress_falls_back_to_the_service(juju: jubilant.Juju):
    """Scenario: un-ingressing a TLS otelcol falls back to the in-cluster Service."""
    # GIVEN the scaled, TLS otelcol from the previous test
    # WHEN Traefik and its ingress relation are removed
    juju.remove_relation("otelcol:ingress", "traefik")
    juju.remove_application("traefik")
    # An app on its way out can report error, which says nothing about otelcol
    wait_settled(juju, "otelcol", "sender", error_on=("otelcol", "sender"))

    # THEN the sender falls back to the in-cluster Service over gRPC, with TLS and without
    # certificate errors, since every unit's certificate also covers the Service name and gRPC
    # endpoints carry no scheme, hence the `insecure` check.
    exporter = otlp_exporter(juju, "sender")
    assert f"otelcol.{juju.model}.svc.cluster.local" in exporter["endpoint"]
    assert exporter["tls"]["insecure"] is False, (
        f"expected {exporter['endpoint']!r} to be reached over TLS, got {exporter['tls']}"
    )
    assert_no_tls_verification_errors(juju, "sender")
