import json
from unittest.mock import patch

import pytest
from ops.testing import Container, Relation, State

from charms.tls_certificates_interface.v4.tls_certificates import (
    TLSCertificatesRequiresV4,
    Certificate,
)
from src.constants import SERVICE_NAME, CONFIG_PATH
from tests.unit.helpers import get_otelcol_file


@pytest.fixture
def tls_mock(cert_obj, private_key):
    with (
        patch.object(TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None),
        patch.object(
            TLSCertificatesRequiresV4,
            "get_assigned_certificate",
            return_value=(cert_obj, private_key),
        ),
        patch.object(Certificate, "from_string", return_value=cert_obj),
    ):
        yield


@pytest.mark.parametrize("relation_joined", (True, False))
def test_waiting_for_send_profiles_endpoint(ctx, execs, relation_joined):
    """Scenario: a send_profiles relation joined, but we didn't get the grpc endpoint yet."""
    # GIVEN otelcol deployed in isolation
    container = Container(name="otelcol", can_connect=True, execs=execs)

    # WHEN a send_profiles relation joins but pyroscope didn't reply with an endpoint yet,
    # or the relation didn't join yet at all
    relations = (
        {
            Relation(
                endpoint="send-profiles",
            )
        }
        if relation_joined
        else {}
    )

    state_in = State(relations=relations, containers=[container])
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the pebble layer command and check contain no feature gate
    plan_out = state_out.get_container("otelcol").plan
    assert plan_out.services[SERVICE_NAME].command == f"/usr/bin/otelcol --config={CONFIG_PATH}"
    assert (
        plan_out.checks["valid-config"].exec["command"]
        == f"otelcol validate --config={CONFIG_PATH}"
    )


@pytest.mark.parametrize("relation_joined", (True, False))
def test_waiting_for_receive_profiles_endpoint(ctx, execs, relation_joined):
    """Scenario: a receive_profiles relation joined."""
    # GIVEN otelcol deployed in isolation
    container = Container(name="otelcol", can_connect=True, execs=execs)

    # WHEN a receive_profiles relation joins
    state_in = State(
        relations={
            Relation(
                endpoint="receive-profiles",
            )
        },
        containers=[container],
    )
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the pebble layer command and check contain the feature gate
    plan_out = state_out.get_container("otelcol").plan
    assert (
        plan_out.services[SERVICE_NAME].command
        == f"/usr/bin/otelcol --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    )
    assert (
        plan_out.checks["valid-config"].exec["command"]
        == f"otelcol validate --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    )


@pytest.mark.parametrize("insecure_skip_verify", (True, False))
@pytest.mark.parametrize("remote_insecure", (True, False))
def test_send_profiles_integration(ctx, execs, insecure_skip_verify, remote_insecure):
    """Scenario: a profiling relation joined and sent us a grpc endpoint."""
    # GIVEN otelcol deployed in isolation
    container = Container(name="otelcol", can_connect=True, execs=execs)

    pyro_url = "my.fqdn.cluster.local:12345"
    # WHEN a profiling relation joins and pyroscope sent an endpoint
    send_profiles = Relation(
        endpoint="send-profiles",
        remote_app_data={
            "otlp_grpc_endpoint_url": json.dumps(pyro_url),
            "insecure": json.dumps(remote_insecure),
        },
    )
    state_in = State(
        relations=[send_profiles],
        containers=[container],
        config={"tls_insecure_skip_verify": insecure_skip_verify},
    )
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the pebble layer command and check contain the profilesSupport feature gate
    plan_out = state_out.get_container("otelcol").plan
    assert (
        plan_out.services[SERVICE_NAME].command
        == f"/usr/bin/otelcol --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    )
    assert (
        plan_out.checks["valid-config"].exec["command"]
        == f"otelcol validate --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    )

    # AND the profiling pipeline contains an exporter to the expected url
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert cfg["service"]["pipelines"]["profiles"]["exporters"][0] == "otlp/profiling/0"
    assert cfg["service"]["pipelines"]["profiles"]["receivers"][0] == "otlp"
    assert cfg["exporters"]["otlp/profiling/0"]["endpoint"] == pyro_url
    assert cfg["exporters"]["otlp/profiling/0"]["tls"] == {
        "insecure": remote_insecure,
        "insecure_skip_verify": insecure_skip_verify,
    }


@patch("socket.getfqdn", return_value="localhost")
@pytest.mark.parametrize("insecure_skip_verify", (True, False))
def test_receive_profiles_integration(sock_mock, ctx, execs, insecure_skip_verify):
    """Scenario: a receive-profiles relation joined."""
    # GIVEN otelcol deployed in isolation
    container = Container(name="otelcol", can_connect=True, execs=execs)

    # WHEN a receive-profiles relation joins and pyroscope sent an endpoint
    receive_profiles = Relation(endpoint="receive-profiles")
    state_in = State(
        relations=[receive_profiles],
        containers=[container],
        config={"tls_insecure_skip_verify": insecure_skip_verify},
        leader=True,
    )
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the pebble layer command and check contain the profilesSupport feature gate
    plan_out = state_out.get_container("otelcol").plan
    assert (
        plan_out.services[SERVICE_NAME].command
        == f"/usr/bin/otelcol --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    )
    assert (
        plan_out.checks["valid-config"].exec["command"]
        == f"otelcol validate --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    )

    # AND the profiling pipeline contains a profiling pipeline, but no exporters other than debug
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert cfg["service"]["pipelines"]["profiles"]["exporters"] == [
        "debug/opentelemetry-collector-k8s/0"
    ]

    # AND we publish to app databag our profile ingestion endpoints for otlp_grpc
    receive_profiles_app_data = state_out.get_relation(receive_profiles.id).local_app_data
    assert receive_profiles_app_data["otlp_grpc_endpoint_url"]


@pytest.mark.parametrize("insecure_skip_verify", (True, False))
def test_profiling_integration_tls(ctx, execs, insecure_skip_verify, tls_mock):
    """Scenario: a profiling relation joined and sent us a grpc endpoint."""
    # GIVEN otelcol deployed with self-signed-certs
    container = Container(name="otelcol", can_connect=True, execs=execs)

    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )

    pyro_url = "my.fqdn.cluster.local:12345"
    # WHEN a profiling relation joins and pyroscope sent an endpoint
    profiling = Relation(
        endpoint="send-profiles",
        remote_app_data={
            "otlp_grpc_endpoint_url": json.dumps(pyro_url),
        },
    )
    state_in = State(
        relations=[profiling, ssc],
        containers=[container],
        config={"tls_insecure_skip_verify": insecure_skip_verify},
    )
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the pebble layer command and check contain the profilesSupport feature gate
    plan_out = state_out.get_container("otelcol").plan
    assert (
        plan_out.services[SERVICE_NAME].command
        == f"/usr/bin/otelcol --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    )
    assert (
        plan_out.checks["valid-config"].exec["command"]
        == f"otelcol validate --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    )

    # AND the profiling pipeline contains an exporter to the expected url
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert cfg["service"]["pipelines"]["profiles"]["exporters"][0] == "otlp/profiling/0"
    assert cfg["exporters"]["otlp/profiling/0"]["endpoint"] == pyro_url
    assert cfg["exporters"]["otlp/profiling/0"]["tls"] == {
        "insecure": False,
        "insecure_skip_verify": insecure_skip_verify,
    }
