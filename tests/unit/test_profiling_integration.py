import contextlib
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
    with patch.object(
        TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None
    ), patch.object(
        TLSCertificatesRequiresV4, "get_assigned_certificate", return_value=(cert_obj, private_key)
    ), patch.object(Certificate, "from_string", return_value=cert_obj):
        yield


@pytest.mark.parametrize("relation_joined", (True, False))
def test_waiting_for_profiling_endpoint(ctx, execs, relation_joined):
    """Scenario: a profiling relation joined, but we didn't get the grpc endpoint yet."""
    # GIVEN otelcol deployed in isolation
    container = Container(name="otelcol", can_connect=True, execs=execs)

    # WHEN a profiling relation joins but pyroscope didn't reply with an endpoint yet,
    # or the relation didn't join yet at all
    relations = {Relation(
        endpoint="send-profiles",
    )} if relation_joined else {}

    state_in = State(relations=relations, containers=[container])
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the pebble layer command and check contain no feature gate
    plan_out = state_out.get_container("otelcol").plan
    assert plan_out.services[SERVICE_NAME].command == f"/usr/bin/otelcol --config={CONFIG_PATH}"
    assert plan_out.checks["valid-config"].exec['command'] == f"otelcol validate --config={CONFIG_PATH}"


@pytest.mark.parametrize("insecure_skip_verify", (True, False))
def test_profiling_integration(ctx, execs, insecure_skip_verify):
    """Scenario: a profiling relation joined and sent us a grpc endpoint."""
    # GIVEN otelcol deployed in isolation
    container = Container(name="otelcol", can_connect=True, execs=execs)

    pyro_url = "my.fqdn.cluster.local:12345"
    # WHEN a profiling relation joins and pyroscope sent an endpoint
    profiling = Relation(
        endpoint="send-profiles",
        remote_app_data={"otlp_grpc_endpoint_url": json.dumps(pyro_url)}
    )
    state_in = State(relations=[profiling], containers=[container],
                     config={"tls_insecure_skip_verify": insecure_skip_verify})
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the pebble layer command and check contain the profilesSupport feature gate
    plan_out = state_out.get_container("otelcol").plan
    assert plan_out.services[SERVICE_NAME].command == f"/usr/bin/otelcol --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    assert plan_out.checks["valid-config"].exec['command'] == f"otelcol validate --config={CONFIG_PATH} --feature-gates=service.profilesSupport"

    # AND the profiling pipeline contains an exporter to the expected url
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert cfg['service']['pipelines']['profiles']['exporters'][0] == 'otlp/profiling/0'
    assert cfg['exporters']['otlp/profiling/0']['endpoint'] == pyro_url
    assert cfg["exporters"]["otlp/profiling/0"]["tls"] == {"insecure": True, "insecure_skip_verify": insecure_skip_verify}



@pytest.mark.xfail(reason="pyroscope does not support TLS ingestion yet")
# cfr. FIXME in config_manager.ConfigManager.add_profiling
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
        remote_app_data={"otlp_grpc_endpoint_url": json.dumps(pyro_url)}
    )
    state_in = State(relations=[profiling, ssc], containers=[container],
                     config={"tls_insecure_skip_verify": insecure_skip_verify})
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the pebble layer command and check contain the profilesSupport feature gate
    plan_out = state_out.get_container("otelcol").plan
    assert plan_out.services[SERVICE_NAME].command == f"/usr/bin/otelcol --config={CONFIG_PATH} --feature-gates=service.profilesSupport"
    assert plan_out.checks["valid-config"].exec['command'] == f"otelcol validate --config={CONFIG_PATH} --feature-gates=service.profilesSupport"

    # AND the profiling pipeline contains an exporter to the expected url
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert cfg['service']['pipelines']['profiles']['exporters'][0] == 'otlp/profiling/0'
    assert cfg['exporters']['otlp/profiling/0']['endpoint'] == pyro_url
    assert cfg["exporters"]["otlp/profiling/0"]["tls"] == {"insecure": False, "insecure_skip_verify": insecure_skip_verify}


