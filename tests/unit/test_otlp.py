# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoint handling."""

import json
from unittest.mock import patch

import pytest
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    TLSCertificatesRequiresV4,
)
from helpers import get_otelcol_file
from ops.testing import Relation, State
from pydantic import ValidationError

from src.constants import (
    CONFIG_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
)
from src.integrations import cyclic_otlp_relations_exist
from src.otlp import OtlpEndpoint, OtlpProviderUnitData, ProtocolType, TelemetryType

UNITS_DATA = {0: {"data": '[{"protocol": "http", "endpoint": "http://host:4317", "telemetries": ["metrics"]}]'}}


@pytest.mark.parametrize(
    "data, error_match",
    [
        (
            {"protocol": "invalid", "endpoint": "http://host:4317", "telemetries": ["logs"]},
            "Input should be 'grpc' or 'http'",
        ),
        (
            {"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["invalid"]},
            "Input should be 'logs', 'metrics' or 'traces'",
        ),
    ],
)
def test_provider_app_data_raises_validation_error(data, error_match):
    """Test that OtlpProviderAppData validates protocols and telemetries."""
    with pytest.raises(ValidationError, match=error_match):
        OtlpProviderUnitData(data=[OtlpEndpoint(**data)])


# TODO: Add a test for more units and more relations
@pytest.mark.parametrize(
    "provides, otlp_endpoint",
    (
        (
            OtlpProviderUnitData(
                data=[
                    OtlpEndpoint(
                        protocol=ProtocolType.grpc,
                        endpoint="http://host:4317",
                        telemetries=[TelemetryType.log],
                    ),
                    OtlpEndpoint(
                        protocol=ProtocolType.http,
                        endpoint="http://host:4318",
                        telemetries=[TelemetryType.metric],
                    ),
                ]
            ),
            OtlpEndpoint(
                protocol=ProtocolType.grpc,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.log],
            ),
        ),
        (
            OtlpProviderUnitData(
                data=[
                    OtlpEndpoint(
                        protocol=ProtocolType.grpc,
                        endpoint="http://host:4317",
                        telemetries=[TelemetryType.metric],
                    ),
                    OtlpEndpoint(
                        protocol=ProtocolType.grpc,
                        endpoint="http://host:4317",
                        telemetries=[TelemetryType.trace],
                    ),
                ]
            ),
            OtlpEndpoint(
                protocol=ProtocolType.grpc,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.metric],
            ),
        ),
        (
            OtlpProviderUnitData(
                data=[
                    OtlpEndpoint(
                        protocol=ProtocolType.grpc,
                        endpoint="http://host:4317",
                        telemetries=[TelemetryType.trace],
                    ),
                ]
            ),
            OtlpEndpoint(
                protocol=ProtocolType.grpc,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.trace],
            ),
        ),
        (
            OtlpProviderUnitData(
                data=[
                    OtlpEndpoint(
                        protocol=ProtocolType.http,
                        endpoint="http://host:4318",
                        telemetries=[TelemetryType.log],
                    ),
                ]
            ),
            OtlpEndpoint(
                protocol=ProtocolType.http,
                endpoint="http://host:4318",
                telemetries=[TelemetryType.log],
            ),
        ),
        (
            OtlpProviderUnitData(
                data=[
                    OtlpEndpoint(
                        protocol=ProtocolType.http,
                        endpoint="http://host:4318",
                        telemetries=[TelemetryType.log, TelemetryType.metric],
                    ),
                ]
            ),
            OtlpEndpoint(
                protocol=ProtocolType.http,
                endpoint="http://host:4318",
                telemetries=[TelemetryType.log, TelemetryType.metric],
            ),
        ),
    ),
)
def test_send_otlp(ctx, otelcol_container, provides, otlp_endpoint):
    # GIVEN a remote app provides one (or multiple) OtlpEndpoint(s)
    # WHEN they are related over the "send-otlp" endpoint
    provider = Relation(
        "send-otlp",
        id=123,
        remote_units_data={0: {"data": json.dumps(provides.model_dump()["data"])}},
    )
    state = State(
        relations=[provider],
        leader=True,
        containers=otelcol_container,
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        mgr.run()
        # THEN the returned endpoint (many-to-one) is correct
        result = mgr.charm.otlp_consumer.get_remote_otlp_endpoints()[123]

    assert result.model_dump_json() == otlp_endpoint.model_dump_json()


@pytest.mark.parametrize(
    "provides, otlp_endpoint",
    (
        (
            [
                {"protocol": "http", "endpoint": "http://host:4317", "telemetries": ["metrics"]},
                {"protocol": "fake", "endpoint": "http://host:0000", "telemetries": ["metrics"]},
            ],
            OtlpEndpoint(
                protocol=ProtocolType.http,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.metric],
            ),
        ),
        (
            [
                {
                    "protocol": "http",
                    "endpoint": "http://host:4317",
                    "telemetries": ["logs", "fake", "traces"],
                },
            ],
            OtlpEndpoint(
                protocol=ProtocolType.http,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.log, TelemetryType.trace],
            ),
        ),
    ),
)
def test_send_otlp_invalid(ctx, otelcol_container, provides, otlp_endpoint):
    # GIVEN a remote app provides one (or multiple) invalid OtlpEndpoint(s)
    # WHEN they are related over the "send-otlp" endpoint
    provider = Relation(
        "send-otlp",
        id=123,
        remote_units_data={0: {"data": json.dumps(provides)}},
    )
    state = State(
        relations=[provider],
        leader=True,
        containers=otelcol_container,
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        mgr.run()
        # THEN the returned endpoint (many-to-one) is correct
        result = mgr.charm.otlp_consumer.get_remote_otlp_endpoints()[123]
    assert result.model_dump_json() == otlp_endpoint.model_dump_json()


@patch("socket.getfqdn", new=lambda *args: "fqdn")
def test_receive_otlp(ctx, otelcol_container):
    expected_endpoints = [
        OtlpEndpoint(
            protocol=ProtocolType.grpc,
            endpoint="http://fqdn:4317",
            telemetries=[TelemetryType.metric],
        ),
        OtlpEndpoint(
            protocol=ProtocolType.http,
            endpoint="http://fqdn:4318",
            telemetries=[TelemetryType.metric],
        ),
    ]

    # GIVEN a receive-otlp relation
    state = State(leader=True, containers=otelcol_container, relations=[Relation("receive-otlp")])

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        mgr.run()
        result = mgr.charm.otlp_provider.otlp_endpoints

    # THEN the OtlpProvider is supplying a list of its supported (endpoints) protocols and telemetries
    for idx, endpoint in enumerate(result):
        assert endpoint.model_dump_json() == expected_endpoints[idx].model_dump_json()


@patch("socket.getfqdn", new=lambda *args: "fqdn")
def test_exporter_mtls(ctx, otelcol_container, cert_obj, private_key):
    provides = [
        {"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["logs"]},
        {"protocol": "http", "endpoint": "http://host:4318", "telemetries": ["metrics"]},
    ]
    otlp = Relation(
        "send-otlp",
        id=123,
        remote_units_data={0: {"data": json.dumps(provides)}},
    )
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )

    # GIVEN the otelcol server is signed and communicating via OTLP
    state = State(leader=True, relations=[ssc, otlp], containers=otelcol_container)

    # AND WHEN any event executes the reconciler
    # TODO: Make these patches re-usable, also used in test_tls_certificates
    with (
        patch.object(TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None),
        patch.object(
            TLSCertificatesRequiresV4,
            "get_assigned_certificate",
            return_value=(cert_obj, private_key),
        ),
        patch.object(Certificate, "from_string", return_value=cert_obj),
    ):
        state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the OTLP exporter config has TLS configured
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert cfg["exporters"]["otlp/rel-123"]["tls"] == {
        "cert_file": SERVER_CERT_PATH,
        "insecure": False,
        "insecure_skip_verify": False,
        "key_file": SERVER_CERT_PRIVATE_KEY_PATH,
    }

    # AND WHEN the certificates relation departs
    state_out = ctx.run(ctx.on.relation_broken(ssc), state)

    # THEN the OTLP exporter config has no TLS configured
    cfg = get_otelcol_file(state_out, ctx, CONFIG_PATH)
    assert cfg["exporters"]["otlp/rel-123"]["tls"] == {
        "insecure": True,
        "insecure_skip_verify": False,
    }


@pytest.mark.parametrize(
    "relations, is_cyclic",
    (
        (
            [
                Relation("send-otlp", remote_app_name="a", remote_units_data=UNITS_DATA),
                Relation("receive-otlp", remote_app_name="b", remote_units_data=UNITS_DATA),
            ],
            False,
        ),
        (
            [
                Relation("send-otlp", remote_app_name="b", remote_units_data=UNITS_DATA),
                Relation("receive-otlp", remote_app_name="a", remote_units_data=UNITS_DATA),
            ],
            False,
        ),
        (
            [
                Relation("send-otlp", remote_app_name="a", remote_units_data=UNITS_DATA),
                Relation("receive-otlp", remote_app_name="a", remote_units_data=UNITS_DATA),
            ],
            True,
        ),
        (
            [
                Relation("send-otlp", remote_app_name="a", remote_units_data=UNITS_DATA),
                Relation("send-otlp", remote_app_name="b", remote_units_data=UNITS_DATA),
                Relation("receive-otlp", remote_app_name="b", remote_units_data=UNITS_DATA),
            ],
            True,
        ),
    ),
)
def test_cyclic_relations(ctx, otelcol_container, relations, is_cyclic):
    # GIVEN otelcol can send OTLP data to the same charm who just sent OTLP data, i.e. cyclic data
    state = State(
        relations=relations,
        leader=True,
        containers=otelcol_container,
    )

    # WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        mgr.run()
        result = cyclic_otlp_relations_exist(mgr.charm)

    # THEN the charm correctly identifies cyclic relations (one-level deep)
    assert result == is_cyclic
