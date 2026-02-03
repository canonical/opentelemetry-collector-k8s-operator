# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoint handling."""

import json
from unittest.mock import patch

import pytest
from ops.testing import Relation, State
from pydantic import ValidationError

from src.integrations import cyclic_otlp_relations_exist
from src.otlp import OtlpEndpoint, OtlpProviderUnitData, ProtocolType, TelemetryType

UNITS_DATA = {
    0: {
        OtlpProviderUnitData.KEY: '{"endpoints": [{"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["logs"]}]}'
    }
}


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
        OtlpProviderUnitData(endpoints=[OtlpEndpoint(**data)])


# TODO: Add a test for more units and more relations
@pytest.mark.parametrize(
    "provides, otlp_endpoint",
    (
        (
            OtlpProviderUnitData(
                endpoints=[
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
                endpoints=[
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
                endpoints=[
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
                endpoints=[
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
                endpoints=[
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
    input_databag = json.dumps(provides.model_dump())
    provider = Relation(
        "send-otlp",
        id=123,
        remote_units_data={0: {OtlpProviderUnitData.KEY: input_databag}},
    )
    state = State(
        relations=[provider],
        leader=True,
        containers=otelcol_container,
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()
        result = mgr.charm.otlp_consumer.get_remote_otlp_endpoints()[123]

    # THEN the databag contains multiple provider endpoints
    remote_unit_data = list(state_out.relations)[0].remote_units_data[0]
    assert remote_unit_data[OtlpProviderUnitData.KEY] == input_databag

    # AND the returned endpoint (many-to-one) is correct
    returned_endpoint = list(result.values())[0]
    assert returned_endpoint.model_dump_json() == otlp_endpoint.model_dump_json()


# NOTE: we cannot use OtlpProviderUnitData for "provides" since it would raise validation errors
@pytest.mark.parametrize(
    "provides, otlp_endpoint",
    (
        (
            {
                "endpoints": [
                    {
                        "protocol": "http",
                        "endpoint": "http://host:4317",
                        "telemetries": ["metrics"],
                    },
                    {
                        "protocol": "fake",
                        "endpoint": "http://host:0000",
                        "telemetries": ["metrics"],
                    },
                ]
            },
            OtlpEndpoint(
                protocol=ProtocolType.http,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.metric],
            ),
        ),
        (
            {
                "endpoints": [
                    {
                        "protocol": "http",
                        "endpoint": "http://host:4317",
                        "telemetries": ["logs", "fake", "traces"],
                    },
                ]
            },
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
        remote_units_data={0: {OtlpProviderUnitData.KEY: json.dumps(provides)}},
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

    returned_endpoint = list(result.values())[0]
    assert returned_endpoint.model_dump_json() == otlp_endpoint.model_dump_json()


@patch("socket.getfqdn", new=lambda *args: "fqdn")
def test_receive_otlp(ctx, otelcol_container):
    # GIVEN a receive-otlp relation
    state = State(
        leader=True,
        containers=otelcol_container,
        relations=[Relation("receive-otlp")],
    )

    # AND WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state)
    unit_data = list(state_out.relations)[0].local_unit_data

    # THEN otelcol offers its supported OTLP endpoints in the databag
    expected_endpoints = [
        {"protocol": "grpc", "endpoint": "http://fqdn:4317", "telemetries": ["metrics"]},
        {"protocol": "http", "endpoint": "http://fqdn:4318", "telemetries": ["metrics"]},
    ]
    assert json.loads(unit_data[OtlpProviderUnitData.KEY])["endpoints"] == expected_endpoints


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
