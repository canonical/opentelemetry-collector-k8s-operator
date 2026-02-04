# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoint handling."""

import json
from unittest.mock import patch

import pytest
from ops.testing import Relation, State
from pydantic import ValidationError

from src.integrations import cyclic_otlp_relations_exist
from src.otlp import OtlpEndpoint, OtlpProviderAppData, ProtocolType, TelemetryType

APP_DATA = {
    OtlpProviderAppData.KEY: '{"endpoints": [{"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["logs"]}]}'
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
        OtlpProviderAppData(endpoints=[OtlpEndpoint(**data)])


def test_send_otlp_multiple_relations(ctx, otelcol_container):
    # GIVEN a remote app provides multiple OtlpEndpoint per unit
    remote_app_data = {
        OtlpProviderAppData.KEY: json.dumps(
            OtlpProviderAppData(
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
            ).model_dump()
        )
    }

    expected_consumed_endpoints = {
        "remote": OtlpEndpoint(
            protocol=ProtocolType.grpc,
            endpoint="http://host:4317",
            telemetries=[TelemetryType.log],
        ),
    }

    # WHEN they are related over the "send-otlp" endpoint
    provider_0 = Relation(
        "send-otlp",
        id=123,
        remote_app_data=remote_app_data,
    )
    provider_1 = Relation(
        "send-otlp",
        id=321,
        remote_app_data=remote_app_data,
    )
    state = State(
        relations=[provider_0, provider_1],
        leader=True,
        containers=otelcol_container,
    )

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()
        remote_endpoints = mgr.charm.otlp_consumer.get_remote_otlp_endpoints()

    # THEN the databag contains multiple provider endpoints, per relation
    for rel in list(state_out.relations):
        assert rel.remote_app_data == remote_app_data

    # AND the returned endpoint (many-to-one) is correct
    expected = {k: v.model_dump() for k, v in expected_consumed_endpoints.items()}
    assert {k: v.model_dump() for k, v in remote_endpoints[123].items()} == expected
    assert {k: v.model_dump() for k, v in remote_endpoints[321].items()} == expected


# NOTE: we cannot use OtlpProviderAppData for "provides" since it would raise validation errors
@pytest.mark.parametrize(
    "provides, otlp_endpoint",
    (
        (
            {
                "endpoints": [
                    {
                        "protocol": "fake",
                        "endpoint": "http://host:0000",
                        "telemetries": ["metrics"],
                    },
                    {
                        "protocol": "http",
                        "endpoint": "http://host:4317",
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
        remote_app_data={OtlpProviderAppData.KEY: json.dumps(provides)},
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
    app_data = list(state_out.relations)[0].local_app_data

    # THEN otelcol offers its supported OTLP endpoints in the databag
    expected_endpoints = [
        {"protocol": "http", "endpoint": "http://fqdn:4318", "telemetries": ["metrics"]},
    ]
    assert json.loads(app_data[OtlpProviderAppData.KEY])["endpoints"] == expected_endpoints


@pytest.mark.parametrize(
    "relations, is_cyclic",
    (
        (
            [
                Relation("send-otlp", remote_app_name="a", remote_app_data=APP_DATA),
                Relation("receive-otlp", remote_app_name="b", remote_app_data=APP_DATA),
            ],
            False,
        ),
        (
            [
                Relation("send-otlp", remote_app_name="b", remote_app_data=APP_DATA),
                Relation("receive-otlp", remote_app_name="a", remote_app_data=APP_DATA),
            ],
            False,
        ),
        (
            [
                Relation("send-otlp", remote_app_name="a", remote_app_data=APP_DATA),
                Relation("receive-otlp", remote_app_name="a", remote_app_data=APP_DATA),
            ],
            True,
        ),
        (
            [
                Relation("send-otlp", remote_app_name="a", remote_app_data=APP_DATA),
                Relation("send-otlp", remote_app_name="b", remote_app_data=APP_DATA),
                Relation("receive-otlp", remote_app_name="b", remote_app_data=APP_DATA),
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
