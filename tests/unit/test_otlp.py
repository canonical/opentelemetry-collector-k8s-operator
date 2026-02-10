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


# TODO: When moving some of these tests to the lib, we should still assert that this charm
#       correctly filters to only accepted telems, e.g. metrics
# TODO: Add an equivalent test in the lib for test_receive_otlp
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
def test_provider_app_data_raises_validation_error_lib(data, error_match):
    """Test that OtlpProviderAppData validates protocols and telemetries."""
    with pytest.raises(ValidationError, match=error_match):
        OtlpProviderAppData(endpoints=[OtlpEndpoint(**data)])


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
                telemetries=[TelemetryType.metrics],
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
                telemetries=[TelemetryType.logs, TelemetryType.traces],
            ),
        ),
    ),
)
def test_send_otlp_invalid_lib(ctx, otelcol_container, provides, otlp_endpoint):
    # GIVEN a remote app provides an invalid OtlpEndpoint
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

    with ctx(ctx.on.update_status(), state=state) as mgr:
        mgr.run()
        # AND WHEN the consumer supports all telemetries
        with (
            patch.object(mgr.charm.otlp_consumer, "_protocols", new=list(ProtocolType)),
            patch.object(mgr.charm.otlp_consumer, "_telemetries", new=list(TelemetryType)),
        ):
            result = mgr.charm.otlp_consumer.get_remote_otlp_endpoints()[123]

    # THEN the returned endpoint does not include invalid protocols or telemetries
    assert result.model_dump() == otlp_endpoint.model_dump()


@pytest.mark.parametrize(
    "protocols, telemetries, expected",
    [
        (
            list(ProtocolType),
            list(TelemetryType),
            {
                123: OtlpEndpoint(
                    protocol=ProtocolType.http,
                    endpoint="http://provider-123.endpoint:4318",
                    telemetries=[TelemetryType.logs, TelemetryType.metrics],
                ),
                456: OtlpEndpoint(
                    protocol=ProtocolType.grpc,
                    endpoint="http://provider-456.endpoint:4317",
                    telemetries=[TelemetryType.traces],
                ),
            },
        ),
        (
            [ProtocolType.grpc],
            list(TelemetryType),
            {
                456: OtlpEndpoint(
                    protocol=ProtocolType.grpc,
                    endpoint="http://provider-456.endpoint:4317",
                    telemetries=[TelemetryType.traces],
                )
            },
        ),
        (
            list(ProtocolType),
            [TelemetryType.metrics],
            {
                123: OtlpEndpoint(
                    protocol=ProtocolType.http,
                    endpoint="http://provider-123.endpoint:4318",
                    telemetries=[TelemetryType.metrics],
                ),
                456: OtlpEndpoint(
                    protocol=ProtocolType.http,
                    endpoint="http://provider-456.endpoint:4318",
                    telemetries=[TelemetryType.metrics],
                ),
            },
        ),
        ([ProtocolType.http], [TelemetryType.traces], {}),
    ],
)
def test_send_otlp_with_varying_consumer_support_lib(
    ctx, otelcol_container, protocols, telemetries, expected
):
    # GIVEN a remote app provides multiple OtlpEndpoints
    remote_app_data_1 = {
        OtlpProviderAppData.KEY: json.dumps(
            OtlpProviderAppData(
                endpoints=[
                    OtlpEndpoint(
                        protocol=ProtocolType.http,
                        endpoint="http://provider-123.endpoint:4318",
                        telemetries=[TelemetryType.logs, TelemetryType.metrics],
                    )
                ]
            ).model_dump()
        )
    }
    remote_app_data_2 = {
        OtlpProviderAppData.KEY: json.dumps(
            OtlpProviderAppData(
                endpoints=[
                    OtlpEndpoint(
                        protocol=ProtocolType.grpc,
                        endpoint="http://provider-456.endpoint:4317",
                        telemetries=[TelemetryType.traces],
                    ),
                    OtlpEndpoint(
                        protocol=ProtocolType.http,
                        endpoint="http://provider-456.endpoint:4318",
                        telemetries=[TelemetryType.metrics],
                    ),
                ]
            ).model_dump()
        )
    }

    # WHEN they are related over the "send-otlp" endpoint
    provider_0 = Relation(
        "send-otlp",
        id=123,
        remote_app_data=remote_app_data_1,
    )
    provider_1 = Relation(
        "send-otlp",
        id=456,
        remote_app_data=remote_app_data_2,
    )
    state = State(
        relations=[provider_0, provider_1],
        leader=True,
        containers=otelcol_container,
    )

    # AND WHEN the consumer has varying support for OTLP protocols and telemetries
    with ctx(ctx.on.update_status(), state=state) as mgr:
        with (
            patch.object(mgr.charm.otlp_consumer, "_protocols", new=protocols),
            patch.object(mgr.charm.otlp_consumer, "_telemetries", new=telemetries),
        ):
            remote_endpoints = mgr.charm.otlp_consumer.get_remote_otlp_endpoints()

    # THEN the returned endpoints are filtered accordingly
    assert {k: v.model_dump() for k, v in remote_endpoints.items()} == {
        k: v.model_dump() for k, v in expected.items()
    }


def test_send_otlp(ctx, otelcol_container):
    # GIVEN a remote app provides multiple OtlpEndpoints
    remote_app_data_1 = {
        OtlpProviderAppData.KEY: json.dumps(
            OtlpProviderAppData(
                endpoints=[
                    OtlpEndpoint(
                        protocol=ProtocolType.http,
                        endpoint="http://provider-123.endpoint:4318",
                        telemetries=[TelemetryType.logs, TelemetryType.metrics],
                    )
                ]
            ).model_dump()
        )
    }
    remote_app_data_2 = {
        OtlpProviderAppData.KEY: json.dumps(
            OtlpProviderAppData(
                endpoints=[
                    OtlpEndpoint(
                        protocol=ProtocolType.grpc,
                        endpoint="http://provider-456.endpoint:4317",
                        telemetries=[TelemetryType.traces],
                    ),
                    OtlpEndpoint(
                        protocol=ProtocolType.http,
                        endpoint="http://provider-456.endpoint:4318",
                        telemetries=[TelemetryType.metrics],
                    ),
                ]
            ).model_dump()
        )
    }

    expected_endpoints = {
        456: OtlpEndpoint(
            protocol=ProtocolType.http,
            endpoint="http://provider-456.endpoint:4318",
            telemetries=[TelemetryType.metrics],
        ),
        123: OtlpEndpoint(
            protocol=ProtocolType.http,
            endpoint="http://provider-123.endpoint:4318",
            telemetries=[TelemetryType.metrics],
        ),
    }

    # WHEN they are related over the "send-otlp" endpoint
    provider_1 = Relation(
        "send-otlp",
        id=123,
        remote_app_data=remote_app_data_1,
    )
    provider_2 = Relation(
        "send-otlp",
        id=456,
        remote_app_data=remote_app_data_2,
    )
    state = State(
        relations=[provider_1, provider_2],
        leader=True,
        containers=otelcol_container,
    )

    # AND WHEN the consumer has varying support for OTLP protocols and telemetries
    with ctx(ctx.on.update_status(), state=state) as mgr:
        remote_endpoints = mgr.charm.otlp_consumer.get_remote_otlp_endpoints()

    # THEN the returned endpoints are filtered accordingly
    assert {k: v.model_dump() for k, v in remote_endpoints.items()} == {
        k: v.model_dump() for k, v in expected_endpoints.items()
    }


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
    expected_endpoints = {
        "endpoints": [
            {
                "protocol": "http",
                "endpoint": "http://fqdn:4318",
                "telemetries": ["metrics"],
            }
        ],
    }
    assert json.loads(app_data[OtlpProviderAppData.KEY]) == expected_endpoints


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
