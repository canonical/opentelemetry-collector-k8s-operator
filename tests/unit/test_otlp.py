# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoint handling."""

import json

import pytest
from ops.testing import Relation, State
from pydantic import ValidationError

from src.otlp import OtlpEndpoint, OtlpProviderAppData, ProtocolType, TelemetryType


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
        OtlpProviderAppData(data=[OtlpEndpoint(**data)])


@pytest.mark.parametrize(
    "provides, otlp_endpoint",
    (
        (
            [
                '{"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["logs"]}',
                '{"protocol": "http", "endpoint": "http://host:4318", "telemetries": ["metrics"]}',
            ],
            OtlpEndpoint(
                protocol=ProtocolType.grpc,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.log],
            ),
        ),
        (
            [
                '{"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["metrics"]}',
                '{"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["traces"]}',
            ],
            OtlpEndpoint(
                protocol=ProtocolType.grpc,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.metric],
            ),
        ),
        (
            ['{"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["traces"]}'],
            OtlpEndpoint(
                protocol=ProtocolType.grpc,
                endpoint="http://host:4317",
                telemetries=[TelemetryType.trace],
            ),
        ),
        (
            ['{"protocol": "http", "endpoint": "http://host:4318", "telemetries": ["logs"]}'],
            OtlpEndpoint(
                protocol=ProtocolType.http,
                endpoint="http://host:4318",
                telemetries=[TelemetryType.log],
            ),
        ),
        (
            [
                '{"protocol": "http","endpoint": "http://host:4318","telemetries": ["logs", "metrics"]}'
            ],
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
        remote_app_data={"data": json.dumps(provides)},
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
        result = mgr.charm.otlp_consumer.get_remote_otlp_endpoint()[123]
        assert result.model_dump_json() == otlp_endpoint.model_dump_json()

# TODO: Test receive_otlp which ensures that otlp_endpoints is correct. The test above checks that the consumer is able to get the endpoints from provider
