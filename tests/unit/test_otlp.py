# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoint handling."""

import json

import pytest
from ops.testing import Relation, State

from src.otlp import OtlpEndpoint


@pytest.mark.parametrize(
    "provides, otlp_endpoint",
    (
        (
            [
                {"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["logs"]},
                {"protocol": "http", "endpoint": "http://host:4318", "telemetries": ["metrics"]},
            ],
            OtlpEndpoint(protocol="grpc", endpoint="http://host:4317", telemetries=["logs"]),
        ),
        (
            [
                {"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["metrics"]},
                {"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["traces"]},
            ],
            OtlpEndpoint(protocol="grpc", endpoint="http://host:4317", telemetries=["metrics"]),
        ),
        (
            [{"protocol": "grpc", "endpoint": "http://host:4317", "telemetries": ["traces"]}],
            OtlpEndpoint(protocol="grpc", endpoint="http://host:4317", telemetries=["traces"]),
        ),
        (
            [{"protocol": "http", "endpoint": "http://host:4318", "telemetries": ["logs"]}],
            OtlpEndpoint(protocol="http", endpoint="http://host:4318", telemetries=["logs"]),
        ),
        (
            [
                {
                    "protocol": "http",
                    "endpoint": "http://host:4318",
                    "telemetries": ["logs", "metrics"],
                }
            ],
            OtlpEndpoint(
                protocol="http", endpoint="http://host:4318", telemetries=["logs", "metrics"]
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


# TODO: Test multiple otlp relations (send and receive)


@pytest.mark.parametrize(
    "provides, otlp_endpoint",
    (
        (
            [{"protocol": "invalid", "endpoint": "http://host:4317", "telemetries": ["logs"]}],
            OtlpEndpoint(protocol="grpc", endpoint="http://host:4317", telemetries=["logs"]),
        ),
        (
            [{"protocol": "grpc", "endpoint": "invalid", "telemetries": ["logs"]}],
            OtlpEndpoint(protocol="grpc", endpoint="http://host:4317", telemetries=["logs"]),
        ),
        (
            [{"protocol": "grpc", "endpoint": "foo://host:4317", "telemetries": ["invalid"]}],
            OtlpEndpoint(protocol="grpc", endpoint="http://host:4317", telemetries=["logs"]),
        ),
    ),
)
def test_send_otlp_invalid(ctx, otelcol_container, provides, otlp_endpoint):
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
        # TODO: fix this so that it errors in otlp.py or something?
        result = mgr.charm.otlp_consumer.get_remote_otlp_endpoint()[123]
        assert result.model_dump_json() == otlp_endpoint.model_dump_json()
