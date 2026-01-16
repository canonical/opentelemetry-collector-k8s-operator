# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can operate behind an ingress."""

import json
from unittest.mock import patch

import yaml
from ops.testing import Relation, State

from src.config_builder import Port


def test_external_url_in_databag(ctx, otelcol_container):
    # WHEN traefik ingress is related to otelcol
    receive_logs_endpoint = Relation("receive-loki-logs")
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(
        relations=[ingress, receive_logs_endpoint], containers=otelcol_container, leader=True
    )

    out = ctx.run(ctx.on.relation_created(receive_logs_endpoint), state)

    # THEN external_url is present in receive-loki-logs relation databag
    receive_logs_out = out.get_relations(receive_logs_endpoint.endpoint)[0]
    expected_data = {"url": "http://1.2.3.4/loki/api/v1/push"}
    assert json.loads(receive_logs_out.local_unit_data["endpoint"]) == expected_data


@patch("socket.getfqdn", lambda: "1.2.3.4")
def test_traefik_sent_config(ctx, otelcol_container):
    """Scenario: Otelcol deployed without tls-certificates relation."""
    # GIVEN otelcol deployed in isolation
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(relations=[ingress], containers=otelcol_container, leader=True)

    charm_name = "opentelemetry-collector-k8s"
    expected_rel_data = {
        "http": {
            "routers": {
                f"juju-{state.model.name}-{charm_name}-health": {
                    "entryPoints": ["health"],
                    "rule": "ClientIP(`0.0.0.0/0`)",
                    "service": f"juju-{state.model.name}-{charm_name}-service-health",
                },
                f"juju-{state.model.name}-{charm_name}-jaeger-grpc": {
                    "entryPoints": ["jaeger-grpc"],
                    "rule": "ClientIP(`0.0.0.0/0`)",
                    "service": f"juju-{state.model.name}-{charm_name}-service-jaeger-grpc",
                },
                f"juju-{state.model.name}-{charm_name}-jaeger-thrift-http": {
                    "entryPoints": ["jaeger-thrift-http"],
                    "rule": "ClientIP(`0.0.0.0/0`)",
                    "service": f"juju-{state.model.name}-{charm_name}-service-jaeger-thrift-http",
                },
                f"juju-{state.model.name}-{charm_name}-loki-http": {
                    "entryPoints": ["loki-http"],
                    "rule": "ClientIP(`0.0.0.0/0`)",
                    "service": f"juju-{state.model.name}-{charm_name}-service-loki-http",
                },
                f"juju-{state.model.name}-{charm_name}-metrics": {
                    "entryPoints": ["metrics"],
                    "rule": "ClientIP(`0.0.0.0/0`)",
                    "service": f"juju-{state.model.name}-{charm_name}-service-metrics",
                },
                f"juju-{state.model.name}-{charm_name}-otlp-grpc": {
                    "entryPoints": ["otlp-grpc"],
                    "rule": "ClientIP(`0.0.0.0/0`)",
                    "service": f"juju-{state.model.name}-{charm_name}-service-otlp-grpc",
                },
                f"juju-{state.model.name}-{charm_name}-otlp-http": {
                    "entryPoints": ["otlp-http"],
                    "rule": "ClientIP(`0.0.0.0/0`)",
                    "service": f"juju-{state.model.name}-{charm_name}-service-otlp-http",
                },
                f"juju-{state.model.name}-{charm_name}-zipkin": {
                    "entryPoints": ["zipkin"],
                    "rule": "ClientIP(`0.0.0.0/0`)",
                    "service": f"juju-{state.model.name}-{charm_name}-service-zipkin",
                },
            },
            "services": {
                f"juju-{state.model.name}-{charm_name}-service-health": {
                    "loadBalancer": {"servers": [{"url": "http://1.2.3.4:13133"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-jaeger-grpc": {
                    "loadBalancer": {"servers": [{"url": "http://1.2.3.4:14250"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-jaeger-thrift-http": {
                    "loadBalancer": {"servers": [{"url": "http://1.2.3.4:14268"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-loki-http": {
                    "loadBalancer": {"servers": [{"url": "http://1.2.3.4:3500"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-metrics": {
                    "loadBalancer": {"servers": [{"url": "http://1.2.3.4:8888"}]},
                },
                f"juju-{state.model.name}-{charm_name}-service-otlp-grpc": {
                    "loadBalancer": {"servers": [{"url": "http://1.2.3.4:4317"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-otlp-http": {
                    "loadBalancer": {"servers": [{"url": "http://1.2.3.4:4318"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-zipkin": {
                    "loadBalancer": {"servers": [{"url": "http://1.2.3.4:9411"}]}
                },
            },
        },
    }

    out = ctx.run(ctx.on.relation_joined(ingress), state)

    # THEN dynamic config is present in ingress relation
    ingress_out = out.get_relations(ingress.endpoint)[0]
    assert ingress_out.local_app_data
    assert yaml.safe_load(ingress_out.local_app_data["config"]) == expected_rel_data


def test_ingress_config_middleware_tls(ctx, otelcol_container):
    # GIVEN an ingress relation with TLS
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "https"})

    state = State(relations=[ingress], containers=otelcol_container, leader=True)

    # WHEN the ingress relation joins
    out = ctx.run(ctx.on.relation_joined(ingress), state)

    # THEN middleware config is present in ingress config
    ingress_out = out.get_relations(ingress.endpoint)[0]
    assert ingress_out.local_app_data
    config = yaml.safe_load(ingress_out.local_app_data["config"])
    middlewares = config["http"]["middlewares"]
    charm_name = "opentelemetry-collector-k8s"
    for port in Port:
        middleware = (
            f"juju-{state.model.name}-{charm_name}-middleware-{port.name.replace('_', '-')}"
        )
        assert middleware in middlewares
        assert middlewares[middleware] == {
            "redirectScheme": {
                "permanent": True,
                "port": port,
                "scheme": "https",
            }
        }
