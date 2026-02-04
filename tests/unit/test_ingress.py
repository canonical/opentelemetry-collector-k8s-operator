# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can operate behind an ingress."""

import json
from typing import Any, List
from unittest.mock import patch

import yaml
from ops.testing import Relation, State

from src.config_builder import Port
from src.constants import INGRESS_IP_MATCHER
from src.otlp import OtlpProviderAppData


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
                    "rule": INGRESS_IP_MATCHER,
                    "service": f"juju-{state.model.name}-{charm_name}-service-health",
                },
                f"juju-{state.model.name}-{charm_name}-jaeger-grpc": {
                    "entryPoints": ["jaeger-grpc"],
                    "rule": INGRESS_IP_MATCHER,
                    "service": f"juju-{state.model.name}-{charm_name}-service-jaeger-grpc",
                },
                f"juju-{state.model.name}-{charm_name}-jaeger-thrift-http": {
                    "entryPoints": ["jaeger-thrift-http"],
                    "rule": INGRESS_IP_MATCHER,
                    "service": f"juju-{state.model.name}-{charm_name}-service-jaeger-thrift-http",
                },
                f"juju-{state.model.name}-{charm_name}-loki-http": {
                    "entryPoints": ["loki-http"],
                    "rule": INGRESS_IP_MATCHER,
                    "service": f"juju-{state.model.name}-{charm_name}-service-loki-http",
                },
                f"juju-{state.model.name}-{charm_name}-metrics": {
                    "entryPoints": ["metrics"],
                    "rule": INGRESS_IP_MATCHER,
                    "service": f"juju-{state.model.name}-{charm_name}-service-metrics",
                },
                f"juju-{state.model.name}-{charm_name}-otlp-grpc": {
                    "entryPoints": ["otlp-grpc"],
                    "rule": INGRESS_IP_MATCHER,
                    "service": f"juju-{state.model.name}-{charm_name}-service-otlp-grpc",
                },
                f"juju-{state.model.name}-{charm_name}-otlp-http": {
                    "entryPoints": ["otlp-http"],
                    "rule": INGRESS_IP_MATCHER,
                    "service": f"juju-{state.model.name}-{charm_name}-service-otlp-http",
                },
                f"juju-{state.model.name}-{charm_name}-zipkin": {
                    "entryPoints": ["zipkin"],
                    "rule": INGRESS_IP_MATCHER,
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


@patch("socket.getfqdn", new=lambda *args: "fqdn")
def test_loki_url_in_databag(ctx, otelcol_container):
    # WHEN traefik ingress is related to otelcol
    receive_logs_endpoint = Relation("receive-loki-logs")
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(
        relations=[ingress, receive_logs_endpoint], containers=otelcol_container, leader=True
    )

    # AND WHEN the ingress relation is created
    out_1 = ctx.run(ctx.on.relation_created(ingress), state)

    # THEN ingress URL is present in receive-loki-logs relation databag
    receive_logs_out = out_1.get_relations(receive_logs_endpoint.endpoint)[0]
    expected_data = {"url": f"http://1.2.3.4:{Port.loki_http.value}/loki/api/v1/push"}
    assert json.loads(receive_logs_out.local_unit_data["endpoint"]) == expected_data

    # AND WHEN the receive-loki-logs relation is created
    out_2 = ctx.run(ctx.on.relation_created(receive_logs_endpoint), state)

    # THEN ingress URL is present in receive-loki-logs relation databag
    receive_logs_out = out_2.get_relations(receive_logs_endpoint.endpoint)[0]
    expected_data = {"url": f"http://1.2.3.4:{Port.loki_http.value}/loki/api/v1/push"}
    assert json.loads(receive_logs_out.local_unit_data["endpoint"]) == expected_data

    # AND WHEN ingress is removed
    out_3 = ctx.run(ctx.on.relation_broken(ingress), state)
    # THEN the internal URL is present in receive-loki-logs relation databag
    receive_logs_out = out_3.get_relations(receive_logs_endpoint.endpoint)[0]
    expected_data = {"url": f"http://fqdn:{Port.loki_http.value}/loki/api/v1/push"}
    assert json.loads(receive_logs_out.local_unit_data["endpoint"]) == expected_data


@patch("socket.getfqdn", new=lambda *args: "fqdn")
def test_otlp_url_in_databag(ctx, otelcol_container):
    def expected_endpoints(ingress: bool) -> List[dict[str, Any]]:
        host = "1.2.3.4" if ingress else "fqdn"
        return [
            {
                "protocol": "http",
                "endpoint": f"http://{host}:{Port.otlp_http.value}",
                "telemetries": ["metrics"],
            },
        ]

    # WHEN traefik ingress is related to otelcol
    receive_otlp = Relation("receive-otlp")
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(relations=[ingress, receive_otlp], containers=otelcol_container, leader=True)

    # AND WHEN the ingress relation is created
    out_1 = ctx.run(ctx.on.relation_created(ingress), state)

    # THEN ingress URL is present in receive-otlp relation databag
    receive_otlp_out = out_1.get_relations(receive_otlp.endpoint)[0]
    assert json.loads(receive_otlp_out.local_app_data[OtlpProviderAppData.KEY])[
        "endpoints"
    ] == expected_endpoints(ingress=True)

    # AND WHEN the receive-otlp relation is created
    out_2 = ctx.run(ctx.on.relation_created(receive_otlp), state)

    # THEN ingress URL is present in receive-otlp relation databag
    receive_otlp_out = out_2.get_relations(receive_otlp.endpoint)[0]
    assert json.loads(receive_otlp_out.local_app_data[OtlpProviderAppData.KEY])[
        "endpoints"
    ] == expected_endpoints(ingress=True)

    # AND WHEN ingress is removed
    out_3 = ctx.run(ctx.on.relation_broken(ingress), state)
    # THEN the internal URL is present in receive-otlp relation databag
    receive_otlp_out = out_3.get_relations(receive_otlp.endpoint)[0]
    assert json.loads(receive_otlp_out.local_app_data[OtlpProviderAppData.KEY])[
        "endpoints"
    ] == expected_endpoints(ingress=False)
