# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can run in HTTPS mode."""

import json
from unittest.mock import patch

import yaml
from ops.testing import Relation, State

from src.config_builder import Port

# TODO: itest -> assert ingress in databag/traefik and then check logs are pushed to Loki


def test_external_url_present(ctx, otelcol_container):
    # WHEN traefik ingress is related with external_host
    receive_logs_endpoint = Relation("receive-loki-logs")
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(
        relations=[ingress, receive_logs_endpoint], containers=otelcol_container, leader=True
    )

    out = ctx.run(ctx.on.relation_created(receive_logs_endpoint), state)

    # THEN external_url is present in tracing relation databag
    receive_logs_out = out.get_relations(receive_logs_endpoint.endpoint)[0]
    expected_data = {"url": "http://1.2.3.4/loki/api/v1/push"}
    assert json.loads(receive_logs_out.local_unit_data["endpoint"]) == expected_data


# TODO: https://github.com/canonical/traefik-k8s-operator/pull/450
@patch("socket.getfqdn", lambda: "1.2.3.4")
def test_no_tls_certificates_relation(ctx, otelcol_container):
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
    # TODO: Patch fqdn
    # TODO: steal tests from test_ingressed_tracing.py in Tempo
    # WHEN any event is emitted
    # THEN the config file doesn't include "key_file" nor "cert_file"


def test_ingress_config_middleware_tls(ctx, otelcol_container):
    # GIVEN an ingress relation with TLS
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "https"})

    state = State(relations=[ingress], containers=otelcol_container, leader=True)

    # WHEN relation is joined
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


tempo_cfg_from_cos = """
http:
  routers:
    juju-cos-tempo-jaeger-grpc:
      entryPoints:
      - jaeger-grpc
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-jaeger-grpc
    juju-cos-tempo-jaeger-grpc-tls:
      entryPoints:
      - jaeger-grpc
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-jaeger-grpc
      tls: {}
    juju-cos-tempo-jaeger-thrift-http:
      entryPoints:
      - jaeger-thrift-http
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-jaeger-thrift-http
    juju-cos-tempo-jaeger-thrift-http-tls:
      entryPoints:
      - jaeger-thrift-http
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-jaeger-thrift-http
      tls: {}
    juju-cos-tempo-otlp-grpc:
      entryPoints:
      - otlp-grpc
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-otlp-grpc
    juju-cos-tempo-otlp-grpc-tls:
      entryPoints:
      - otlp-grpc
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-otlp-grpc
      tls: {}
    juju-cos-tempo-otlp-http:
      entryPoints:
      - otlp-http
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-otlp-http
    juju-cos-tempo-otlp-http-tls:
      entryPoints:
      - otlp-http
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-otlp-http
      tls: {}
    juju-cos-tempo-tempo-grpc:
      entryPoints:
      - tempo-grpc
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-tempo-grpc
    juju-cos-tempo-tempo-grpc-tls:
      entryPoints:
      - tempo-grpc
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-tempo-grpc
      tls: {}
    juju-cos-tempo-tempo-http:
      entryPoints:
      - tempo-http
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-tempo-http
    juju-cos-tempo-tempo-http-tls:
      entryPoints:
      - tempo-http
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-tempo-http
      tls: {}
    juju-cos-tempo-zipkin:
      entryPoints:
      - zipkin
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-zipkin
    juju-cos-tempo-zipkin-tls:
      entryPoints:
      - zipkin
      rule: ClientIP(`0.0.0.0/0`)
      service: juju-cos-tempo-service-zipkin
      tls: {}
  services:
    juju-cos-tempo-service-jaeger-grpc:
      loadBalancer:
        servers:
        - url: https://tempo-0.tempo-endpoints.cos.svc.cluster.local:14250
    juju-cos-tempo-service-jaeger-thrift-http:
      loadBalancer:
        servers:
        - url: https://tempo-0.tempo-endpoints.cos.svc.cluster.local:14268
    juju-cos-tempo-service-otlp-grpc:
      loadBalancer:
        servers:
        - url: https://tempo-0.tempo-endpoints.cos.svc.cluster.local:4317
    juju-cos-tempo-service-otlp-http:
      loadBalancer:
        servers:
        - url: https://tempo-0.tempo-endpoints.cos.svc.cluster.local:4318
    juju-cos-tempo-service-tempo-grpc:
      loadBalancer:
        servers:
        - url: https://tempo-0.tempo-endpoints.cos.svc.cluster.local:9096
    juju-cos-tempo-service-tempo-http:
      loadBalancer:
        servers:
        - url: https://tempo-0.tempo-endpoints.cos.svc.cluster.local:3200
    juju-cos-tempo-service-zipkin:
      loadBalancer:
        servers:
        - url: https://tempo-0.tempo-endpoints.cos.svc.cluster.local:9411
"""
