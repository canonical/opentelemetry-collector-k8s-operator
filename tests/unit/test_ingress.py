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

FQDN = "otelcol-0.otelcol-endpoints.otel.svc.cluster.local"


@patch("socket.getfqdn", lambda: FQDN)
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
                    "loadBalancer": {"servers": [{"url": f"http://{FQDN}:13133"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-jaeger-grpc": {
                    "loadBalancer": {"servers": [{"url": f"http://{FQDN}:14250"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-jaeger-thrift-http": {
                    "loadBalancer": {"servers": [{"url": f"http://{FQDN}:14268"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-loki-http": {
                    "loadBalancer": {"servers": [{"url": f"http://{FQDN}:3500"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-metrics": {
                    "loadBalancer": {"servers": [{"url": f"http://{FQDN}:8888"}]},
                },
                f"juju-{state.model.name}-{charm_name}-service-otlp-grpc": {
                    "loadBalancer": {"servers": [{"url": f"http://{FQDN}:4317"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-otlp-http": {
                    "loadBalancer": {"servers": [{"url": f"http://{FQDN}:4318"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-zipkin": {
                    "loadBalancer": {"servers": [{"url": f"http://{FQDN}:9411"}]}
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


@patch("socket.getfqdn", lambda: "fqdn")
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
                "telemetries": ["metrics", "logs", "traces"],
                "insecure": False,
            },
        ]

    # WHEN traefik ingress is related to otelcol
    rules = json.dumps({"logql": {}, "promql": {}})
    receive_otlp = Relation("receive-otlp", remote_app_data={"rules": rules, "metadata": "{}"})
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(relations=[ingress, receive_otlp], containers=otelcol_container, leader=True)

    # AND WHEN the ingress relation is created
    out_1 = ctx.run(ctx.on.relation_created(ingress), state)

    # THEN ingress URL is present in receive-otlp relation databag
    receive_otlp_out = out_1.get_relations(receive_otlp.endpoint)[0]
    endpoints = json.loads(receive_otlp_out.local_app_data.get("endpoints", "[]"))
    assert endpoints == expected_endpoints(ingress=True)

    # AND WHEN the receive-otlp relation is created
    out_2 = ctx.run(ctx.on.relation_created(receive_otlp), state)

    # THEN ingress URL is present in receive-otlp relation databag
    receive_otlp_out = out_2.get_relations(receive_otlp.endpoint)[0]
    endpoints = json.loads(receive_otlp_out.local_app_data.get("endpoints", "[]"))
    assert endpoints == expected_endpoints(ingress=True)

    # AND WHEN ingress is removed
    out_3 = ctx.run(ctx.on.relation_broken(ingress), state)
    # THEN the internal URL is present in receive-otlp relation databag
    receive_otlp_out = out_3.get_relations(receive_otlp.endpoint)[0]
    endpoints = json.loads(receive_otlp_out.local_app_data.get("endpoints", "[]"))
    assert endpoints == expected_endpoints(ingress=False)


def test_blocked_status_when_scaled_without_ingress(ctx, otelcol_container):
    # GIVEN otelcol is not scaled and has no ingress relation
    state = State(planned_units=1, containers=otelcol_container, leader=True)

    # WHEN any event executes the reconciler
    out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is Active
    assert out.unit_status.name != "blocked"

    # AND WHEN otelcol is scaled to 2 units
    state = State(planned_units=2, containers=otelcol_container, leader=True)
    out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is Blocked
    assert out.unit_status.name == "blocked"
    assert "Ingress missing" in out.unit_status.message

    # AND WHEN otelcol is scaled to 2 units with ingress relation
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(
        planned_units=2,
        relations=[ingress],
        containers=otelcol_container,
        leader=True,
    )
    out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is Active
    assert out.unit_status.name != "blocked"
    assert not out.unit_status.message


@patch("socket.getfqdn", lambda: FQDN)
def test_istio_ingress_config_submitted(ctx, otelcol_container):
    """Scenario: Istio ingress relation is connected and the charm submits a valid config."""
    # GIVEN an istio-ingress relation with external_host and tls_enabled=False
    istio_ingress = Relation(
        "istio-ingress",
        remote_app_data={"external_host": "5.6.7.8", "tls_enabled": "False"},
    )
    state = State(relations=[istio_ingress], containers=otelcol_container, leader=True)

    # WHEN any event executes the reconciler
    out = ctx.run(ctx.on.relation_joined(istio_ingress), state)

    # THEN the charm submitted a config to the istio-ingress relation
    istio_out = out.get_relations(istio_ingress.endpoint)[0]
    assert istio_out.local_app_data
    assert "config" in istio_out.local_app_data

    config = json.loads(istio_out.local_app_data["config"])
    # Config should contain listeners and routes for all Port entries
    assert "listeners" in config
    assert "http_routes" in config
    assert "grpc_routes" in config
    # There should be listeners for all ports
    assert len(config["listeners"]) == len(list(Port))
    # gRPC ports (otlp_grpc, jaeger_grpc) should be in grpc_routes
    grpc_port_names = {"otlp_grpc", "jaeger_grpc"}
    grpc_ports = {p.value for p in Port if p.name in grpc_port_names}
    http_ports = {p.value for p in Port if p.name not in grpc_port_names}
    grpc_route_ports = {r["backends"][0]["port"] for r in config["grpc_routes"]}
    http_route_ports = {r["backends"][0]["port"] for r in config["http_routes"]}
    assert grpc_route_ports == grpc_ports
    assert http_route_ports == http_ports


@patch("socket.getfqdn", lambda: FQDN)
def test_blocked_when_both_ingresses_active(ctx, otelcol_container):
    """Scenario: Both Traefik and Istio ingress are active simultaneously."""
    # GIVEN both ingress and istio-ingress relations with external hosts
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    istio_ingress = Relation(
        "istio-ingress",
        remote_app_data={"external_host": "5.6.7.8", "tls_enabled": "False"},
    )
    state = State(
        relations=[ingress, istio_ingress], containers=otelcol_container, leader=True
    )

    # WHEN any event executes the reconciler
    out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is blocked with a multiple-ingress message
    assert out.unit_status.name == "blocked"
    assert "Multiple ingress" in out.unit_status.message


@patch("socket.getfqdn", lambda: "fqdn")
def test_istio_ingress_url_in_loki_databag(ctx, otelcol_container):
    """Scenario: Only Istio ingress is related; the Loki databag should have the Istio external URL."""
    # GIVEN only istio-ingress is related (no Traefik ingress)
    receive_logs_endpoint = Relation("receive-loki-logs")
    istio_ingress = Relation(
        "istio-ingress",
        remote_app_data={"external_host": "5.6.7.8", "tls_enabled": "False"},
    )
    state = State(
        relations=[istio_ingress, receive_logs_endpoint],
        containers=otelcol_container,
        leader=True,
    )

    # WHEN any event executes the reconciler
    out = ctx.run(ctx.on.relation_created(istio_ingress), state)

    # THEN the Istio external host URL is in the receive-loki-logs relation databag
    receive_logs_out = out.get_relations(receive_logs_endpoint.endpoint)[0]
    endpoint_data = json.loads(receive_logs_out.local_unit_data["endpoint"])
    expected_data = {"url": f"http://5.6.7.8:{Port.loki_http.value}/loki/api/v1/push"}
    assert endpoint_data == expected_data


@patch("socket.getfqdn", lambda: "fqdn")
def test_charm_address_prefers_traefik_over_istio(ctx, otelcol_container):
    """Scenario: When only Traefik ingress is ready, resolved URL uses the Traefik external host."""
    # GIVEN only Traefik ingress is related (no Istio ingress)
    receive_logs_endpoint = Relation("receive-loki-logs")
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(
        relations=[ingress, receive_logs_endpoint],
        containers=otelcol_container,
        leader=True,
    )

    # WHEN any event executes the reconciler
    out = ctx.run(ctx.on.relation_created(ingress), state)

    # THEN the Traefik external host URL is in the receive-loki-logs relation databag
    receive_logs_out = out.get_relations(receive_logs_endpoint.endpoint)[0]
    endpoint_data = json.loads(receive_logs_out.local_unit_data["endpoint"])
    expected_data = {"url": f"http://1.2.3.4:{Port.loki_http.value}/loki/api/v1/push"}
    assert endpoint_data == expected_data
