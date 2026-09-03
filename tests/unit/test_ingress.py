# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can operate behind an ingress."""

import json
from typing import Any, List
from unittest.mock import patch

import pytest
import yaml
from helpers import IssuedCertificate, issued_certificate
from ops.testing import Model, Relation, State

from src.config_builder import Port
from src.constants import INGRESS_IP_MATCHER

FQDN = "otelcol-0.otelcol-endpoints.otel.svc.cluster.local"
CHARM_NAME = "opentelemetry-collector-k8s"


def service_fqdn(state) -> str:
    """Return the Kubernetes Service FQDN otelcol advertises for the given state."""
    return f"{CHARM_NAME}.{state.model.name}.svc.cluster.local"


def test_active_when_scaled_without_ingress(ctx, otelcol_container):
    """Scenario: scaling without ingress is fine, because traffic goes to the K8s Service."""
    # GIVEN otelcol is not scaled and has no ingress relation
    state = State(planned_units=1, containers=otelcol_container, leader=True)

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is Active
    assert state_out.unit_status.name == "active"

    # AND WHEN otelcol is scaled to 2 units without ingress
    state = State(planned_units=2, containers=otelcol_container, leader=True)
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is still Active, because the K8s Service load-balances across units
    assert state_out.unit_status.name == "active"

    # AND WHEN otelcol is scaled to 2 units with ingress relation
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(
        planned_units=2,
        relations=[ingress],
        containers=otelcol_container,
        leader=True,
    )
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is Active
    assert state_out.unit_status.name == "active"
    assert not state_out.unit_status.message


def test_blocked_when_both_ingresses_active(ctx, otelcol_container):
    """Scenario: Both Traefik and Istio ingress are active simultaneously."""
    # GIVEN both ingress and istio-ingress relations with external hosts
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    istio_ingress = Relation(
        "istio-ingress",
        remote_app_data={"external_host": "5.6.7.8", "tls_enabled": "False"},
    )
    state = State(relations=[ingress, istio_ingress], containers=otelcol_container, leader=True)

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is blocked with a multiple-ingress message
    assert state_out.unit_status.name == "blocked"
    assert "Multiple ingress" in state_out.unit_status.message


def test_istio_sent_config(ctx, otelcol_container):
    """Scenario: Istio ingress relation is connected and the charm submits a valid config."""
    # GIVEN an istio-ingress relation with external_host
    istio_ingress = Relation(
        "istio-ingress",
        remote_app_data={"external_host": "5.6.7.8", "tls_enabled": "False"},
    )
    state = State(relations=[istio_ingress], containers=otelcol_container, leader=True)

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.relation_joined(istio_ingress), state)

    # THEN the charm submitted a config to the istio-ingress relation
    istio_out = state_out.get_relations(istio_ingress.endpoint)[0]
    assert istio_out.local_app_data
    assert "config" in istio_out.local_app_data

    config = json.loads(istio_out.local_app_data["config"])

    # AND the config should contain listeners and routes for all Port entries
    assert "listeners" in config
    assert "http_routes" in config
    assert "grpc_routes" in config
    assert len(config["listeners"]) == len(list(Port))

    # AND gRPC ports (otlp_grpc, jaeger_grpc) should be in grpc_routes
    grpc_port_names = {"otlp_grpc", "jaeger_grpc"}
    grpc_ports = {p.value for p in Port if p.name in grpc_port_names}
    http_ports = {p.value for p in Port if p.name not in grpc_port_names}
    grpc_route_ports = {r["backends"][0]["port"] for r in config["grpc_routes"]}
    http_route_ports = {r["backends"][0]["port"] for r in config["http_routes"]}
    assert grpc_route_ports == grpc_ports
    assert http_route_ports == http_ports


@patch("socket.getfqdn", lambda: FQDN)
def test_traefik_sent_config(ctx, otelcol_container):
    """Scenario: Otelcol deployed without tls-certificates relation."""
    # GIVEN otelcol deployed in isolation
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "http"})
    state = State(relations=[ingress], containers=otelcol_container, leader=True)
    charm_name = CHARM_NAME
    # Traefik must load-balance across all units, so the backend is the K8s Service, not a pod
    backend = service_fqdn(state)
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
                    "loadBalancer": {"servers": [{"url": f"http://{backend}:13133"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-jaeger-grpc": {
                    "loadBalancer": {"servers": [{"url": f"http://{backend}:14250"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-jaeger-thrift-http": {
                    "loadBalancer": {"servers": [{"url": f"http://{backend}:14268"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-loki-http": {
                    "loadBalancer": {"servers": [{"url": f"http://{backend}:3500"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-metrics": {
                    "loadBalancer": {"servers": [{"url": f"http://{backend}:8888"}]},
                },
                f"juju-{state.model.name}-{charm_name}-service-otlp-grpc": {
                    "loadBalancer": {"servers": [{"url": f"http://{backend}:4317"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-otlp-http": {
                    "loadBalancer": {"servers": [{"url": f"http://{backend}:4318"}]}
                },
                f"juju-{state.model.name}-{charm_name}-service-zipkin": {
                    "loadBalancer": {"servers": [{"url": f"http://{backend}:9411"}]}
                },
            },
        },
    }

    # WHEN the ingress relation joins
    state_out = ctx.run(ctx.on.relation_joined(ingress), state)

    # THEN dynamic config is present in ingress relation
    ingress_out = state_out.get_relations(ingress.endpoint)[0]
    assert ingress_out.local_app_data
    assert yaml.safe_load(ingress_out.local_app_data["config"]) == expected_rel_data


def test_traefik_ingress_config_middleware_tls(ctx, otelcol_container):
    # GIVEN a Traefik ingress relation with TLS
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "https"})

    state = State(relations=[ingress], containers=otelcol_container, leader=True)

    # WHEN the ingress relation joins
    state_out = ctx.run(ctx.on.relation_joined(ingress), state)

    # THEN middleware config is present in ingress config
    ingress_out = state_out.get_relations(ingress.endpoint)[0]
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


@pytest.mark.parametrize(
    "ingress_rel_name,ingress_remote_data,external_host",
    [
        ("ingress", {"external_host": "1.2.3.4", "scheme": "http"}, "1.2.3.4"),
        ("istio-ingress", {"external_host": "5.6.7.8", "tls_enabled": "False"}, "5.6.7.8"),
    ],
)
@patch("socket.getfqdn", new=lambda *args: FQDN)
def test_loki_url_in_databag(
    ctx, otelcol_container, ingress_rel_name, ingress_remote_data, external_host
):
    # GIVEN an ingress is related to otelcol
    receive_logs_endpoint = Relation("receive-loki-logs")
    ingress = Relation(ingress_rel_name, remote_app_data=ingress_remote_data)
    state = State(
        relations=[ingress, receive_logs_endpoint], containers=otelcol_container, leader=True
    )

    # WHEN the ingress relation is created
    out_1 = ctx.run(ctx.on.relation_created(ingress), state)

    # THEN ingress URL is present in receive-loki-logs relation databag
    receive_logs_out = out_1.get_relations(receive_logs_endpoint.endpoint)[0]
    expected_data = {"url": f"http://{external_host}:{Port.loki_http.value}/loki/api/v1/push"}
    assert json.loads(receive_logs_out.local_unit_data["endpoint"]) == expected_data

    # AND WHEN the receive-loki-logs relation is created
    out_2 = ctx.run(ctx.on.relation_created(receive_logs_endpoint), state)

    # THEN ingress URL is present in receive-loki-logs relation databag
    receive_logs_out = out_2.get_relations(receive_logs_endpoint.endpoint)[0]
    expected_data = {"url": f"http://{external_host}:{Port.loki_http.value}/loki/api/v1/push"}
    assert json.loads(receive_logs_out.local_unit_data["endpoint"]) == expected_data

    # AND WHEN ingress is removed
    out_3 = ctx.run(ctx.on.relation_broken(ingress), state)
    # THEN the K8s Service URL is present in receive-loki-logs relation databag,
    # so that logs are load-balanced across units instead of sent to every unit
    receive_logs_out = out_3.get_relations(receive_logs_endpoint.endpoint)[0]
    expected_data = {
        "url": f"http://{service_fqdn(state)}:{Port.loki_http.value}/loki/api/v1/push"
    }
    assert json.loads(receive_logs_out.local_unit_data["endpoint"]) == expected_data


@pytest.mark.parametrize(
    "ingress_rel_name,ingress_remote_data,external_host,tls",
    [
        ("ingress", {"external_host": "1.2.3.4", "scheme": "http"}, "1.2.3.4", False),
        ("ingress", {"external_host": "1.2.3.4", "scheme": "https"}, "1.2.3.4", True),
        ("istio-ingress", {"external_host": "5.6.7.8", "tls_enabled": "False"}, "5.6.7.8", False),
        ("istio-ingress", {"external_host": "5.6.7.8", "tls_enabled": "True"}, "5.6.7.8", True),
    ],
)
@patch("socket.getfqdn", new=lambda *args: FQDN)
def test_otlp_url_in_databag(
    ctx, otelcol_container, ingress_rel_name, ingress_remote_data, external_host, tls
):
    def expected_endpoints(traefik: bool, istio: bool) -> List[dict[str, Any]]:
        has_ingress = traefik or istio
        # Without ingress, the K8s Service FQDN is advertised so that OTLP data is
        # load-balanced across units instead of duplicated to each of them.
        host = (
            external_host if has_ingress else f"{CHARM_NAME}.{state.model.name}.svc.cluster.local"
        )
        # since we do not patch integrations.is_tls_ready(container), internal TLS will be False
        insecure = not (tls if has_ingress else False)
        scheme = "http" if insecure else "https"
        endpoints = [
            {
                "protocol": "http",
                "endpoint": f"{scheme}://{host}:{Port.otlp_http.value}",
                "telemetries": ["metrics", "logs", "traces"],
                "insecure": insecure,
            }
        ]
        if not traefik:
            endpoints.append(
                {
                    "protocol": "grpc",
                    "endpoint": f"{host}:{Port.otlp_grpc.value}",
                    "telemetries": ["metrics", "logs", "traces"],
                    "insecure": insecure,
                },
            )
        return endpoints

    # GIVEN an ingress is related to otelcol
    rules = json.dumps({"logql": {}, "promql": {}})
    receive_otlp = Relation("receive-otlp", remote_app_data={"rules": rules, "metadata": "{}"})
    ingress = Relation(ingress_rel_name, remote_app_data=ingress_remote_data)
    state = State(relations=[ingress, receive_otlp], containers=otelcol_container, leader=True)

    # WHEN the ingress relation is created
    out_1 = ctx.run(ctx.on.relation_created(ingress), state)

    # THEN ingress URL is present in receive-otlp relation databag
    receive_otlp_out = out_1.get_relations(receive_otlp.endpoint)[0]
    endpoints = json.loads(receive_otlp_out.local_app_data.get("endpoints", "[]"))
    assert endpoints == expected_endpoints(
        traefik=ingress_rel_name == "ingress", istio=ingress_rel_name == "istio-ingress"
    )

    # AND WHEN the receive-otlp relation is created
    out_2 = ctx.run(ctx.on.relation_created(receive_otlp), state)

    # THEN ingress URL is present in receive-otlp relation databag
    receive_otlp_out = out_2.get_relations(receive_otlp.endpoint)[0]
    endpoints = json.loads(receive_otlp_out.local_app_data.get("endpoints", "[]"))
    assert endpoints == expected_endpoints(
        traefik=ingress_rel_name == "ingress", istio=ingress_rel_name == "istio-ingress"
    )

    # AND WHEN ingress is removed
    out_3 = ctx.run(ctx.on.relation_broken(ingress), state)
    # THEN the internal URL is present in receive-otlp relation databag
    receive_otlp_out = out_3.get_relations(receive_otlp.endpoint)[0]
    endpoints = json.loads(receive_otlp_out.local_app_data.get("endpoints", "[]"))
    assert endpoints == expected_endpoints(traefik=False, istio=False)


def traefik_backends(state_out, ingress) -> set:
    """Return the distinct backend URLs otelcol told Traefik to route to."""
    config = yaml.safe_load(state_out.get_relation(ingress.id).local_app_data["config"])
    return {
        server["url"]
        for service in config["http"]["services"].values()
        for server in service["loadBalancer"]["servers"]
    }


@patch("socket.getfqdn", new=lambda *args: FQDN)
def test_traefik_backend_waits_for_a_certificate_covering_the_service_name(ctx, otelcol_container):
    """Scenario: a TLS otelcol refreshed from a revision that only asked for the pod name.

    Traefik verifies the hostname of the backend it connects to, so pointing it at the
    Kubernetes Service name while the units still serve a pod-only certificate would break
    ingress outright. The backend must therefore follow the same rule as the address we
    advertise to in-cluster senders.
    """
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "https"})
    ssc = Relation(endpoint="receive-server-cert", interface="tls-certificate")
    state = State(
        planned_units=2,
        relations=[ingress, ssc],
        containers=otelcol_container,
        leader=True,
        model=Model(name="otel"),
    )
    service = service_fqdn(state)

    # GIVEN the certificate on disk only covers this pod
    with issued_certificate(IssuedCertificate("otelcol-0", frozenset({FQDN}))):
        state_out = ctx.run(ctx.on.update_status(), state)

    # THEN Traefik is pointed at the pod, over HTTPS, so hostname verification still succeeds
    assert traefik_backends(state_out, ingress) == {
        f"https://{FQDN}:{port.value}" for port in Port
    }

    # AND the charm says why scaling is not distributing anything yet
    assert state_out.unit_status.name == "waiting"
    assert "Kubernetes Service name" in state_out.unit_status.message

    # WHEN the CA issues a certificate that also covers the K8s Service name
    with issued_certificate(IssuedCertificate("otelcol-0", frozenset({FQDN, service}))):
        state_out = ctx.run(ctx.on.update_status(), state)

    # THEN Traefik load-balances across all units via the K8s Service
    assert traefik_backends(state_out, ingress) == {
        f"https://{service}:{port.value}" for port in Port
    }
    assert state_out.unit_status.name == "active"


def test_traefik_backend_scheme_matches_tls_on_the_hook_it_becomes_ready(ctx, otelcol_container):
    """Scenario: the CA's certificate arrives on this very hook.

    The scheme handed to Traefik is read after the certificate relations are reconciled, so
    it describes what the receivers serve now not what they served when the hook started.
    """
    ingress = Relation("ingress", remote_app_data={"external_host": "1.2.3.4", "scheme": "https"})
    ssc = Relation(endpoint="receive-server-cert", interface="tls-certificate")
    state = State(relations=[ingress, ssc], containers=otelcol_container, leader=True)
    service = service_fqdn(state)

    # GIVEN no certificate on disk yet, WHEN one is assigned during this reconcile
    with issued_certificate(IssuedCertificate("otelcol-0", frozenset({FQDN, service}))):
        state_out = ctx.run(ctx.on.relation_changed(ssc), state)

    # THEN Traefik is told to speak HTTPS to the backend, not HTTP
    assert traefik_backends(state_out, ingress) == {
        f"https://{service}:{port.value}" for port in Port
    }
