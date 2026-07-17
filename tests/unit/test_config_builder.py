# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

from copy import deepcopy

import pytest
import yaml
import copy

from config_builder import ConfigBuilder, Component


@pytest.mark.parametrize("pipelines", ([], ["logs", "metrics", "traces"]))
@pytest.mark.parametrize(
    "component",
    (Component.receiver, Component.exporter, Component.connector, Component.processor),
)
def test_add_pipeline_component(pipelines, component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    Pipeline names can follow the type[/name] format, valid for e.g. logs, metrics, traces, logs/2, ...

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    # GIVEN an empty config
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    # WHEN adding a pipeline component with a nested config
    sample_config = {"a": {"b": "c"}}
    config.add_component(
        component=component,
        name="foo",
        config=sample_config,
        pipelines=pipelines,
    )
    # THEN the nested config is added to the config
    assert "foo" in config._config[component.value]
    assert sample_config == config._config[component.value]["foo"]
    # AND the pipeline is not added if none were specified
    if not pipelines:
        assert not config._config["service"]["pipelines"]
    # AND the pipelines are added to the service::pipelines config if specified
    for pipeline in pipelines:
        assert "foo" in config._config["service"]["pipelines"][pipeline][component.value]


@pytest.mark.parametrize("pipelines", ([], ["logs", "metrics", "traces"]))
@pytest.mark.parametrize(
    "component",
    (Component.receiver, Component.exporter, Component.connector, Component.processor),
)
def test_add_to_pipeline(pipelines, component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    # GIVEN an empty config
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    # WHEN adding a pipeline component
    config._add_to_pipeline("foo", component, pipelines)
    # THEN the pipeline component is added to the pipeline config
    if not pipelines:
        assert not config._config["service"]["pipelines"]
    for pipeline in pipelines:
        assert "foo" in config._config["service"]["pipelines"][pipeline][component.value]


def test_add_extension():
    # GIVEN an empty config
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    # WHEN adding a pipeline with a config
    sample_config = {"a": {"b": "c"}}
    config.add_extension("foo", sample_config)
    # THEN the extension is added to the top-level extensions config
    assert sample_config == config._config["extensions"]["foo"]
    # AND the extension is added to the service::extensions config
    assert "foo" in config._config["service"]["extensions"]


def test_add_telemetry():
    # GIVEN an empty config
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    # WHEN adding a pipeline with a config
    sample_config = [{"a": {"b": "c"}}]
    config.add_telemetry("logs", {"level": "INFO"})
    config.add_telemetry("metrics", {"level": "normal"})
    config.add_telemetry("metrics", {"some_config": sample_config})
    # THEN the respective telemetry sections are added to the service::telemetry config
    assert ["logs", "metrics"] == list(config._config["service"]["telemetry"].keys())
    # AND the telemetry is added to the service::telemetry config
    assert config._config["service"]["telemetry"]["metrics"] == {"some_config": sample_config}
    assert config._config["service"]["telemetry"]["logs"] == {"level": "INFO"}


def test_rendered_default_is_valid():
    # GIVEN a default config
    # WHEN the config is rendered
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_default_config()
    config_yaml = yaml.safe_load(config.build())
    # THEN a nop exporter is added for each pipeline missing one
    pipelines = [
        config_yaml["service"]["pipelines"][p] for p in config_yaml["service"]["pipelines"]
    ]
    pairs = [(len(p["receivers"]) > 0, len(p["exporters"]) > 0) for p in pipelines]
    # AND each pipeline has at least one receiver-exporter pair
    assert all(all(condition for condition in pair) for pair in pairs)


def test_default_internal_logs_self_export_plaintext():
    # GIVEN a default config without receiver TLS
    config = ConfigBuilder(
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        receiver_tls=False,
    )
    config.add_default_config()
    logs_telemetry = config._config["service"]["telemetry"]["logs"]
    # THEN the collector's own telemetry resource is tagged so the Loki exporter derives
    # `job=otelcol-internal` from `service.name` deterministically (distinguishable in Grafana)
    # AND the full internal log record (body + attributes) is rendered into the Loki line
    assert config._config["service"]["telemetry"]["resource"] == {
        "service.name": "otelcol-internal",
        "loki.format": "logfmt",
    }
    # AND internal logs are exported over OTLP to the collector's own OTLP receiver
    otlp = logs_telemetry["processors"][0]["batch"]["exporter"]["otlp"]
    assert otlp["protocol"] == "http/protobuf"
    # AND the loopback endpoint uses plaintext HTTP with no CA certificate and no TLS block
    assert otlp["endpoint"] == "http://localhost:4318"
    assert "certificate" not in otlp
    assert "tls" not in otlp


def test_internal_logs_full_record_rendered_to_loki():
    # GIVEN a default config
    config = ConfigBuilder(
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        receiver_tls=False,
    )
    config.add_default_config()
    resource = config._config["service"]["telemetry"]["resource"]
    # THEN `loki.format: logfmt` renders the full record (so in-log context like `target_labels`
    # survives), and no otelcol-own topology labels are injected
    assert resource == {
        "service.name": "otelcol-internal",
        "loki.format": "logfmt",
    }


def test_internal_logs_topology_labels_promoted_to_loki_labels():
    # GIVEN a config built with this collector's own Juju topology
    topology = {
        "juju_application": "otelcol",
        "juju_charm": "opentelemetry-collector-k8s",
        "juju_model": "mymodel",
        "juju_model_uuid": "abcd-1234",
        "juju_unit": "otelcol/0",
    }
    config = ConfigBuilder(
        unit_name="otelcol/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        topology_labels=topology,
    )
    config.add_default_config()
    resource = config._config["service"]["telemetry"]["resource"]
    # THEN the topology is attached to the internal-telemetry resource ...
    for key, value in topology.items():
        assert resource[key] == value
    # AND `service.instance.id` is pinned to the Juju unit (so the Loki `instance` label is stable
    # and correlatable, instead of a random per-process UUID that churns on every restart)
    assert resource["service.instance.id"] == "otelcol/0"
    # AND the job label is still derived from service.name
    assert resource["service.name"] == "otelcol-internal"
    # AND ONLY the bounded topology keys are promoted to Loki labels (no high-cardinality otelcol
    # attributes like `error`/`target_labels`/`scrape_timestamp` are promoted)
    promoted = {label.strip() for label in resource["loki.resource.labels"].split(",")}
    assert promoted == set(topology.keys())


def test_internal_logs_without_topology_labels_are_unchanged():
    # GIVEN no topology is supplied (the historical behaviour)
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_default_config()
    resource = config._config["service"]["telemetry"]["resource"]
    # THEN no topology labels, no pinned instance id, and no label-promotion hint are injected
    assert resource == {"service.name": "otelcol-internal", "loki.format": "logfmt"}


def test_default_internal_logs_self_export_tls():
    # GIVEN a default config WITH receiver TLS and the unit FQDN the server cert is valid for
    config = ConfigBuilder(
        unit_name="fake/0",
        global_scrape_interval="",
        global_scrape_timeout="",
        receiver_tls=True,
        internal_host="otelcol-0.otelcol-endpoints.o11y.svc.cluster.local",
    )
    config.add_default_config()
    otlp = config._config["service"]["telemetry"]["logs"]["processors"][0]["batch"]["exporter"][
        "otlp"
    ]
    # THEN the loopback endpoint targets the FQDN (a name present in the cert SANs) over HTTPS, so
    # verification succeeds -- NOT `localhost`, which would fail ("valid for <fqdn>, not localhost")
    assert (
        otlp["endpoint"]
        == "https://otelcol-0.otelcol-endpoints.o11y.svc.cluster.local:4318"
    )
    # AND no explicit CA is configured: trust is via the system root store
    assert "certificate" not in otlp
    assert "insecure" not in otlp
    assert "tls" not in otlp


def test_default_internal_logs_loop_breaker_filter_present():
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_default_config()
    filter_name = "filter/internal-telemetry-loop-breaker/fake/0"
    filter_cfg = config._config["processors"][filter_name]
    # Filter is wired into the logs pipeline and tolerates OTTL eval errors (keeps valid data).
    assert filter_cfg["error_mode"] == "ignore"
    assert filter_name in config._config["service"]["pipelines"]["logs/fake/0"]["processors"]


def test_loop_breaker_filter_conditions_populated_from_logs_exporters():
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_default_config()
    for name in ("loki/send-loki-logs/0", "otlphttp/rel-1/fake/0"):
        config.add_component(Component.exporter, name, {"endpoint": "x"}, pipelines=["logs/fake/0"])
    # A non-log exporter (metrics pipeline) must NOT be covered.
    config.add_component(
        Component.exporter, "prometheusremotewrite/0", {"endpoint": "x"}, pipelines=["metrics/fake/0"]
    )
    built = yaml.safe_load(config.build())
    conditions = built["processors"]["filter/internal-telemetry-loop-breaker/fake/0"]["logs"][
        "log_record"
    ]
    # Every logs-pipeline exporter is covered, each scoped to the logs signal; nothing else is.
    assert all('instrumentation_scope.attributes["otelcol.signal"] == "logs"' in c for c in conditions)
    covered = {c for eid in ("loki/send-loki-logs/0", "otlphttp/rel-1/fake/0") for c in conditions if eid in c}
    assert len(covered) == 2
    assert not any("prometheusremotewrite" in c or "nop" in c or "debug" in c for c in conditions)


def test_loop_breaker_filter_covers_exporters_on_custom_logs_pipelines():
    # A user-supplied config can add its own logs pipeline (e.g. `logs/custom`) with its own
    # exporters. Those can still fail-and-recurse, so the loop-breaker must cover them too, not
    # just exporters on the charm-managed `logs/<unit>` pipeline.
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_default_config()
    # Exporter on the charm-managed logs pipeline.
    config.add_component(
        Component.exporter, "loki/send-loki-logs/0", {"endpoint": "x"}, pipelines=["logs/fake/0"]
    )
    # Exporter on a user-defined logs pipeline in a different namespace.
    config.add_component(
        Component.exporter, "otlphttp/user-custom", {"endpoint": "x"}, pipelines=["logs/custom"]
    )
    # A bare `logs` pipeline (no `/<name>` suffix) is also a logs pipeline.
    config.add_component(
        Component.exporter, "kafka/user-bare", {"endpoint": "x"}, pipelines=["logs"]
    )
    # A metrics-pipeline exporter must NOT be covered even on a custom namespace.
    config.add_component(
        Component.exporter, "prometheusremotewrite/user", {"endpoint": "x"}, pipelines=["metrics/custom"]
    )
    built = yaml.safe_load(config.build())
    conditions = built["processors"]["filter/internal-telemetry-loop-breaker/fake/0"]["logs"][
        "log_record"
    ]
    covered = {
        eid
        for eid in ("loki/send-loki-logs/0", "otlphttp/user-custom", "kafka/user-bare")
        if any(eid in c for c in conditions)
    }
    assert covered == {"loki/send-loki-logs/0", "otlphttp/user-custom", "kafka/user-bare"}
    assert not any("prometheusremotewrite" in c for c in conditions)


def test_loop_breaker_filter_deduplicates_shared_exporter_across_logs_pipelines():
    # An exporter shared by multiple logs pipelines must yield exactly one drop condition.
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_default_config()
    config.add_component(
        Component.exporter,
        "loki/send-loki-logs/0",
        {"endpoint": "x"},
        pipelines=["logs/fake/0", "logs/custom"],
    )
    built = yaml.safe_load(config.build())
    conditions = built["processors"]["filter/internal-telemetry-loop-breaker/fake/0"]["logs"][
        "log_record"
    ]
    assert sum("loki/send-loki-logs/0" in c for c in conditions) == 1


def test_loop_breaker_filter_conditions_empty_without_log_exporter():
    # With no log exporter (only the fallback nop), nothing can recurse -> no drop conditions.
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_default_config()
    built = yaml.safe_load(config.build())
    assert built["processors"]["filter/internal-telemetry-loop-breaker/fake/0"]["logs"][
        "log_record"
    ] == []


def test_receivers_tls_empty_config():
    # GIVEN an "empty" config
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")
    # THEN it has no effect on the rendered config
    assert (
        config.build()
        == ConfigBuilder(
            unit_name="fake/0", global_scrape_interval="", global_scrape_timeout=""
        ).build()
    )


def test_receivers_tls_no_protocols():
    # GIVEN a config without any protocols
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_component(
        Component.receiver, "prometheus", {"config": {"foo": "bar"}}, pipelines=["metrics"]
    )

    # TODO When we impl fluent config (with immutable builder), then we won't need to copy anymore, because we would:
    #  yaml1 = config.enable_receiver_tls("foo", "bar").yaml
    #  yaml2 = config.yaml
    config_copy = copy.deepcopy(config)

    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")

    # THEN it has no effect on the rendered config
    assert config.build() == config_copy.build()


def test_receivers_tls_unknown_protocols():
    # GIVEN a config with an unknown protocols
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_component(
        Component.receiver,
        "some_receiver",
        {"protocols": {"unknown_protocol_name": {"endpoint": "0.0.0.0:1234"}}},
        pipelines=["metrics"],
    )
    config_copy = copy.deepcopy(config)

    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")

    # THEN it has no effect on the rendered config
    assert config.build() == config_copy.build()


def test_receivers_tls_known_protocols():
    # GIVEN a config with known protocols (http, grpc)
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_component(
        Component.receiver,
        "some-http-receiver",
        {"protocols": {"http": {"endpoint": "0.0.0.0:1234"}}},
        pipelines=["metrics"],
    )
    config.add_component(
        Component.receiver,
        "another-http-receiver",
        {"protocols": {"http": {"endpoint": "0.0.0.0:1235"}}},
        pipelines=["metrics"],
    )
    config.add_component(
        Component.receiver,
        "some-grpc-receiver",
        {"protocols": {"grpc": {"endpoint": "0.0.0.0:5678"}}},
        pipelines=["metrics"],
    )
    config.add_component(
        Component.receiver,
        "another-grpc-receiver",
        {"protocols": {"grpc": {"endpoint": "0.0.0.0:5679"}}},
        pipelines=["metrics"],
    )
    config.add_component(
        Component.receiver,
        "with-existing-tls",
        {
            "protocols": {
                "grpc": {
                    "endpoint": "0.0.0.0:5679",
                    "tls": {"key_file": "foo", "cert_file": "bar"},
                }
            }
        },
        pipelines=["metrics"],
    )

    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")
    config_dict = yaml.safe_load(config.build())

    # THEN all receivers' http, grpc protocols gain a tls section
    for tls_section in (
        config_dict["receivers"]["some-http-receiver"]["protocols"]["http"]["tls"],
        config_dict["receivers"]["another-http-receiver"]["protocols"]["http"]["tls"],
        config_dict["receivers"]["some-grpc-receiver"]["protocols"]["grpc"]["tls"],
        config_dict["receivers"]["another-grpc-receiver"]["protocols"]["grpc"]["tls"],
    ):
        assert "key_file" in tls_section
        assert tls_section["key_file"] == "/some/private.key"
        assert "cert_file" in tls_section
        assert tls_section["cert_file"] == "/some/cert.crt"

    # AND receivers which had a configured tls section, keep their configuration
    assert (
        config_dict["receivers"]["with-existing-tls"]["protocols"]["grpc"]["tls"]["key_file"]
        == "foo"
    )
    assert (
        config_dict["receivers"]["with-existing-tls"]["protocols"]["grpc"]["tls"]["cert_file"]
        == "bar"
    )


def test_insecure_skip_verify():
    # GIVEN an empty config without exporters
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config_copy = deepcopy(config)
    # WHEN updating the tls::insecure_skip_verify exporter configuration
    config._add_exporter_insecure_skip_verify(False)
    # THEN it has no effect on the rendered config
    assert config._config == config_copy._config
    # WHEN multiple exporters are added
    config.add_component(Component.exporter, "foo", {"endpoint": "foo"})
    config.add_component(
        Component.exporter,
        "bar",
        {
            "endpoint": "bar",
            "tls": {"insecure_skip_verify": True},
        },
    )
    # AND the tls::insecure_skip_verify configuration is added
    config._add_exporter_insecure_skip_verify(False)
    # THEN tls::insecure_skip_verify is set for each exporter which was missing this configuration
    assert config._config["exporters"]["foo"]["tls"]["insecure_skip_verify"] is False
    # AND any existing tls::insecure_skip_verify configuration is untouched
    assert config._config["exporters"]["bar"]["tls"]["insecure_skip_verify"] is True


def test_some_exporters_exclude_tls_config():
    # GIVEN an empty config without exporters
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    # WHEN multiple nop exporters are added
    config.add_component(Component.exporter, "nop", {"config": {"foo": "bar"}})
    config.add_component(Component.exporter, "nop/descriptor", {"config": {"foo": "bar"}})
    # WHEN multiple debug exporters are added
    config.add_component(Component.exporter, "debug", {"config": {"foo": "bar"}})
    config.add_component(Component.exporter, "debug/descriptor", {"config": {"foo": "bar"}})
    # AND the tls::insecure_skip_verify configuration is added
    config._add_exporter_insecure_skip_verify(True)
    # THEN tls::insecure_skip_verify is not set for these exporters
    assert all("tls" not in exp.keys() for exp in config._config["exporters"].values())


def test_global_scrape_timeout_and_interval():
    # GIVEN a config with multiple prometheus receivers
    config = ConfigBuilder(unit_name="fake/0", global_scrape_interval="", global_scrape_timeout="")
    config.add_component(Component.receiver, name="prometheus", config={"config": {}})
    config.add_component(
        Component.receiver, name="prometheus/empty-cfgs", config={"config": {"scrape_configs": []}}
    )
    config.add_component(
        Component.receiver,
        name="prometheus/missing-timeout",
        config={"config": {"scrape_configs": [{"scrape_interval": "1s"}]}},
    )
    config.add_component(
        Component.receiver,
        name="prometheus/missing-interval",
        config={"config": {"scrape_configs": [{"scrape_timeout": "1s"}]}},
    )
    config.add_component(
        Component.receiver,
        name="prometheus/multiple-cfgs",
        config={
            "config": {
                "scrape_configs": [
                    {"scrape_interval": "1s", "scrape_timeout": "1s"},
                    {"scrape_interval": "1s", "scrape_timeout": "1s"},
                ]
            }
        },
    )
    # WHEN the global scrape interval and timeout is set
    config._set_prometheus_receiver_global_timeout_and_interval("1m", "10s")
    # THEN all prometheus receivers are updated
    for receiver in config._config["receivers"].values():
        if receiver["config"]:
            for scrape_cfg in receiver["config"]["scrape_configs"]:
                assert scrape_cfg["scrape_interval"] == "1m"
                assert scrape_cfg["scrape_timeout"] == "10s"
