# OpenTelemetry Collector Operator for Kubernetes

[![CharmHub Badge](https://charmhub.io/opentelemetry-collector-k8s/badge.svg)](https://charmhub.io/opentelemetry-collector-k8s)
[![Release](https://github.com/canonical/opentelemetry-collector-k8s-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/opentelemetry-collector-k8s-operator/actions/workflows/release.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

Charmed [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector) operator for Kubernetes.


## Design

This charm is written in the reconciler pattern.


## Usage

```bash
charmcraft pack
juju deploy ./opentelemetry-collector-k8s_ubuntu@24.04-amd64.charm otelcol \
  --resource opentelemetry-collector-image=ubuntu/opentelemetry-collector
```

You can "recreate the world" with a dedicated charm action,

```bash
juju run otelcol/0 reconcile
```


## Deployment scenarios

### Collection agent, pushing directly to backends

```mermaid
graph LR

subgraph app-model
app-one --- otelcol
app-two --- otelcol
end

subgraph observability-model
otelcol ---|send-remote-write| mimir
otelcol ---|send-loki-logs| loki
otelcol ---|send-traces| tempo
otelcol ---|grafana-dashboards-consumer| grafana
end
```


## OCI Images

| Workload container | Rock repo                              | Dockerhub                                     |
|--------------------|----------------------------------------|-----------------------------------------------|
| `otelcol`          | [`opentelemetry-collector-rock`][rock] | [`ubuntu/opentelemetry-collector`][dockerhub] |


## Releases

| GitHub branch | Charmhub track | Supported until |
|---------------|----------------|-----------------|
| `track/2`     | `2`            | 2026-07         |


## Related charms

- [opentelemetry-collector](https://github.com/canonical/opentelemetry-collector-operator) (VM charm)
- [grafana-agent-k8s](https://github.com/canonical/grafana-agent-k8s-operator)


## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and the [contributing](CONTRIBUTING.md) doc for developer guidance.


[rock]: https://github.com/canonical/opentelemetry-collector-rock
[dockerhub]: https://hub.docker.com/r/ubuntu/opentelemetry-collector
