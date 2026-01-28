# OpenTelemetry Collector Operator OTLP interface

The idea of the lib is that the provider offers all the supported protocols mapped to its endpoint (host and port)

```json
{
  "grpc": "http://provider-0.provider-endpoints.test.svc.cluster.local:4317",
  "http": "http://provider-0.provider-endpoints.test.svc.cluster.local:4318"
}
```

If the OTLP requirer class is instantiated with a preferred protocol, it will choose that one from the provider, else it prefers grpc over http if provided. The lib should provide an endpoint method or property which the charm can then use to do something with. E.g. in the case of otelcollector, it would place this into the collector config like:

```yaml
exporters:
  otlp:
    endpoint: http://otlp-0.otlp-endpoints.sane.svc.cluster.local:4317
```

Note, the requirer does not use the databag because it has nothing to communitcate to the provider.

Use this as a head start:

- [pull/131](https://github.com/canonical/opentelemetry-collector-k8s-operator/pull/131)

Currently, this minimal implementation allows 2 otelcol charms to relate to eachother and send data over OTLP receivers/exporters.
