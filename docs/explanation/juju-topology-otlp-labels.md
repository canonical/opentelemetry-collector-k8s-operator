# How JujuTopology labels appear in OTLP telemetry

[This telemetry labels explanation doc](https://documentation.ubuntu.com/observability/track-2/explanation/telemetry-labels/) is outdated, as it does not mention what the telemetry is normalized to in the OTLP data model.

Juju topology labels identify where telemetry comes from in a Juju model.
In this charm, the labels are represented as the usual keys:

- `juju_model`
- `juju_model_uuid`
- `juju_application`
- `juju_unit`
- `juju_charm`

This page explains where those labels are injected for OTLP-related flows, and where they are expected to already exist.

## Why this matters

OTLP data is often centralized and mixed across many applications and models.
Without topology attributes, logs, metrics, and traces are much harder to filter, route, alert on, and correlate.

## Injection points in this charm

The charm uses the OTLP interface library (`OtlpConsumer`/`OtlpProvider`) and OpenTelemetry Collector config generation to preserve and propagate Juju topology context.

At a high level:

1. The charm builds Juju topology from charm identity (`JujuTopology.from_charm(...)`).
2. The OTLP relation library publishes topology metadata and topology-aware rules in relation data bags.
3. Collector pipelines attach or surface topology labels depending on signal path:
   - logs: topology labels are surfaced as Loki labels
   - metrics: topology labels are attached for self-scraped metrics
   - traces: topology should be present as OTLP resource attributes from the emitter side

## Logs: how labels are surfaced

For logs forwarded to Loki, the collector uses Loki exporter attribute hints.
The config adds `loki.attribute.labels` including Juju keys, so those attributes become Loki stream labels.

Conceptually:

- log/resource attributes carry Juju topology values
- collector sets Loki label hints
- Loki indexes those values as labels for querying and alerting

### Placeholder: logs screenshot

<!-- TODO: Insert screenshot of logs in OTEL pipeline showing Juju topology attributes -->

`[LOGS_SCREENSHOT_PLACEHOLDER]`

### Placeholder: OTLP logs sample

```json
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          {"key": "juju_model", "value": {"stringValue": "<model>"}},
          {"key": "juju_model_uuid", "value": {"stringValue": "<uuid>"}},
          {"key": "juju_application", "value": {"stringValue": "<application>"}},
          {"key": "juju_unit", "value": {"stringValue": "<unit>"}},
          {"key": "juju_charm", "value": {"stringValue": "<charm>"}}
        ]
      },
      "scopeLogs": [
        {
          "logRecords": [
            {
              "body": {"stringValue": "<log line>"}
            }
          ]
        }
      ]
    }
  ]
}
```

## Metrics: how labels are attached

For collector self-monitoring metrics, the charm explicitly configures scrape labels with Juju topology (`add_self_scrape(...)`).
Those labels are then attached to scraped metric series.

For incoming OTLP metrics from related workloads, the collector forwards the OTLP metric payload selected via the OTLP relation endpoint. In that flow, topology is expected to already be present in OTLP resource attributes from the sender side.

### Placeholder: metrics screenshot

<!-- TODO: Insert screenshot of metric series showing juju_* labels -->

`[METRICS_SCREENSHOT_PLACEHOLDER]`

### Placeholder: OTLP metrics sample

```json
{
  "resourceMetrics": [
    {
      "resource": {
        "attributes": [
          {"key": "juju_model", "value": {"stringValue": "<model>"}},
          {"key": "juju_application", "value": {"stringValue": "<application>"}},
          {"key": "juju_unit", "value": {"stringValue": "<unit>"}}
        ]
      },
      "scopeMetrics": [
        {
          "metrics": [
            {
              "name": "<metric_name>"
            }
          ]
        }
      ]
    }
  ]
}
```

## Traces: where topology belongs

Trace ingestion/forwarding in this charm is configured through tracing integrations and OTLP HTTP exporters for Tempo paths.

For traces, Juju topology should be represented in OTLP resource attributes (typically on the ResourceSpans). The collector pipeline forwards that context so traces can be filtered and correlated by source in the backend.

### Placeholder: traces screenshot

<!-- TODO: Insert screenshot of trace/resource attributes showing juju_* keys -->

`[TRACES_SCREENSHOT_PLACEHOLDER]`

### Placeholder: OTLP traces sample

```json
{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          {"key": "juju_model", "value": {"stringValue": "<model>"}},
          {"key": "juju_application", "value": {"stringValue": "<application>"}},
          {"key": "juju_unit", "value": {"stringValue": "<unit>"}}
        ]
      },
      "scopeSpans": [
        {
          "spans": [
            {
              "name": "<span_name>"
            }
          ]
        }
      ]
    }
  ]
}
```

## What the OTLP relation library injects directly

The OTLP relation library injects Juju topology into:

- relation metadata (`metadata`) published by the OTLP consumer
- rule material (LogQL/PromQL) generated or processed with topology context

This enables downstream systems to keep alerting/rule scope aligned with the same origin metadata as telemetry.

## Practical takeaway

When validating topology end-to-end, check these layers separately:

1. relation data: topology metadata and rules are published
2. collector config: signal pipelines include expected processors/exporters and label hints
3. backend payload/index: OTLP resource attributes (and Loki labels for logs) contain `juju_*` keys
