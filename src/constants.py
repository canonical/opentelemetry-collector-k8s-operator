"""Charm constants, for better testability."""

from typing import Final

SERVICE_NAME: Final[str] = "otelcol"
CUSTOM_COMPONENT_ID: Final[str] = "_custom"
RECV_CA_CERT_FOLDER_PATH: Final[str] = "/usr/local/share/ca-certificates/juju_receive-ca-cert"
SERVER_CA_CERT_PATH: Final[str] = (
    "/usr/local/share/ca-certificates/juju_receive-ca-cert/cos-ca.crt"
)
SERVER_CERT_PATH: Final[str] = "/etc/otelcol/otelcol-server-cert.crt"
SERVER_CERT_PRIVATE_KEY_PATH: Final[str] = "/etc/otelcol/otelcol-private-key.key"
CONFIG_PATH: Final[str] = "/etc/otelcol/config.yaml"
METRICS_RULES_SRC_PATH: Final[str] = "src/prometheus_alert_rules"
METRICS_RULES_DEST_PATH: Final[str] = "prometheus_alert_rules"
LOKI_RULES_SRC_PATH: Final[str] = "src/loki_alert_rules"
LOKI_RULES_DEST_PATH: Final[str] = "loki_alert_rules"
DASHBOARDS_SRC_PATH: Final[str] = "src/grafana_dashboards"
DASHBOARDS_DEST_PATH: Final[str] = "grafana_dashboards"
FILE_STORAGE_DIRECTORY: Final[str] = "/otelcol"
# Certs received from relation data for client-like operations, e.g. scrape_configs are stored here. Certs received from `tls-certificates` and `certificate_transfer` interfaces are stored in the root CA store
CERTS_DIR: Final[str] = "/etc/otelcol/certs/"
EXTERNAL_CONFIG_SECRETS_DIR: Final[str] = "/etc/otelcol/external_config_secrets/"
INGRESS_IP_MATCHER: Final[str] = "ClientIP(`0.0.0.0/0`)"

# Loop-breaker for self-ingested internal telemetry.
# The collector feeds its OWN internal logs into the `logs/<unit>` pipeline, so they can be
# exported with topology labels. Only the exporter(s) attached to the LOGS pipeline can recurse:
# such an exporter's "Exporting failed" log is itself an internal log, so it re-enters the same
# pipeline and is re-exported -> an unbounded loop when the endpoint is down. We drop the logs
# emitted by exactly those log-pipeline exporter components (matched on `otelcol.component.id`,
# enumerated dynamically at build time in ConfigBuilder._populate_loop_breaker_filter). Every OTHER
# component's logs -- including failure logs from exporters on the metrics/traces pipelines
# (Mimir/remote-write, Tempo, OTLP-metrics/traces) -- pass through to Loki, since they cannot form
# a cycle while the log path is up and are the most useful logs to see in Grafana.
INTERNAL_LOGS_FILTER_ID: Final[str] = "internal-telemetry-loop-breaker"
# Exporter component-id prefixes that are auto-injected by the builder (not real destinations) and
# so must never be treated as loop-through log exporters by the loop-breaker filter.
NON_LOOPING_EXPORTER_PREFIXES: Final[tuple] = ("nop", "debug")
