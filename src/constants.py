"""Charm constants, for better testability."""

from typing import Final

RECV_CA_CERT_FOLDER_PATH: Final[str] = "/usr/local/share/ca-certificates/juju_receive-ca-cert"
SERVER_CA_CERT_PATH: Final[str] = (
    "/usr/local/share/ca-certificates/juju_receive-ca-cert/cos-ca.crt"
)
SERVER_CERT_PATH: Final[str] = "/etc/otelcol/otelcol-server-cert.crt"
SERVER_CERT_PRIVATE_KEY_PATH: Final[str] = "/etc/otelcol/otelcol-private-key.key"
CONFIG_PATH: Final[str] = "/etc/otelcol/config.yaml"
SERVICE_NAME: Final[str] = "otelcol"
METRICS_RULES_SRC_PATH: Final[str] = "src/prometheus_alert_rules"
METRICS_RULES_DEST_PATH: Final[str] = "prometheus_alert_rules"
LOKI_RULES_SRC_PATH: Final[str] = "src/loki_alert_rules"
LOKI_RULES_DEST_PATH: Final[str] = "loki_alert_rules"
DASHBOARDS_SRC_PATH: Final[str] = "src/grafana_dashboards"
DASHBOARDS_DEST_PATH: Final[str] = "grafana_dashboards"
INTERNAL_TELEMETRY_LOG_FILE: Final[str] = "/var/log/otelcol.log"
FILE_STORAGE_DIRECTORY: Final[str] = "/otelcol"
# Certs received from relation data for client-like operations, e.g. scrape_configs are stored here. Certs received from `tls-certificates` and `certificate_transfer` interfaces are stored in the root CA store
CERTS_DIR: Final[str] = "/etc/otelcol/certs/"
