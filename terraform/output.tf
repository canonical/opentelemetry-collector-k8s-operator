output "app_name" {
  value = juju_application.opentelemetry_collector.name
}

output "endpoints" {
  value = {
    # Requires
    metrics_endpoint            = "metrics-endpoint",
    send_remote_write           = "send_remote_write",
    send_loki_logs              = "send-loki-logs",
    receive_ca_cert             = "receive-ca-cert",
    grafana_dashboards_consumer = "grafana-dashboards-consumer",
    cloud_config                = "cloud-config",
    receive_server_cert         = "receive-server-cert",
    send_traces                 = "send-traces",

    # Provides
    receive_loki_logs           = "receive-loki-logs",
    grafana_dashboards_provider = "grafana-dashboards-provider",
    receive_traces              = "receive-traces",
  }
}
