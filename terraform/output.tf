output "app_name" {
  value = juju_application.opentelemetry_collector.name
}

output "endpoints" {
  value = {
    # Requires
    metrics_endpoint  = "metrics-endpoint",
    send_remote_write = "send_remote_write",
    send_loki_logs    = "send-loki-logs",
    receive_ca_cert   = "receive-ca-cert",

    # Provides
    receive_loki_logs = "receive-loki-logs",
  }
}