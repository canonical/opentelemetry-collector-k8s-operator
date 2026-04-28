output "app_name" {
  value = juju_application.opentelemetry_collector.name
}

output "provides" {
  value = {
    grafana_dashboards_provider = "grafana-dashboards-provider",
    provide_cmr_mesh            = "provide-cmr-mesh",
    receive_loki_logs           = "receive-loki-logs",
    receive_otlp                = "receive-otlp",
    receive_traces              = "receive-traces",
  }
}

output "requires" {
  value = {
    cloud_config                = "cloud-config",
    metrics_endpoint            = "metrics-endpoint",
    grafana_dashboards_consumer = "grafana-dashboards-consumer",
    ingress                     = "ingress",
    receive_ca_cert             = "receive-ca-cert",
    receive_server_cert         = "receive-server-cert",
    require_cmr_mesh            = "require-cmr-mesh",
    send_loki_logs              = "send-loki-logs",
    send_otlp                   = "send-otlp",
    send_remote_write           = "send-remote-write",
    send_traces                 = "send-traces",
    service_mesh                = "service-mesh",
  }
}
