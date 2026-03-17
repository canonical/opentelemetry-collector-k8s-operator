<!-- Copilot task file: Integrations overview for this charm -->
# Integrations Overview

Purpose: give Copilot concise, actionable context about how `opentelemetry-collector-k8s-operator` integrates with other charms and services so it can reliably author relation code, databag shapes, and tests.

High-level summary
- The charm exposes and consumes multiple relations to interoperate with logging, metrics, tracing, TLS, and observability tooling. Integration logic is encapsulated in small provider/requirer classes so each relation's behaviour is testable and isolated.

Primary relations and databag keys
- `send-otlp` (provides): providers expose OTLP endpoints via a databag keyed by `OtlpProviderAppData.KEY` containing JSON like `{"endpoints": [{"protocol":"http|grpc","endpoint":"http://host:port","telemetries":["logs","metrics","traces"]}]}`. The consumer filters endpoints by supported protocols/telemetries.
- `receive-otlp` (requires): the charm publishes its own supported OTLP endpoints (http/grpc) in the provider databag so downstream collectors can connect.
- `loki` / Loki push API (consume & provide): the charm may accept Loki pushes for logs (`receive-loki-logs/...`) and/or forward logs to Loki exporters (`send-loki-logs/...`). Config hints like `loki.format` and `loki.attribute.labels` are used.
- `prometheus metrics endpoint` (provide): exposes `prometheus/metrics-endpoint/<unit>` scrape jobs (self-monitoring) and can forward metrics via remote-write to Prometheus/Mimir (`prometheusremotewrite/send-remote-write/<idx>`).
- `grafana-dashboard` (provide): the charm provides Grafana dashboards via `GrafanaDashboardProvider` for observability teams.
- `certificates` / TLS relations: TLS certificates are obtained via `TLSCertificatesRequiresV4` or similar certificate-transfer interfaces. Keys and cert chains are represented as objects/strings and used to configure TLS sections in generated collector config and container files.

Integration patterns and conventions
- Encapsulation: integration behaviour lives in `src/integrations.py` (and related modules). Each integration exposes minimal methods to get/set databag data and to indicate readiness.
- Pydantic models: databag schemas and relation payloads use pydantic models (e.g., `OtlpProviderAppData`, `OtlpEndpoint`) for validation and normalization.
- IDs & mapping: relation mappings use relation id (int) as keys when assembling forwarding configurations (e.g., mapping relation id -> `OtlpEndpoint`).
- Filtering & compatibility: providers may publish multiple endpoints; consumers must filter endpoints to match supported protocols and telemetry types. See unit tests in `tests/unit/test_otlp.py` for examples.
- TLS handling: TLS may be provided either via a `certificates` relation or from Juju config (`tls-ca`, `tls-cert`, `tls-key`). The charm centralises TLS handling in `ConfigManager`/`ConfigBuilder` and writes certificate files into the workload container before restarting services.

Testing and authoring guidance (for Copilot)
- Unit tests should exercise integrations by constructing `Relation` objects in `ops.testing.State` with `remote_app_data` or `local_app_data` set to pydantic-style serialised payloads. Use `ctx` fixture and `with ctx(ctx.on.update_status(), state=state) as mgr:`.
- Use `pytest` + `unittest.mock.patch` to control integration readiness checks and to inject provider databag values.
- When adding or changing databag keys, update pydantic models and unit tests that validate serialization (`model_dump()` comparisons are used in tests).
- For certificate flows, unit tests use `MockCertificate` fixtures and `mock_container` to simulate filesystem interactions; integration tests rely on real certificate relations in a test model.

Operational notes
- When generating config YAML that references relation-provided endpoints, always mark HTTP endpoints as `insecure` when scheme is `http` (no TLS); set `insecure_skip_verify` per charm config.
- When forwarding telemetry to multiple endpoints, use unique exporter names (e.g., `otlp/<unit>`, `otlp/profiling/<idx>`) so the collector config stays deterministic.

When Copilot edits integration code
- Preserve existing pydantic schemas and relation keys unless upgrading the relation schema deliberately; include migration tests when changing schemas.
- Keep provider/requirer responsibilities small: parsing/validation in models, state changes in integration class, and side-effects (file writes, pebble changes) in workload helpers.
- Add unit tests that construct minimal `Relation` objects and assert the resulting config fragments (loaded via `yaml.safe_load`) or model outputs.

References for examples in this repo
- `tests/unit/test_otlp.py` — OTLP provider/consumer validation, filtering and databag shaping.
- `src/config_manager.py` & `src/config_builder.py` — how relation data is consumed to construct collector config (OTLP exporters, Loki exporters, Prometheus receivers).
- `tests/unit/conftest.py` — fixtures used to emulate relation and certificate behaviours.
