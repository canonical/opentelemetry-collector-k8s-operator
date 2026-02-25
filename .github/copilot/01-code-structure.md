# Charm Architecture

This charm follows a small, opinionated architecture so contributors and Copilot can reason
about where to place code and how to write tests.

## File layout and responsibilities
- `src/charm.py`: the top-level `OpenTelemetryCollectorK8sCharm` class and event handler wiring. Handlers should be thin and delegate to a reconciler or integration helpers.
- `src/integrations.py`: integration classes that encapsulate relation logic (provider/requirer or consumer/provider pairs). Integrations handle databag shaping and relation-specific conversions.
- `src/config_builder.py`: programmatic builder for the OpenTelemetry Collector configuration (produces YAML). Use it to compose receivers, exporters, processors, extensions and pipelines.
- `src/config_manager.py`: higher-level config management utilities (persisting configs, validating, applying TLS options, global scrape settings).
- `src/constants.py`: shared constants and keys used across modules.
- `tests/unit` and `tests/integration`: unit tests use `ops.testing` primitives; integration tests use `jubilant` and real Juju models.

## Event flow and reconciler
- Pattern: each event handler should perform minimal validation and then call a single `reconcile()` function (or a reconciler object).
- `reconcile()` responsibilities:
	- Compute the desired state (files, pebble layers, relation databags, k8s resources) from the charm's current model and config.
	- Compare desired vs current state and apply only necessary changes.
- Idempotency is required: running `reconcile()` multiple times must not cause unexpected side-effects.

## Separation of concerns
- Charm: event wiring and high-level state decisions.
- Reconciler/integrations: business logic for relations and desired-state computation.
- Workload helpers: Pebble layer building, file writes, and service management.

Do not place workload code (Pebble layers, file writes, k8s API calls) directly inside event handlers.

## Integrations pattern
- Use pydantic models to validate and normalise relation databag contents (see `tests/unit/test_otlp.py`).
- Keep relationship logic testable and free of side-effects: unit tests should be able to instantiate integration classes and call methods without Juju.

## Config and TLS handling
- Use `ConfigBuilder` to construct collector YAML; tests should compare structures by loading YAML with `yaml.safe_load` and asserting dicts.
- Centralise TLS handling and `insecure_skip_verify` defaults so all exporters/receivers are consistently configured.

## Testing guidance (for Copilot and contributors)
- Unit tests:
	- Use `ops.testing.Context`, `State`, `Relation`, `Container`, and `Exec` to build deterministic scenarios (see `tests/unit/conftest.py`).
	- Use the `ctx` fixture pattern and run events with `with ctx(ctx.on.update_status(), state=state) as mgr:` then `mgr.run()` or `state_out = ctx.run(...)`.
	- Patch external dependencies (e.g. `KubernetesComputeResourcesPatch`, `lightkube` clients) with `unittest.mock.patch` or `patch.object`.
	- Prefer `pytest.mark.parametrize` for permutations and assert pydantic `ValidationError` messages where applicable.

- Integration tests:
	- Use `jubilant` fixtures `charm`, `charm_resources`, and `juju` from `tests/integration/conftest.py`.
	- Build the charm with `charmcraft pack()` unless `CHARM_PATH` is provided.
	- Deploy with `juju.deploy(charm, 'otelcol', resources=charm_resources, trust=True)` and wait with `juju.wait(jubilant.all_active)`.
	- Perform container-level checks with `juju.ssh(unit, command='pebble checks', container='otelcol')`.

## Good example (thin handler)
```
def on_config_changed(self, event):
		if not self.unit.is_leader():
				return
		self.reconcile()
```

## Bad example (avoid heavy handlers)
```
def on_config_changed(self, event):
		# Bad: performing many side-effects here makes testing and reasoning difficult
		write_config_files()
		patch_kubernetes_resources()
		restart_services()
```

## Another good / bad example from this repo

**Good example (small, testable helper)** — the charm keeps filesystem and container interactions
in focused helper methods (example simplified from `src/charm.py`):
```
def _write_ca_certificates_to_disk(self, scrape_jobs, container):
	if not container.can_connect():
		return {}
	cert_paths = {}
	for job in scrape_jobs:
		ca = job.get("tls_config", {}).get("ca")
		if not ca or not self._validate_cert(ca):
			continue
		path = f"/etc/ssl/otel_{job['job_name']}_ca.pem"
		container.push(path, ca)
		cert_paths[job['job_name']] = path
	return cert_paths
```
Why it's good: single responsibility, easy to unit-test (pass a mock `container`), and no hidden global side-effects.

**Bad example (avoid IO-heavy properties)** — properties should be cheap; doing blocking IO in a property is brittle:
```
@property
def _otelcol_version(self):
	# BAD: runs `container.exec(...)` and may raise/timeout unexpectedly
	version_output, _ = container.exec(["/usr/bin/otelcol", "--version"]).wait_output()
	return parse_version(version_output)
```
Why it's bad: hidden IO in a property can throw, block, or be expensive. Prefer an explicit method like `get_workload_version()` with clear error handling and timeouts.

## PR expectations and style
- Keep changes small and well-tested. Add unit tests for logic and integration tests for behaviour changes.
- Update `src/integrations.py` and relevant tests when changing relation schemas or databag keys.
- Use clear function names and keep single-responsibility functions.

## Where to look when debugging
- `src/integrations.py`, `src/config_builder.py`, `src/config_manager.py` for relation handling and config generation.
- `tests/unit` for quick iteration; `tests/integration` for end-to-end scenarios.

If Copilot is asked to modify or debug the charm, prefer small, test-driven changes that follow these conventions.
