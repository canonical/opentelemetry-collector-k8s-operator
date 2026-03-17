<!-- Copilot task file: Integration testing guidelines for this repo -->
# Integration testing guidelines for Copilot

Purpose: describe how integration tests in `tests/integration` work so Copilot can author and update integration scenarios consistently and safely.

Key points & fixtures:
- Integration tests use `jubilant` (a Juju test helper) to manage temporary models and to deploy charms.
- `charm` fixture (module-scoped) builds the charm via `charmcraft.pack()` when `CHARM_PATH` is not provided. The fixture uses a memoizer to avoid rebuilding frequently.
- `charm_resources(metadata_file='charmcraft.yaml')` reads `charmcraft.yaml` to map resource names to `upstream-source` values; pass this `resources` dict to `juju.deploy`.
- `juju` fixture uses `jubilant.temp_model(keep=KEEP_MODELS)`; optionally set `KEEP_MODELS` env var to keep models for debugging.

Common test flow & patterns:
- Deploy the charm using `juju.deploy(charm, 'otelcol', resources=charm_resources, trust=True)`.
- Wait for the unit(s) to become ready using `juju.wait(jubilant.all_active)` or other jubilant helpers.
- Use `juju.ssh(unit, command=..., container='otelcol')` for container-level checks such as `pebble checks`.
- Keep integration tests focused: one real-world scenario per test (e.g., deploy standalone charm and verify pebble checks pass, or deploy with relations and assert behaviour).
- Use module-scoped caching for expensive operations (charm build) — see `timed_memoizer` in `tests/integration/conftest.py`.

Environment & requirements:
- Integration tests require:
  - `charmcraft` installed and on PATH (for packaging if `CHARM_PATH` not set).
  - `juju` controller access and credentials for deploying into a model (the test harness uses `jubilant` to create temporary models).
  - Python deps including `jubilant` and test requirements from `requirements.txt`.
- Helpful env vars:
  - `CHARM_PATH`: path to a pre-built .charm artifact to skip building.
  - `KEEP_MODELS`: if set, `jubilant.temp_model` will keep created models after test for debugging.

Running integration tests (example):

```
python -m pip install -r requirements.txt
# Optional: export CHARM_PATH=/path/to/opentelemetry-collector-k8s_*.charm
pytest -q tests/integration
```

Notes for Copilot when authoring integration tests:
- Prefer using fixtures `charm`, `charm_resources`, and `juju` rather than manually creating models.
- Keep deployments idempotent and add appropriate waits (use `jubilant` helpers) to avoid flakes.
- For heavy or slow operations, use module-scoped fixtures and memoization to cache results.
- Add logging for long-running steps to aid debugging.
