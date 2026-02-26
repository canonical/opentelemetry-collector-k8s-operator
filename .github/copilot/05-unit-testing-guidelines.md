<!-- Copilot task file: Unit testing guidelines for this repo -->
# Unit testing guidelines for Copilot

Purpose: teach Copilot the patterns and conventions used by the repo's unit tests so it can generate and update tests consistently.

- Test runner: `pytest` (tests live in `tests/unit`).
- Style: small, focused unit tests that exercise charm logic via `ops.testing.Context` and `ops.testing.State`.

Fixtures & helpers (common):
- `ctx` (fixture): returns an `ops.testing.Context(OpenTelemetryCollectorK8sCharm, charm_root=...)`. Use `with ctx(ctx.on.update_status(), state=state) as mgr:` or `state_out = ctx.run(ctx.on.update_status(), state)` to run events.
- `otelcol_container` (fixture): list containing a `Container` for the `otelcol` container with `Exec` entries for expected commands.
- `execs` (fixture): provides `Exec([...])` objects used to emulate container command results.
- `mock_container`, `disconnected_container`: MagicMock-based container fixtures for fine-grained control over connectivity and filesystem behavior.
- `cert_obj`, `server_cert`, `ca_cert`, `sample_ca_cert`: certificate fixtures used by certificate-related tests.
- Helpers in `tests/unit/helpers.py`: e.g. `get_otelcol_file(state_out, ctx, file_path)` reads files from the fake container filesystem and asserts service state.

Testing patterns & conventions:
- Use `ops.testing.State`, `Relation`, and `Container` to build a synthetic charm state rather than running the charm in a real Juju model for unit tests.
- Preferred approach for exercising charm reactions:
  - Construct a `State` with `relations`, `leader` flag, and `containers` as needed.
  - Use `with ctx(ctx.on.update_status(), state=state) as mgr:` then call `mgr.run()` or call `ctx.run(...)` directly.
- Patch external dependencies with `unittest.mock.patch` and `patch.object` to control behavior (e.g., patch `mgr.charm.otlp_consumer._protocols`).
- Use `pytest.mark.parametrize` liberally for input permutations and validation cases.
- Validate model/data objects using `pydantic` where appropriate and assert raised `ValidationError` messages.
- For filesystem checks inside containers, use `otelcol.get_filesystem(ctx)` and read files via the test helper.

Mocking Kubernetes & external libs:
- An autouse fixture `k8s_resource_multipatch` patches `KubernetesComputeResourcesPatch` and `lightkube.core.client.GenericSyncClient` so unit tests don't require k8s.

What to assert:
- Focus on: data transformations, relation databag contents, config generation YAML, and method outputs (e.g., `get_remote_otlp_endpoints`).
- When inspecting generated YAML configs use `yaml.safe_load` and compare dict structures rather than string equality.
- Prefer asserting `model_dump()` values for pydantic models when comparing endpoints or objects.

Running unit tests locally:

```
python -m pip install -r requirements.txt
pytest -q tests/unit
```

Notes for Copilot when editing/authoring unit tests:
- Reuse existing fixtures names and patterns; ensure new tests use `ctx` and `otelcol_container` where applicable.
- Keep tests self-contained and deterministic: patch external calls, and provide `Exec` entries for expected container invocations.
- When adding new fixtures, mimic the style in `tests/unit/conftest.py` and add minimal setup/teardown.
