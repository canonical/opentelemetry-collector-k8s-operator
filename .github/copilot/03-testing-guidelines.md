# Testing Guidelines (ops.testing)

All unit tests must use the `ops.testing.Harness` and follow a consistent structure.

## Test Structure
- One test file per module
- Use fixtures for repeated setup
- Avoid mocking Juju internals unless necessary

## Required Tests
- Reconciler behavior
- Event handler → reconcile wiring
- Workload helper functions
- Error handling and edge cases

## Good Test Example
(Provide a simple, clean ops.testing example)

## Bad Test Example
(Show an overly mocked or brittle test)

## Additional Notes
- Prefer asserting on observable behavior, not internal state.
- Keep tests deterministic and isolated.
