# Charm Architecture

This charm uses a structured, predictable architecture designed for clarity and maintainability.

## File Layout
- `src/charm.py`: event handlers and charm wiring
- `src/reconciler.py`: reconciliation logic
- `src/workload.py`: workload-specific operations
- `src/utils.py`: small helper utilities

## Event Flow
- All Juju events should delegate to a single `reconcile()` call.
- Event handlers must remain thin and free of business logic.
- The reconciler is responsible for computing and applying desired state.

## Separation of Concerns
- Charm logic handles events and state transitions.
- Workload logic handles configuration, services, and health checks.
- No workload logic should appear in `charm.py`.

## Good Example
(Provide a short example of a clean event handler)

## Bad Example
(Provide an example of an event handler doing too much work)
