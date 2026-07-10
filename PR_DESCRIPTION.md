# Forward received dashboards via compressed pass-through (ADR-0001, consumer side)

## What

Reworks how otelcol forwards Grafana dashboards so that dashboards *received* over
`grafana-dashboards-consumer` are published to `grafana-dashboards-provider`
**verbatim** — without decompressing, writing to disk, or re-compressing them.

Concretely:

- **Vendors `grafana_dashboard` lib `LIBPATCH 50 → 51`**, which adds
  `GrafanaDashboardProvider.add_dashboard_precompressed(key, encoded_content, …)`
  and `remove_dashboard(key)`.
- **Rewrites `forward_dashboards`** (`src/integrations.py`):
  - Bundled (on-disk) dashboards are still published with a single
    `reload_dashboards()` (cost is small and fixed).
  - Received dashboards are published with `add_dashboard_precompressed`, keyed
    per relation as `rel_{relation_id}__{template_id}`, passing the **already
    compressed** `content` straight through.
  - `_get_dashboards`/`_add_dashboards` (decompress + disk round-trip) are
    replaced by `_get_received_dashboards`, which returns the compressed blobs
    untouched.
- **Wires the `reconcile` action** (previously declared in `charmcraft.yaml` with
  no handler) to report success after the holistic reconcile rebuilds the world.

## Why

This is the consumer side of **ADR-0001** ("Scalable dashboard/rule convergence
for large fan-in aggregators"). otelcol fans in dashboards from ~300 relations.
The previous `forward_dashboards` did, on **every** hook:

1. `copytree` the bundled dashboards,
2. for every received dashboard: `LZMABase64.decompress` + `json.loads`,
3. write each to disk, then
4. `reload_dashboards()` — which re-globs the whole directory and
   **re-compresses every file** before publishing.

Dashboards received over `grafana_dashboard` are forwarded verbatim: the incoming
compressed blob is byte-identical to what must be published. The
decompress → disk → re-compress → rescan cycle was pure, redundant work. Passing
the compressed content straight through eliminates it, so per-hook cost scales
with the received dashboards rather than re-compressing every dashboard on disk.

## Design notes

- **Per-relation keying (`rel_{id}__{template_id}`)** is stable across hooks and
  cannot collide with the `prog:{8-char}` ids that
  `GrafanaDashboardProvider.add_dashboard` auto-derives.
- **Departed relations self-clean**: `forward_dashboards` calls
  `remove_non_builtin_dashboards()` before (re)adding the current set, so
  dashboards from a removed consumer relation are no longer republished. (The
  `prog:` keyspace is what `remove_non_builtin_dashboards` sweeps — see the
  library-side rationale for reusing that namespace.)
- **`inject_dropdowns=False`** is preserved: otelcol is an aggregator, the origin
  charm already rendered topology, so we do not re-inject dropdowns.
- **Caller-trust contract**: the compressed content is not validated (validating
  would require the decompress we are trying to avoid); malformed content is
  rejected downstream by Grafana, exactly as before.

## Testing

Scenario unit tests in `tests/unit/test_dashboard_transfer.py`:

- `test_dashboard_propagation` — received dashboards are published under their
  per-relation pass-through keys, alongside otelcol's bundled dashboard.
- `test_received_content_is_forwarded_verbatim` — the published `content` is
  byte-identical to what was received and still decompresses to the original.
- `test_forwarding_does_not_decompress_received_dashboards` — spies that
  `LZMABase64.decompress` is **not** called on the send path (the O(N) win).
- `test_departed_consumer_dashboards_are_dropped` — dashboards from a removed
  consumer relation are not republished; bundled ones remain.
- `test_reconcile_action_reports_success` — the `reconcile` action rebuilds the
  world and reports success.

Run:

```sh
tox -e unit
```

Result: full unit suite `129 passed, 1 skipped, 1 xfailed, 1 xpassed`; `ruff
check` clean.

## Compatibility

- Requires the vendored `grafana_dashboard` lib at `LIBPATCH ≥ 51` (included).
- Databag schema is unchanged (same `templates` map; only the template ids for
  received dashboards change from disk-derived `file:…` names to the
  per-relation `prog:rel_{id}__…` keys). Grafana consumes the templates map
  prefix-agnostically.

## Out of scope (follow-up)

The deeper ADR-0001 items — **event-scoped delta convergence** (process only
`event.relation` on `relation-changed`), **per-relation fingerprints** in
peer/stored-state, and **`list_files`-based deletion deltas** (items 1–3) —
require reshaping the charm's holistic `_reconcile()` flow into event-aware
handlers with peer-state bookkeeping. That is a larger, higher-risk change and
will be a separate PR. This PR delivers the dominant compute win (killing the
decompress/re-compress cycle and the directory rescan for received dashboards)
plus the mandatory `reconcile` action safety net.
