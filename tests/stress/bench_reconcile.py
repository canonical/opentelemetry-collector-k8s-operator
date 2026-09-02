# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Stress-test / micro-benchmark for the otelcol charm reconciliation.

This measures the *charm code* execution time (i.e. `_reconcile()`) as a function
of the number of related charms. It uses the ops.testing (Scenario) framework, so
it runs the real reconciliation logic WITHOUT needing a Kubernetes cluster.

Container I/O (push/pull/replan) is handled in-memory by Scenario, so the numbers
reflect the pure Python/charm cost: relation parsing, LZMA (de)compression,
alert-rule staging, YAML generation and hashing.

Run with:
    uv run python tests/stress/bench_reconcile.py                    # quick table
    uv run python tests/stress/bench_reconcile.py --profile --n 300  # cProfile at N=300
    uv run python tests/stress/bench_reconcile.py --breakdown --n 300  # per-function breakdown
    uv run python tests/stress/bench_reconcile.py --sizes 1,50,100,200,300,500
"""

import argparse
import cProfile
import contextlib
import json
import pstats
import time
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from cosl import LZMABase64
from cosl.rules import JujuTopology
from charmlibs.interfaces.otlp._rules import RuleStore, _RulesModel
from ops import ActiveStatus
from ops.testing import Container, Context, Exec, Relation, State

from src.charm import OpenTelemetryCollectorK8sCharm

CHARM_ROOT = Path(__file__).parent.parent.parent


@contextlib.contextmanager
def k8s_patches():
    """Replicate the autouse `k8s_resource_multipatch` fixture from conftest.py."""
    with patch.multiple(
        "charms.observability_libs.v0.kubernetes_compute_resources_patch.KubernetesComputeResourcesPatch",
        _namespace="test-namespace",
        _patch=lambda *_a, **_kw: True,
        is_ready=lambda *_a, **_kw: True,
        get_status=lambda _: ActiveStatus(),
    ):
        with patch("lightkube.core.client.GenericSyncClient", new=MagicMock()):
            yield


def _make_ctx(tmp_path: Path) -> Context:
    """Replicate the `ctx` fixture from tests/unit/conftest.py."""
    for src_dir in ["grafana_dashboards", "loki_alert_rules", "prometheus_alert_rules"]:
        copytree(CHARM_ROOT / "src" / src_dir, tmp_path / "src" / src_dir, dirs_exist_ok=True)
    return Context(OpenTelemetryCollectorK8sCharm, charm_root=tmp_path)


# Load the real bundled dashboard once so every emulated client sends a realistic
# (~77KB) payload, giving LZMA (de)compression representative work.
_REAL_DASHBOARD = json.loads(
    (CHARM_ROOT / "src" / "grafana_dashboards" / "overview-dashboard.json").read_text()
)


def _dashboard_payload(idx: int) -> str:
    """Build a realistic (compressed) dashboard databag for one client.

    Uses the actual bundled overview dashboard (src/grafana_dashboards/overview-dashboard.json)
    so the LZMA compression/decompression and JSON parsing costs match production.
    The title is made unique per client to avoid the dedup-by-title collapse in
    `_get_dashboards`, so all N dashboards are actually processed.
    """
    dashboard = dict(_REAL_DASHBOARD)
    dashboard["title"] = f"{dashboard.get('title', 'Overview')} - client {idx}"
    return json.dumps(
        {
            "templates": {
                f"file:dashboard-{idx}": {
                    "charm": f"client-charm-{idx}",
                    "content": LZMABase64.compress(json.dumps(dashboard)),
                }
            }
        }
    )


def _otlp_rules_databag(idx: int) -> dict:
    """Build the full ``receive-otlp`` remote app databag for one client.

    This mirrors exactly how a remote OtlpRequirer serializes its app data
    (see charmlibs.interfaces.otlp._otlp._OtlpRequirerAppData):
      - ``rules``: the whole ``_RulesModel`` dumped to JSON and LZMA-compressed as
        a single blob (NOT a plain JSON of separately-compressed fields).
      - ``metadata``: the requirer's Juju topology as a JSON dict, used to label
        rule expressions.

    The PromQL rules are the real bundled ones from ``src/prometheus_alert_rules``.
    ``src/loki_alert_rules`` ships empty (only a .gitkeep), so we add a small,
    representative LogQL rule to exercise the LogQL path too. The topology is made
    unique per client so the N payloads are all distinct, like real deployments.
    """
    topology = JujuTopology(
        model="stress-model",
        model_uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f",
        application=f"client-{idx}",
        unit=f"client-{idx}/0",
        charm_name=f"client-charm-{idx}",
    )
    store = RuleStore(topology)
    store.add_promql_path(CHARM_ROOT / "src" / "prometheus_alert_rules", recursive=True)
    store.add_logql_path(CHARM_ROOT / "src" / "loki_alert_rules", recursive=True)
    # src/loki_alert_rules is empty in the repo; add a representative LogQL rule so
    # the LogQL path is exercised the way it would be with real log alerts.
    store.add_logql(
        {
            "groups": [
                {
                    "name": f"log_alerts_{idx}",
                    "rules": [
                        {
                            "alert": "HighLogVolume",
                            "expr": 'count_over_time({job=~".+"}[30s]) > 100',
                            "labels": {"severity": "high"},
                        }
                    ],
                }
            ]
        }
    )
    rules_model = _RulesModel(logql=store.logql.as_dict(), promql=store.promql.as_dict())
    # ops' Relation.load() runs json.loads() on each databag value before handing
    # it to pydantic, so every value must itself be a JSON string. The rules blob
    # (LZMA+base64) is therefore wrapped with json.dumps so it round-trips back to
    # the blob string, which the model's field validator then LZMA-decompresses.
    return {
        "rules": json.dumps(LZMABase64.compress(rules_model.model_dump_json())),
        "metadata": json.dumps(topology.as_dict()),
    }


def build_state(n_clients: int) -> State:
    """Build a State emulating `n_clients` clients pushing via OTLP + dashboards.

    Each client relates over:
      - receive-otlp  (telemetry + alert rules)
      - grafana-dashboards-consumer (dashboards)
    Plus outgoing relations so the aggregator actually forwards data.
    """
    relations = []
    for i in range(n_clients):
        relations.append(
            Relation(
                "receive-otlp",
                id=1000 + i,
                remote_app_data=_otlp_rules_databag(i),
            )
        )
        relations.append(
            Relation(
                "grafana-dashboards-consumer",
                id=5000 + i,
                remote_app_data={"dashboards": _dashboard_payload(i)},
            )
        )

    # Outgoing (backends) so pipelines have exporters
    relations.append(Relation("send-remote-write", remote_app_data={}))
    relations.append(Relation("send-loki-logs", remote_app_data={}))
    relations.append(Relation("grafana-dashboards-provider"))

    execs = {
        Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout=""),
        Exec(["/usr/bin/otelcol", "--version"], return_code=0, stdout="otelcol version 0.130.1"),
    }
    return State(
        relations=relations,
        leader=True,
        containers=[Container("otelcol", can_connect=True, execs=execs)],
    )


def time_reconcile(n_clients: int, repeats: int = 3) -> float:
    """Return the median wall-clock time (seconds) of one reconciliation."""
    samples = []
    for _ in range(repeats):
        with TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            state = build_state(n_clients)
            with k8s_patches():
                start = time.perf_counter()
                ctx.run(ctx.on.update_status(), state=state)
                samples.append(time.perf_counter() - start)
    samples.sort()
    return samples[len(samples) // 2]


@contextlib.contextmanager
def _no_cos_tool():
    """Neutralize cos-tool subprocess calls to isolate the charm's own per-client cost.

    cos-tool is invoked a *fixed* number of times (independent of client count) to
    inject label matchers into alert rules. It dominates the wall clock but does not
    scale with the number of clients, so patching it out reveals the true O(n) cost.
    """
    def _fake_exec(self, *args, **kwargs):
        # Return the stdin unchanged (skip the real cos-tool subprocess).
        if len(args) >= 2:
            return args[1] or ""
        return kwargs.get("stdin") or ""

    with patch("cosl.cos_tool.CosTool._exec", _fake_exec):
        yield


def run_table(sizes, isolate=False):
    label = "  (cos-tool patched out)" if isolate else ""
    print(f"{'clients':>8} | {'relations':>9} | {'median (s)':>10} | {'per-client (ms)':>15}{label}")
    print("-" * 60)
    for n in sizes:
        if isolate:
            with _no_cos_tool():
                t = time_reconcile(n)
        else:
            t = time_reconcile(n)
        per_client = (t / n * 1000) if n else 0
        print(f"{n:>8} | {n * 2:>9} | {t:>10.3f} | {per_client:>15.2f}")


def run_profile(n_clients: int, isolate: bool = False):
    with TemporaryDirectory() as td:
        ctx = _make_ctx(Path(td))
        state = build_state(n_clients)
        profiler = cProfile.Profile()
        cm = _no_cos_tool() if isolate else contextlib.nullcontext()
        with k8s_patches(), cm:
            profiler.enable()
            ctx.run(ctx.on.update_status(), state=state)
            profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative")
    suffix = " (cos-tool patched out)" if isolate else ""
    print(f"\n=== cProfile @ {n_clients} clients{suffix} (top 30 by cumulative time) ===")
    stats.print_stats(30)


# --- Per-charm-function breakdown --------------------------------------------
#
# Instead of made-up categories, we attribute the time to the REAL functions that
# `_reconcile()` calls directly. cProfile records, for each edge
# (caller -> callee), the cumtime of that edge (the callee's time plus everything
# it calls below it). Since the functions in `_reconcile()` run sequentially and
# do not call one another, those cumtimes do NOT overlap and add up to the total
# of `_reconcile()`. The names come from the profile; nothing is hardcoded.


def _find_reconcile_key(stats):
    for key in stats.stats:
        filename, _lineno, funcname = key
        if funcname == "_reconcile" and filename.endswith("charm.py"):
            return key
    raise RuntimeError("could not find _reconcile in the profile")


def _short_name(func_key) -> str:
    """Readable short name: 'src/file.py:line(function)', or the builtin as-is."""
    filename, lineno, funcname = func_key
    if not filename or filename.startswith("~") or filename.startswith("{"):
        return funcname  # builtin
    # Trim the path starting at 'src/', or to the last couple of segments.
    parts = filename.split("/")
    if "src" in parts:
        short = "/".join(parts[parts.index("src"):])
    elif "site-packages" in parts:
        short = "/".join(parts[parts.index("site-packages") + 1:])
    else:
        short = "/".join(parts[-2:])
    return f"{short}:{lineno}({funcname})"


def run_breakdown(n_clients: int, isolate: bool = False, top: int = 30):
    with TemporaryDirectory() as td:
        ctx = _make_ctx(Path(td))
        state = build_state(n_clients)
        profiler = cProfile.Profile()
        cm = _no_cos_tool() if isolate else contextlib.nullcontext()
        with k8s_patches(), cm:
            profiler.enable()
            ctx.run(ctx.on.update_status(), state=state)
            profiler.disable()

    stats = pstats.Stats(profiler)
    reconcile_key = _find_reconcile_key(stats)
    reconcile_cumtime = stats.stats[reconcile_key][3]

    # For each function, check whether _reconcile called it directly and extract
    # the cumtime of that specific edge.
    # stats.stats[callee] = (cc, nc, tottime, cumtime, callers)
    # callers[caller_key] = (cc, nc, tottime, cumtime)  <- edge cumtime
    rows = []
    attributed = 0.0
    for callee_key, (_cc, _nc, _tt, _ct, callers) in stats.stats.items():
        edge = callers.get(reconcile_key)
        if edge is None:
            continue
        edge_cumtime = edge[3]
        rows.append((_short_name(callee_key), edge_cumtime))
        attributed += edge_cumtime

    rows.sort(key=lambda x: x[1], reverse=True)
    # Unattributed = inline code inside _reconcile (loops, assignments) plus its
    # own tottime; we surface it as "(inline in _reconcile)".
    inline = reconcile_cumtime - attributed
    if inline > 0:
        rows.append(("(inline in _reconcile: loops/assignments/own tottime)", inline))

    suffix = " (cos-tool patched out)" if isolate else ""
    print(f"\n=== _reconcile() breakdown by function @ {n_clients} clients{suffix} ===")
    print("(cumtime of each direct call from _reconcile; they do not overlap)\n")
    print(f"{'cumtime (s)':>12} | {'% recon':>8} | function")
    print("-" * 90)
    for name, t in rows[:top]:
        pct = (t / reconcile_cumtime * 100) if reconcile_cumtime else 0
        print(f"{t:>12.3f} | {pct:>7.1f}% | {name}")
    print("-" * 90)
    print(f"{reconcile_cumtime:>12.3f} | {100.0:>7.1f}% | _reconcile TOTAL")


def main():
    parser = argparse.ArgumentParser(
        description="Micro-benchmark of the otelcol charm's _reconcile().",
    )
    parser.add_argument(
        "--sizes",
        default="1,50,100,200,300",
        help="comma-separated list of client counts (table mode)",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="run cProfile instead of the timing table",
    )
    parser.add_argument(
        "--breakdown",
        action="store_true",
        help="break down _reconcile() time by the charm functions it calls",
    )
    parser.add_argument(
        "--n",
        type=int,
        default=300,
        help="client count to use with --profile/--breakdown (default: 300)",
    )
    parser.add_argument(
        "--isolate",
        action="store_true",
        help="patch out cos-tool to isolate the charm's O(n) cost",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=30,
        help="number of functions to list in --breakdown (default: 30)",
    )
    args = parser.parse_args()

    if args.breakdown:
        run_breakdown(args.n, isolate=args.isolate, top=args.top)
    elif args.profile:
        run_profile(args.n, isolate=args.isolate)
    else:
        sizes = [int(x) for x in args.sizes.split(",")]
        run_table(sizes, isolate=args.isolate)


if __name__ == "__main__":
    main()
