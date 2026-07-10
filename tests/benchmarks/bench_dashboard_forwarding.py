#!/usr/bin/env python3
"""Micro-benchmark for dashboard forwarding: OLD (decompress+rescan) vs NEW (pass-through).

This exercises the exact compute + local-I/O code paths used by
``integrations.forward_dashboards`` at scale, WITHOUT deploying Juju. The feature's win is
CPU (no decompress/re-compress) and disk I/O (no per-dashboard file writes, no directory
rescan), all of which are pure-Python / filesystem operations reproducible in a harness.

It builds a synthetic fan-in of ``--relations`` relations, each providing ``--per-relation``
RECEIVED dashboards of roughly ``--kib`` KiB (uncompressed), plus ``--bundled`` of otelcol's OWN
on-disk dashboards, then times the strategies using the real ``GrafanaDashboardProvider`` and the
real ``cosl`` LZMA+base64 codec.

Received dashboards are forwarded verbatim (never compressed by the NEW path). Bundled dashboards
ARE compressed by every strategy via ``reload_dashboards()`` -- so ``--bundled`` is the knob that
makes the NEW pass-through path do compression work and reveals how the win narrows as the
bundled:received ratio grows. ``--runs`` sets how many times each strategy runs; reported numbers
are the MEDIAN across runs (more runs = less scheduling/GC noise), not a larger workload.

Metrics reported per implementation:
  * wall-clock time (median of ``--runs``)
  * CPU time (process + children)
  * peak additional memory (tracemalloc)
  * number of gzip/lzma (de)compressions performed (via a counting wrapper)
  * bytes written to the dashboards dir (proxy for disk I/O ops)

Usage:
    # from the repo root, with the venv synced (uv sync --extra=dev):
    PYTHONPATH="$PWD:$PWD/lib:$PWD/src" .venv/bin/python \
        tests/benchmarks/bench_dashboard_forwarding.py --relations 300 --per-relation 2 --kib 40

Tip: wrap the whole invocation in `strace -f -c -e trace=%file,write` to get exact syscall
counts, and in `/usr/bin/time -v` to get max RSS, when running inside your constrained VM.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import time
import tracemalloc
from pathlib import Path
from tempfile import mkdtemp
from typing import Dict, List
from unittest.mock import patch

from cosl import LZMABase64
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.testing import Harness

from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider

# A minimal charm that only wires the grafana-dashboards-provider endpoint. This isolates the
# dashboard-forwarding compute from the rest of the otelcol charm (containers, TLS, etc.), so the
# benchmark measures exactly the code path this PR changes and stays cheap on a small VM.
_PROVIDER_META = """
name: bench-otelcol
provides:
  grafana-dashboards-provider:
    interface: grafana_dashboard
"""


class _BenchProviderCharm(CharmBase):
    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.provider = GrafanaDashboardProvider(
            self,
            relation_name="grafana-dashboards-provider",
            dashboards_path=self._bench_dashboards_path,
        )

    # Set by the harness before begin(); a per-run temp dir for bundled dashboards.
    _bench_dashboards_path = "/tmp/bench-dashboards"


# --------------------------------------------------------------------------------------
# Instrumentation: count (de)compressions so we can prove the pass-through avoids them.
# --------------------------------------------------------------------------------------
class Counters:
    def __init__(self) -> None:
        self.compress = 0
        self.decompress = 0


def _instrument_codec(counters: Counters):
    real_compress = LZMABase64.compress
    real_decompress = LZMABase64.decompress

    def counting_compress(*a, **k):
        counters.compress += 1
        return real_compress(*a, **k)

    def counting_decompress(*a, **k):
        counters.decompress += 1
        return real_decompress(*a, **k)

    return patch.multiple(
        LZMABase64,
        compress=staticmethod(counting_compress),
        decompress=staticmethod(counting_decompress),
    )


# --------------------------------------------------------------------------------------
# Synthetic fan-in.
# --------------------------------------------------------------------------------------
def _make_dashboard(kib: int, salt: str) -> dict:
    """A dashboard whose JSON is ~kib KiB, with enough structure to be realistic."""
    # ~1 KiB per panel row of filler; scale the number of panels to hit the target size.
    panels = []
    approx = 0
    i = 0
    while approx < kib * 1024:
        panel = {
            "id": i,
            "title": f"panel-{salt}-{i}",
            "type": "timeseries",
            "targets": [{"expr": f'rate(some_metric_total{{juju_application="{salt}"}}[5m])'}],
            "description": "x" * 512,
        }
        panels.append(panel)
        approx += len(json.dumps(panel))
        i += 1
    return {"title": f"dash-{salt}", "uid": salt[:20], "panels": panels}


def build_fan_in(relations: int, per_relation: int, kib: int) -> List[dict]:
    """Return a list of relation databag payloads mimicking grafana-dashboards-consumer."""
    payloads = []
    for r in range(relations):
        templates = {}
        for d in range(per_relation):
            salt = f"r{r}d{d}"
            encoded = LZMABase64.compress(json.dumps(_make_dashboard(kib, salt)))
            templates[f"file:{salt}"] = {"charm": f"charm-{r}", "content": encoded}
        payloads.append({"templates": templates})
    return payloads


def write_bundled_dashboards(dest_dir: Path, count: int, kib: int) -> None:
    """Write ``count`` raw-JSON bundled dashboards to ``dest_dir``.

    Bundled dashboards are otelcol's *own* on-disk dashboards. Every strategy publishes them via
    ``reload_dashboards()``, which reads each file and **compresses** it. This is the only path on
    which the NEW (pass-through) implementation performs compression, so raising ``--bundled``
    increases the compress workload shared by all strategies and shows how the pass-through win
    narrows as the bundled:received ratio grows.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        salt = f"bundled{i}"
        # Written UNcompressed on disk; reload_dashboards() will compress it.
        (dest_dir / f"{salt}.json").write_text(json.dumps(_make_dashboard(kib, salt)))


# --------------------------------------------------------------------------------------
# The two implementations, isolated to the send-side compute + disk work.
# We drive the *real* GrafanaDashboardProvider for both, differing only in how received
# dashboards are turned into published templates (the thing this PR changes).
# --------------------------------------------------------------------------------------
def old_forward(provider, payloads: List[dict], dest_dir: Path) -> None:
    """OLD behaviour: decompress every received dashboard, write to disk, then rescan+recompress."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    for r, payload in enumerate(payloads):
        for template_id, template in payload["templates"].items():
            content = json.loads(LZMABase64.decompress(template["content"]))  # DECOMPRESS
            title = template_id.replace(":", "_")
            fname = f"juju_{title}-charm-{r}.json"
            (dest_dir / fname).write_text(json.dumps(content))  # DISK WRITE
    # reload_dashboards globs the whole dir and RE-COMPRESSES every file.
    provider._dashboards_path = dest_dir.as_posix()
    provider.reload_dashboards(inject_dropdowns=False)


def new_forward(provider, payloads: List[dict], dest_dir: Path) -> None:
    """NEW behaviour (per-call publish): pass-through, but republish on every add.

    This mirrors the current consumer loop: each ``add_dashboard_precompressed`` republishes the
    whole templates dict, which is O(N^2) in the number of dashboards. Bundled dashboards on disk
    are loaded (and compressed) once via reload_dashboards(), like production.
    """
    provider.reload_dashboards(inject_dropdowns=False)  # compresses bundled dashboards
    provider.remove_non_builtin_dashboards()
    for r, payload in enumerate(payloads):
        for template_id, template in payload["templates"].items():
            provider.add_dashboard_precompressed(
                key=f"rel_{r}__{template_id}",
                encoded_content=template["content"],  # VERBATIM
                inject_dropdowns=False,
            )


def new_forward_batched(provider, payloads: List[dict], dest_dir: Path) -> None:
    """NEW behaviour (batch publish): accumulate all pass-through dashboards, publish ONCE.

    Same verbatim pass-through, but the per-relation databag write is deferred by suppressing the
    per-call publish and calling ``update_dashboards()`` a single time at the end. This avoids the
    O(N^2) re-serialization of the growing templates dict. Bundled dashboards on disk are loaded
    (and compressed) once via reload_dashboards(), like production.
    """
    provider.reload_dashboards(inject_dropdowns=False)  # compresses bundled dashboards
    provider.remove_non_builtin_dashboards()
    for r, payload in enumerate(payloads):
        for template_id, template in payload["templates"].items():
            provider.add_dashboard_precompressed(
                key=f"rel_{r}__{template_id}",
                encoded_content=template["content"],  # VERBATIM
                inject_dropdowns=False,
                publish=False,  # defer the databag write
            )
    provider.update_dashboards()  # single publish (matches production forward_dashboards)


# --------------------------------------------------------------------------------------
# Harness: a live provider inside a Scenario manager, timed over N runs.
# --------------------------------------------------------------------------------------
def _dir_bytes(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def _new_harness(dashboards_path: Path) -> Harness:
    _BenchProviderCharm._bench_dashboards_path = str(dashboards_path)
    dashboards_path.mkdir(parents=True, exist_ok=True)
    harness = Harness(_BenchProviderCharm, meta=_PROVIDER_META)
    harness.set_leader(True)
    harness.begin()
    # A grafana relation so the provider actually writes a databag.
    rel_id = harness.add_relation("grafana-dashboards-provider", "grafana")
    harness.add_relation_unit(rel_id, "grafana/0")
    return harness


def run_impl(
    name: str, impl, payloads: List[dict], runs: int, bundled: int = 0, kib: int = 40
) -> Dict:
    wall, cpu, peak_mem, comp, decomp, disk = [], [], [], [], [], []

    for _ in range(runs):
        dest = Path(mkdtemp()) / "dashboards"
        # Bundled (own, on-disk) dashboards, shared by all strategies via reload_dashboards().
        # These are the dashboards the NEW pass-through path still compresses.
        if bundled:
            write_bundled_dashboards(dest, bundled, kib)
        counters = Counters()
        harness = _new_harness(dest)
        try:
            provider = harness.charm.provider
            tracemalloc.start()
            t0, c0 = time.perf_counter(), time.process_time()
            with _instrument_codec(counters):
                impl(provider, payloads, dest)
            t1, c1 = time.perf_counter(), time.process_time()
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        finally:
            harness.cleanup()

        wall.append(t1 - t0)
        cpu.append(c1 - c0)
        peak_mem.append(peak)
        comp.append(counters.compress)
        decomp.append(counters.decompress)
        disk.append(_dir_bytes(dest) if dest.exists() else 0)
        shutil.rmtree(dest.parent, ignore_errors=True)

    return {
        "name": name,
        "wall_s": statistics.median(wall),
        "cpu_s": statistics.median(cpu),
        "peak_mem_mib": statistics.median(peak_mem) / 1024 / 1024,
        "compress_calls": statistics.median(comp),
        "decompress_calls": statistics.median(decomp),
        "disk_bytes": statistics.median(disk),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--relations", type=int, default=300)
    ap.add_argument("--per-relation", type=int, default=2)
    ap.add_argument("--kib", type=int, default=40, help="approx uncompressed KiB per dashboard")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument(
        "--bundled",
        type=int,
        default=0,
        help="number of otelcol's OWN on-disk dashboards. These are compressed by "
        "reload_dashboards() in every strategy, so they are the workload that makes the NEW "
        "pass-through path compress. Raise this to see how the win narrows as the "
        "bundled:received ratio grows.",
    )
    args = ap.parse_args()

    total = args.relations * args.per_relation
    print(
        f"Building fan-in: {args.relations} relations x {args.per_relation} dashboards "
        f"= {total} received (~{args.kib} KiB each) + {args.bundled} bundled ..."
    )
    payloads = build_fan_in(args.relations, args.per_relation, args.kib)

    results = [
        run_impl("OLD (decompress+disk+rescan)", old_forward, payloads, args.runs, args.bundled, args.kib),
        run_impl("NEW (pass-through, per-call)", new_forward, payloads, args.runs, args.bundled, args.kib),
        run_impl("NEW (pass-through, batched)", new_forward_batched, payloads, args.runs, args.bundled, args.kib),
    ]

    hdr = f"{'impl':<32}{'wall(s)':>10}{'cpu(s)':>10}{'peakMiB':>10}{'compress':>10}{'decompress':>12}{'diskKiB':>10}"
    print("\n" + hdr)
    print("-" * len(hdr))
    for r in results:
        print(
            f"{r['name']:<32}{r['wall_s']:>10.3f}{r['cpu_s']:>10.3f}{r['peak_mem_mib']:>10.1f}"
            f"{r['compress_calls']:>10.0f}{r['decompress_calls']:>12.0f}{r['disk_bytes'] / 1024:>10.1f}"
        )

    old = results[0]
    for new in results[1:]:
        print(
            f"\nvs '{new['name']}':"
            f"\n  CPU speedup: {old['cpu_s'] / max(new['cpu_s'], 1e-9):.1f}x   "
            f"decompress avoided: {old['decompress_calls'] - new['decompress_calls']:.0f}   "
            f"compress avoided: {old['compress_calls'] - new['compress_calls']:.0f}   "
            f"disk KiB avoided: {(old['disk_bytes'] - new['disk_bytes']) / 1024:.0f}"
        )


if __name__ == "__main__":
    main()
