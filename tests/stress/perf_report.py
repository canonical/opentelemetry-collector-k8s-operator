#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Turn the JSON artifacts produced by `src/perf.py` into a report.

Collect the artifacts from the unit first:

    mkdir -p ./perf-data
    juju ssh --container charm otelcol-agg/0 "tar cf - -C /tmp otelcol-perf" 2>/dev/null |
        tar xf - -C ./perf-data
    # or, if you only need the JSONs:
    juju scp --container charm otelcol-agg/0:'/tmp/otelcol-perf/*.json' ./perf-data/

Then:

    python tests/stress/perf_report.py ./perf-data                 # ranking per event
    python tests/stress/perf_report.py ./perf-data --md report.md  # markdown report
    python tests/stress/perf_report.py ./perf-data --slope         # cost per relation

`--slope` fits `ms = a + b * n_relations` per phase across all collected runs (least
squares), which is what turns a 10-relation lab into a defensible statement about 300.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

COUNTER_KEYS = [
    "cos_tool_lookups",
    "cos_tool_misses",
    "cos_tool_ms",
    "pebble_calls",
    "pebble_ms",
    "hookcmd_calls",
    "hookcmd_ms",
    "subprocess_calls",
    "subprocess_ms",
]


def load(path: Path) -> List[Dict[str, Any]]:
    runs: List[Dict[str, Any]] = []
    for f in sorted(path.rglob("*.json")):
        try:
            runs.append(json.loads(f.read_text()))
        except json.JSONDecodeError:
            print(f"skipping unparsable {f}")
    return runs


def _receive_otlp_relations(run: Dict[str, Any]) -> int:
    return int(run.get("relations", {}).get("receive-otlp", 0))


def regime(run: Dict[str, Any]) -> str:
    """Classify a run by the state of the cos-tool cache.

    A run with zero cos-tool misses never spawned the binary: the cache was warm. Mixing
    the two regimes in one fit is meaningless (they differ by two orders of magnitude),
    so every aggregation below is done per regime.
    """
    return "cold" if int(run.get("totals", {}).get("cos_tool_misses", 0)) > 0 else "warm"


def summary_table(runs: List[Dict[str, Any]]) -> str:
    rows = [
        "| event | regime | relations (recv-otlp) | reconcile s | since import s | "
        "process age s | load1 | cos-tool lookups | misses | cos-tool s | pebble | hookcmds |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(runs, key=lambda r: r.get("timestamp", 0)):
        t = r.get("totals", {})
        rows.append(
            "| {event} | {regime} | {rel} | {rec} | {imp} | {age} | {load} | {lookups} "
            "| {miss} | {ct} | {pc}/{pms}s | {hc}/{hms}s |".format(
                event=r.get("event", "?"),
                regime=regime(r),
                load=(r.get("loadavg") or ["?"])[0],
                rel=_receive_otlp_relations(r),
                rec=_s(r.get("reconcile_ms")),
                imp=_s(r.get("since_import_ms")),
                age=_s(r.get("process_age_ms")),
                lookups=int(t.get("cos_tool_lookups", 0)),
                miss=int(t.get("cos_tool_misses", 0)),
                ct=_s(t.get("cos_tool_ms")),
                pc=int(t.get("pebble_calls", 0)),
                pms=_s(t.get("pebble_ms")),
                hc=int(t.get("hookcmd_calls", 0)),
                hms=_s(t.get("hookcmd_ms")),
            )
        )
    return "\n".join(rows)


def _s(ms: Any) -> str:
    if ms is None:
        return "?"
    return f"{float(ms) / 1000:.2f}"


def phase_table(runs: List[Dict[str, Any]], top: int = 15) -> str:
    """Rank phases by median wall time across runs of the same cache regime."""
    per_phase: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in runs:
        for ph in r.get("phases", []):
            per_phase[ph["name"]].append(ph)

    ranked = sorted(
        per_phase.items(), key=lambda kv: -statistics.median(p["ms"] for p in kv[1])
    )
    total = sum(statistics.median(p["ms"] for p in v) for _, v in ranked) or 1.0

    rows = [
        "| phase | median s | max s | % | cos-tool lookups | misses | cos-tool s | "
        "pebble | hookcmds | runs |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, samples in ranked[:top]:
        med = statistics.median(s["ms"] for s in samples)
        rows.append(
            "| `{name}` | {med} | {mx} | {pct:.0f}% | {lookups} | {miss} | {ct} | "
            "{pc}/{pms}s | {hc}/{hms}s | {n} |".format(
                name=name,
                med=_s(med),
                mx=_s(max(s["ms"] for s in samples)),
                pct=100 * med / total,
                lookups=int(statistics.median(s.get("cos_tool_lookups", 0) for s in samples)),
                miss=int(statistics.median(s.get("cos_tool_misses", 0) for s in samples)),
                ct=_s(statistics.median(s.get("cos_tool_ms", 0) for s in samples)),
                pc=int(statistics.median(s.get("pebble_calls", 0) for s in samples)),
                pms=_s(statistics.median(s.get("pebble_ms", 0) for s in samples)),
                hc=int(statistics.median(s.get("hookcmd_calls", 0) for s in samples)),
                hms=_s(statistics.median(s.get("hookcmd_ms", 0) for s in samples)),
                n=len(samples),
            )
        )
    return "\n".join(rows)


def _fit(points: List[Tuple[float, float]]) -> Tuple[float, float]:
    """Least-squares fit of y = a + b*x. Returns (a, b)."""
    n = len(points)
    if n < 2:
        return (points[0][1] if points else 0.0, 0.0)
    sx = sum(x for x, _ in points)
    sy = sum(y for _, y in points)
    sxx = sum(x * x for x, _ in points)
    sxy = sum(x * y for x, y in points)
    denom = n * sxx - sx * sx
    if denom == 0:
        return (sy / n, 0.0)
    b = (n * sxy - sx * sy) / denom
    a = (sy - b * sx) / n
    return a, b


def slope_table(runs: List[Dict[str, Any]], extrapolate_to: int = 300) -> str:
    """Fit per-phase cost as a function of the number of receive-otlp relations."""
    per_phase: Dict[str, List[Tuple[float, float]]] = defaultdict(list)
    for r in runs:
        n = _receive_otlp_relations(r)
        for ph in r.get("phases", []):
            per_phase[ph["name"]].append((float(n), float(ph["ms"])))

    rows = [
        f"| phase | fixed cost s | cost per relation ms | projection @{extrapolate_to} s | points |",
        "|---|---|---|---|---|",
    ]
    fits = []
    for name, pts in per_phase.items():
        xs = {x for x, _ in pts}
        if len(xs) < 2:
            continue
        a, b = _fit(pts)
        fits.append((a + b * extrapolate_to, name, a, b, len(pts)))
    for proj, name, a, b, n in sorted(fits, reverse=True):
        rows.append(
            f"| `{name}` | {a / 1000:.2f} | {b:.1f} | {proj / 1000:.1f} | {n} |"
        )
    if len(rows) == 2:
        rows.append("| _(need runs with at least two different relation counts)_ | | | | |")
    return "\n".join(rows)


def hookcmd_table(runs: List[Dict[str, Any]]) -> str:
    agg: Dict[str, List[int]] = defaultdict(list)
    for r in runs:
        for cmd, count in r.get("hookcmd_by_name", {}).items():
            agg[cmd].append(count)
    if not agg:
        return "_(no hook commands recorded; Scenario runs do not execute them)_"
    rows = ["| hook command | median calls per event |", "|---|---|"]
    for cmd, counts in sorted(agg.items(), key=lambda kv: -statistics.median(kv[1])):
        rows.append(f"| `{cmd}` | {int(statistics.median(counts))} |")
    return "\n".join(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path, help="directory with the perf JSON artifacts")
    ap.add_argument("--md", type=Path, help="write a markdown report to this file")
    ap.add_argument("--slope", action="store_true", help="fit cost per relation")
    ap.add_argument("--to", type=int, default=300, help="relation count to extrapolate to")
    ap.add_argument("--top", type=int, default=15, help="how many phases to show")
    args = ap.parse_args()

    runs = load(args.path)
    if not runs:
        raise SystemExit(f"no JSON artifacts found under {args.path}")

    by_regime: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in runs:
        by_regime[regime(r)].append(r)

    parts = [
        "# Reconcile performance report\n",
        f"Runs analysed: **{len(runs)}** "
        f"(cold cos-tool cache: {len(by_regime['cold'])}, warm: {len(by_regime['warm'])})\n",
        "## Per event\n",
        summary_table(runs),
        "\n## Hook commands per event\n",
        hookcmd_table(runs),
    ]
    for name in ("cold", "warm"):
        if not by_regime[name]:
            continue
        parts += [
            f"\n## Phases ranked by wall time — {name} cos-tool cache\n",
            phase_table(by_regime[name], top=args.top),
        ]
        if args.slope:
            parts += [
                f"\n### Cost model per phase, {name} cache "
                f"(projection to {args.to} relations)\n",
                slope_table(by_regime[name], extrapolate_to=args.to),
            ]
    out = "\n".join(parts)
    print(out)
    if args.md:
        args.md.write_text(out)
        print(f"\nwritten to {args.md}")


if __name__ == "__main__":
    main()
