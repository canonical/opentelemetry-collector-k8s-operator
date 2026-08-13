#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""TEMPORARY diagnostic instrumentation for the reconcile hot path. DO NOT MERGE.

Answers "where does the reconcile time go?" with hard numbers, per phase of `_reconcile`:

  * wall time
  * cos-tool invocations, split into cache hits and misses (misses = real `subprocess`)
  * every other subprocess (count + time)
  * every Pebble HTTP request (count + time)
  * every Juju hook command (count + time), with a per-command breakdown in the summary

Three outputs per hook execution:

  1. `juju-log` (INFO): one line per phase plus a summary line, greppable with `PERF`.
  2. A JSON file per event under ``OUT_DIR`` (default ``/tmp/otelcol-perf``), consumed by
     ``tests/stress/perf_report.py`` to build the report.
  3. An OpenTelemetry span per phase, so with `send-charm-traces` related to Tempo the
     phases show up nested under `ops.main`, alongside the spans that `ops` already emits
     for every hook command (`ops/model.py:_wrap_hookcmd`) and every Pebble call.

Why not only cProfile: it inflates the run ~2x (measured 4.68s -> 9.15s on a 100-relation
reconcile) and its cumulative view is dominated by stdlib/urllib frames instead of charm
phases. cProfile stays available (`OTELCOL_PERF_CPROFILE=1`) for ranking pure-Python hot
spots by `tottime`, and it now dumps a full `.prof` to disk instead of a truncated dump in
the log.

Usage:
    Enabled by default in this diagnostic branch. Toggle with env vars when running the
    Scenario harness or unit tests:
        OTELCOL_PERF=0              disable entirely
        OTELCOL_PERF_CPROFILE=1     also dump a .prof per event
        OTELCOL_PERF_DIR=/some/dir  where to write the JSON/.prof files

    Collect from the unit:
        juju ssh --container charm otelcol-agg/0 "tar cf - -C /tmp otelcol-perf" > perf.tar
        # or: juju scp --container charm otelcol-agg/0:/tmp/otelcol-perf/'*.json' ./perf/
"""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import os
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)


def _flag(name: str, default: str = "1") -> bool:
    return os.environ.get(name, default).lower() not in ("", "0", "false", "no")


ENABLED = _flag("OTELCOL_PERF")
CPROFILE = _flag("OTELCOL_PERF_CPROFILE", default="0")
OUT_DIR = Path(os.environ.get("OTELCOL_PERF_DIR", "/tmp/otelcol-perf"))  # noqa: S108

# Wall clock at import time of this module, i.e. as early as possible in the hook.
_IMPORT_TIME = time.monotonic()


# --------------------------------------------------------------------------- counters
@dataclass
class _Counters:
    """Process-wide counters, sampled at phase boundaries to compute deltas."""

    subprocess_calls: int = 0
    subprocess_seconds: float = 0.0
    cos_tool_lookups: int = 0  # calls into cosl's memoized _exec (hit or miss)
    cos_tool_misses: int = 0  # of those, the ones that spawned cos-tool
    cos_tool_seconds: float = 0.0  # time spent inside cos-tool subprocesses
    pebble_calls: int = 0
    pebble_seconds: float = 0.0
    hookcmd_calls: int = 0
    hookcmd_seconds: float = 0.0
    juju_log_calls: int = 0
    juju_log_seconds: float = 0.0
    subprocess_by_name: Counter = field(default_factory=Counter)

    def snapshot(self) -> Dict[str, float]:
        return {
            "subprocess_calls": self.subprocess_calls,
            "subprocess_ms": self.subprocess_seconds * 1000,
            "cos_tool_lookups": self.cos_tool_lookups,
            "cos_tool_misses": self.cos_tool_misses,
            "cos_tool_ms": self.cos_tool_seconds * 1000,
            "pebble_calls": self.pebble_calls,
            "pebble_ms": self.pebble_seconds * 1000,
            "hookcmd_calls": self.hookcmd_calls,
            "hookcmd_ms": self.hookcmd_seconds * 1000,
            "juju_log_calls": self.juju_log_calls,
            "juju_log_ms": self.juju_log_seconds * 1000,
        }


COUNTERS = _Counters()


@dataclass
class PhaseRecord:
    """Measurements for a single named phase of the reconcile."""

    name: str
    ms: float
    counters: Dict[str, float]
    attrs: Dict[str, Any] = field(default_factory=dict)


PHASES: List[PhaseRecord] = []


# --------------------------------------------------------------------------- patching
_patched = False


def _patch_subprocess() -> None:
    """Count and time every subprocess, classified by argv[0].

    This is the only reliable interception point: Juju hook commands are subprocesses
    (`juju-log`, `relation-get`, ...), and `ops.hookcmds` binds its `run` helper by name
    at import time, so patching the helper's module after import has no effect. Note that
    every `logger.debug()` in charm or library code is one `juju-log` fork, which is
    invisible to Scenario and is the reason this classification matters.
    """
    real_run = subprocess.run

    @functools.wraps(real_run)
    def run(*args: Any, **kwargs: Any):
        cmd = args[0] if args else kwargs.get("args")
        name = "?"
        if isinstance(cmd, (list, tuple)) and cmd:
            name = os.path.basename(str(cmd[0]))
        elif isinstance(cmd, str):
            name = os.path.basename(cmd.split()[0]) if cmd else "?"
        t0 = time.monotonic()
        try:
            return real_run(*args, **kwargs)
        finally:
            dt = time.monotonic() - t0
            COUNTERS.subprocess_calls += 1
            COUNTERS.subprocess_seconds += dt
            COUNTERS.subprocess_by_name[name] += 1
            if "cos-tool" in name:
                COUNTERS.cos_tool_misses += 1
                COUNTERS.cos_tool_seconds += dt
            elif name == "juju-log":
                COUNTERS.juju_log_calls += 1
                COUNTERS.juju_log_seconds += dt
            else:
                # Everything else a charm spawns is a Juju hook command.
                COUNTERS.hookcmd_calls += 1
                COUNTERS.hookcmd_seconds += dt

    subprocess.run = run  # type: ignore[assignment]


def _patch_cos_tool() -> None:
    """Count every *lookup* into cosl's memoized cos-tool exec.

    ``cos_tool_misses`` is counted by the subprocess patch, so
    ``lookups - misses`` is the number of cache hits: exactly the metric needed to tell
    "the cache is working" from "the cache is not the problem".
    """
    try:
        from cosl import cos_tool  # type: ignore
    except ImportError:  # pragma: no cover - only if cosl layout changes
        logger.warning("PERF: could not patch cosl.cos_tool")
        return

    real_exec = cos_tool._exec

    @functools.wraps(real_exec)
    def counting_exec(*args: Any, **kwargs: Any):
        COUNTERS.cos_tool_lookups += 1
        return real_exec(*args, **kwargs)

    cos_tool._exec = counting_exec
    # `CosTool._exec` delegates to the module-level function, so instances pick this up.


def _patch_pebble() -> None:
    """Count and time every Pebble HTTP request."""
    try:
        from ops import pebble  # type: ignore
    except ImportError:  # pragma: no cover
        return

    real_request_raw = pebble.Client._request_raw

    @functools.wraps(real_request_raw)
    def request_raw(self: Any, *args: Any, **kwargs: Any):
        t0 = time.monotonic()
        try:
            return real_request_raw(self, *args, **kwargs)
        finally:
            COUNTERS.pebble_calls += 1
            COUNTERS.pebble_seconds += time.monotonic() - t0

    pebble.Client._request_raw = request_raw  # type: ignore[assignment]


def install() -> None:
    """Install all patches. Idempotent; safe to call from the charm constructor."""
    global _patched
    if not ENABLED or _patched:
        return
    _patched = True
    _patch_subprocess()
    _patch_cos_tool()
    _patch_pebble()


# ------------------------------------------------------------------------------ spans
def _tracer():
    try:
        import opentelemetry.trace  # type: ignore

        return opentelemetry.trace.get_tracer("otelcol.perf")
    except ImportError:  # pragma: no cover
        return None


@contextlib.contextmanager
def phase(name: str, **attrs: Any) -> Iterator[Dict[str, Any]]:
    """Measure a named phase of the reconcile.

    Yields a mutable dict; anything put in it is recorded as an attribute of the phase
    (and of the span), which is how phases report domain facts such as the number of
    relations or rules they processed::

        with perf.phase("otlp_stage_rules") as p:
            ...
            p["n_rules"] = len(rules)
    """
    if not ENABLED:
        yield {}
        return

    before = COUNTERS.snapshot()
    t0 = time.monotonic()
    tracer = _tracer()
    span_cm = tracer.start_as_current_span(f"perf.{name}") if tracer else contextlib.nullcontext()
    try:
        with span_cm as span:
            try:
                yield attrs
            finally:
                ms = (time.monotonic() - t0) * 1000
                after = COUNTERS.snapshot()
                delta = {k: round(after[k] - before[k], 3) for k in after}
                PHASES.append(PhaseRecord(name=name, ms=round(ms, 1), counters=delta, attrs=attrs))
                if span is not None:
                    with contextlib.suppress(Exception):
                        for k, v in {**delta, **attrs}.items():
                            span.set_attribute(f"perf.{k}", v)
    except Exception:
        raise


def measure(name: str):
    """Decorator form of `phase`, for whole functions."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any):
            with phase(name):
                return func(*args, **kwargs)

        return wrapper

    return decorator


# ----------------------------------------------------------------------------- report
def _process_age_ms() -> Optional[float]:
    """Age of this process in ms, i.e. including Python/venv import time.

    Import time of a large charm venv is invisible to any in-charm profiler but very
    much visible to the operator waiting for convergence, so it is reported explicitly.
    """
    try:
        with open("/proc/self/stat") as f:
            starttime_ticks = int(f.read().split(") ", 1)[1].split()[19])
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
        hz = os.sysconf("SC_CLK_TCK")
        return round((uptime - starttime_ticks / hz) * 1000, 1)
    except Exception:  # pragma: no cover - /proc not available
        return None


def _loadavg() -> Optional[List[float]]:
    """Host load average. A contaminated (CPU-starved) run must be discarded, not averaged."""
    try:
        return [round(x, 2) for x in os.getloadavg()]
    except OSError:  # pragma: no cover
        return None


def report(charm: Any = None, event: str = "?", extra: Optional[Dict[str, Any]] = None) -> None:
    """Emit the per-phase lines, the summary line, and the JSON artifact."""
    if not ENABLED:
        return

    since_import_ms = round((time.monotonic() - _IMPORT_TIME) * 1000, 1)
    totals = COUNTERS.snapshot()

    relations: Dict[str, int] = {}
    rule_files: Dict[str, int] = {}
    if charm is not None:
        with contextlib.suppress(Exception):
            relations = {
                name: len(rels) for name, rels in charm.model.relations.items() if rels
            }
        with contextlib.suppress(Exception):
            root = Path(charm.charm_dir).absolute()
            for label, rel in (
                ("promql", "prometheus_alert_rules"),
                ("logql", "loki_alert_rules"),
                ("dashboards", "grafana_dashboards"),
            ):
                d = root / rel
                rule_files[label] = len(list(d.rglob("*"))) if d.is_dir() else 0

    payload = {
        "event": event,
        "timestamp": time.time(),
        "unit": os.environ.get("JUJU_UNIT_NAME", "?"),
        "process_age_ms": _process_age_ms(),
        "loadavg": _loadavg(),
        "cpu_count": os.cpu_count(),
        "since_import_ms": since_import_ms,
        "totals": totals,
        "subprocess_by_name": dict(COUNTERS.subprocess_by_name),
        "hookcmd_by_name": dict(COUNTERS.subprocess_by_name),
        "relations": relations,
        "staged_files": rule_files,
        "phases": [
            {"name": p.name, "ms": p.ms, **p.counters, **p.attrs} for p in PHASES
        ],
        **(extra or {}),
    }

    for p in sorted(PHASES, key=lambda p: -p.ms):
        c = p.counters
        logger.info(
            "PERF phase=%-24s ms=%-9.1f cos_tool=%d/%d(miss/lookup) cos_tool_ms=%.0f "
            "pebble=%d/%.0fms hookcmd=%d/%.0fms juju_log=%d/%.0fms subprocess=%d/%.0fms %s",
            p.name,
            p.ms,
            c["cos_tool_misses"],
            c["cos_tool_lookups"],
            c["cos_tool_ms"],
            c["pebble_calls"],
            c["pebble_ms"],
            c["hookcmd_calls"],
            c["hookcmd_ms"],
            c["juju_log_calls"],
            c["juju_log_ms"],
            c["subprocess_calls"],
            c["subprocess_ms"],
            " ".join(f"{k}={v}" for k, v in p.attrs.items()),
        )

    logger.info(
        "PERF SUMMARY event=%s since_import_ms=%.0f process_age_ms=%s loadavg=%s "
        "reconcile_ms=%s cos_tool_lookups=%d cos_tool_misses=%d cos_tool_ms=%.0f "
        "pebble=%d/%.0fms hookcmd=%d/%.0fms juju_log=%d/%.0fms subprocess=%d/%.0fms "
        "relations=%s staged=%s",
        event,
        since_import_ms,
        payload["process_age_ms"],
        payload["loadavg"],
        payload.get("reconcile_ms", "?"),
        totals["cos_tool_lookups"],
        totals["cos_tool_misses"],
        totals["cos_tool_ms"],
        totals["pebble_calls"],
        totals["pebble_ms"],
        totals["hookcmd_calls"],
        totals["hookcmd_ms"],
        totals["juju_log_calls"],
        totals["juju_log_ms"],
        totals["subprocess_calls"],
        totals["subprocess_ms"],
        json.dumps(relations, sort_keys=True),
        json.dumps(rule_files, sort_keys=True),
    )
    logger.info(
        "PERF SUBPROCESSES %s", json.dumps(dict(COUNTERS.subprocess_by_name), sort_keys=True)
    )

    with contextlib.suppress(Exception):
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        name = f"{time.strftime('%Y%m%dT%H%M%S')}-{event}-{os.getpid()}.json"
        (OUT_DIR / name).write_text(json.dumps(payload, indent=2, sort_keys=True))


@contextlib.contextmanager
def profiled(charm: Any, event: str) -> Iterator[None]:
    """Wrap the whole reconcile: optional cProfile + guaranteed report on the way out."""
    if not ENABLED:
        yield
        return

    profiler = None
    if CPROFILE:
        import cProfile

        profiler = cProfile.Profile()
        profiler.enable()
    t0 = time.monotonic()
    try:
        yield
    finally:
        reconcile_ms = round((time.monotonic() - t0) * 1000, 1)
        if profiler is not None:
            profiler.disable()
            with contextlib.suppress(Exception):
                import pstats

                OUT_DIR.mkdir(parents=True, exist_ok=True)
                stem = f"{time.strftime('%Y%m%dT%H%M%S')}-{event}-{os.getpid()}"
                stats = pstats.Stats(profiler)
                stats.dump_stats(str(OUT_DIR / f"{stem}.prof"))
                # Log only own code, ranked by self time: that is where CPU actually goes.
                import io

                buf = io.StringIO()
                pstats.Stats(profiler, stream=buf).sort_stats("tottime").print_stats(
                    "charm.py|integrations.py|config_manager|config_builder|cosl|charmlibs|lib/charms",
                    25,
                )
                for chunk in buf.getvalue().splitlines():
                    logger.info("PERF CPROFILE %s", chunk)
        report(charm=charm, event=event, extra={"reconcile_ms": reconcile_ms})
