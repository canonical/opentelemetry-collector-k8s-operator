"""Benchmark a full otelcol-k8s reconcile with N receive-otlp + N dashboard relations.

Run from the charm repo root:
    /tmp/opencode/venv/bin/python /tmp/opencode/bench_reconcile.py <n_relations> <cold|warm>
"""

import collections
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from shutil import copytree
from unittest.mock import MagicMock, patch

CHARM_ROOT = Path("/home/ubuntu/repos/opentelemetry-collector-k8s-operator")
sys.path.insert(0, str(CHARM_ROOT))
sys.path.insert(0, str(CHARM_ROOT / "src"))
sys.path.insert(0, str(CHARM_ROOT / "lib"))

from cosl.utils import LZMABase64  # noqa: E402
from ops import ActiveStatus  # noqa: E402
from ops.testing import Container, Context, Exec, Model, PeerRelation, Relation, State  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 10
MODE = sys.argv[2] if len(sys.argv) > 2 else "cold"
RULES_PER_APP = 10
DASHBOARDS_PER_APP = 2

DASHBOARD = json.loads((CHARM_ROOT / "src/grafana_dashboards/overview-dashboard.json").read_text())

# ---------------------------------------------------------------- instrumentation
calls = collections.Counter()
elapsed = collections.defaultdict(float)
_real_run = subprocess.run


INTEREST = {
    "stage_received_otlp_rules", "send_otlp", "receive_loki_logs", "scrape_metrics",
    "send_remote_write", "send_loki_logs", "forward_dashboards", "cloud_integrator",
    "_upset_dashboards_on_relation", "load_dashboards_from_dir", "receive_otlp",
}


def _origin() -> str:
    import inspect
    names = [f.function for f in inspect.stack()[2:]]
    hits = [n for n in names if n in INTEREST]
    return hits[0] if hits else "?"


def counting_run(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args")
    key = "other"
    if isinstance(cmd, (list, tuple)) and cmd:
        key = Path(str(cmd[0])).name
        if "cos-tool" in key:
            key = f"cos-tool:{cmd[cmd.index('--format') + 1] if '--format' in cmd else '?'}:" + (
                "validate" if "validate" in cmd else "transform" if "transform" in cmd else "?"
            )
    key = f"{_origin():32s} {key}"
    t = time.perf_counter()
    try:
        return _real_run(*args, **kwargs)
    finally:
        calls[key] += 1
        elapsed[key] += time.perf_counter() - t


subprocess.run = counting_run


# ---------------------------------------------------------------- fixtures
def promql_rules(i: int) -> dict:
    return {
        "groups": [
            {
                "name": f"zoo_group_{i}",
                "rules": [
                    {
                        "alert": f"ZooAlert{j}",
                        "expr": f'rate(zk_requests_total{{quantile="0.99"}}[5m]) > {j}',
                        "for": "5m",
                        "labels": {"severity": "critical"},
                        "annotations": {"summary": "zk slow"},
                    }
                    for j in range(RULES_PER_APP)
                ],
            }
        ]
    }


def logql_rules(i: int) -> dict:
    return {
        "groups": [
            {
                "name": f"zoo_logs_{i}",
                "rules": [
                    {
                        "alert": f"ZooLogAlert{j}",
                        "expr": 'count_over_time({job=~".+"} |= "ERROR" [5m]) > 10',
                        "labels": {"severity": "warning"},
                    }
                    for j in range(2)
                ],
            }
        ]
    }


def otlp_relation(i: int) -> Relation:
    rules = {"promql": promql_rules(i), "logql": logql_rules(i)}
    metadata = {
        "model": f"test-{i}",
        "model_uuid": f"00000000-0000-4000-8000-{i:012d}",
        "application": "otelcol",
        "unit": "otelcol/0",
        "charm_name": "opentelemetry-collector",
    }
    return Relation(
        "receive-otlp",
        remote_app_name=f"otelcol-{i}",
        remote_app_data={
            "rules": json.dumps(LZMABase64.compress(json.dumps(rules))),
            "metadata": json.dumps(metadata),
        },
    )


def dashboard_relation(i: int, unique_titles: bool = True) -> Relation:
    templates = {}
    for d in range(DASHBOARDS_PER_APP):
        title = f"zookeeper-{i}-{d}" if unique_titles else f"zookeeper-{d}"
        templates[title] = {
            "charm": "zookeeper",
            "content": LZMABase64.compress(json.dumps(DASHBOARD)),
            "juju_topology": {
                "model": f"test-{i}",
                "model_uuid": f"00000000-0000-4000-8000-{i:012d}",
                "application": "zookeeper",
                "unit": "zookeeper/0",
            },
        }
    return Relation(
        "grafana-dashboards-consumer",
        remote_app_name=f"zoo-otelcol-{i}",
        remote_app_data={"dashboards": json.dumps({"templates": templates})},
    )


def main():
    from src.charm import OpenTelemetryCollectorK8sCharm

    tmp = Path(f"/tmp/opencode/bench-root-{N}")
    shutil.rmtree(tmp, ignore_errors=True)
    for src_dir in ["grafana_dashboards", "loki_alert_rules", "prometheus_alert_rules"]:
        copytree(CHARM_ROOT / "src" / src_dir, tmp / "src" / src_dir, dirs_exist_ok=True)

    import cosl.cos_tool as _ct
    cache_dir = f"/tmp/opencode/cache-N{N}"
    if MODE == "cold":
        shutil.rmtree(cache_dir, ignore_errors=True)
    _ct.configure_cache(cache_dir)

    ctx = Context(OpenTelemetryCollectorK8sCharm, charm_root=tmp)
    container = Container(
        name="otelcol",
        can_connect=True,
        execs={
            Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout=""),
            Exec(["/usr/bin/otelcol", "--version"], return_code=0, stdout="otelcol version 0.0.0"),
        },
    )
    relations = [otlp_relation(i) for i in range(N)]
    relations += [dashboard_relation(i, unique_titles=os.environ.get("UNIQUE", "1") == "1") for i in range(N)]
    relations += [
        Relation("send-otlp", remote_app_data={"endpoints": json.dumps([
            {"protocol": "grpc", "endpoint": "cos-otelcol:4317",
             "telemetries": ["logs", "metrics", "traces"], "insecure": True}])}),
        Relation("grafana-dashboards-provider"),
    ]
    if os.environ.get("RW"):
        relations += [
            Relation("send-remote-write", remote_app_data={}, remote_units_data={0: {"remote_write": json.dumps({"url": "http://prom:9090/api/v1/write"})}}),
            Relation("send-loki-logs", remote_units_data={0: {"endpoint": json.dumps({"url": "http://loki:3100/loki/api/v1/push"})}}),
        ]
    relations += [
        PeerRelation("peers"),
    ]
    state = State(
        leader=True,
        containers=[container],
        relations=relations,
        model=Model("agg", uuid="11111111-0000-4000-8000-000000000000"),
    )

    with patch.multiple(
        "charms.observability_libs.v0.kubernetes_compute_resources_patch.KubernetesComputeResourcesPatch",
        _namespace="test-namespace",
        _patch=lambda *a, **kw: True,
        is_ready=lambda *a, **kw: True,
        get_status=lambda _: ActiveStatus(),
    ), patch("lightkube.core.client.GenericSyncClient", new=MagicMock()):
        prof = None
        if os.environ.get("PROFILE"):
            import cProfile
            prof = cProfile.Profile()
            prof.enable()
        t0 = time.perf_counter()
        ctx.run(ctx.on.update_status(), state)
        total = time.perf_counter() - t0
        if prof:
            import pstats
            prof.disable()
            pstats.Stats(prof).sort_stats("cumulative").print_stats(35)

    print(f"\n=== N={N} relations ({N} receive-otlp + {N} dashboards), mode={MODE} ===")
    print(f"total reconcile: {total:.2f}s")
    subs = sum(elapsed.values())
    print(f"subprocess total: {subs:.2f}s in {sum(calls.values())} calls "
          f"({subs / total * 100:.0f}% of reconcile)")
    for k, v in sorted(calls.items(), key=lambda kv: -elapsed[kv[0]]):
        print(f"  {k:35s} calls={v:6d}  time={elapsed[k]:7.2f}s")


if __name__ == "__main__":
    main()
