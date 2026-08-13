#!/usr/bin/env bash
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Drive the reconcile performance matrix against a live deployment and collect the
# artifacts produced by src/perf.py.
#
# Topology assumed (see informe-performance-reconcile.md):
#   cos-config-i --prometheus_scrape--> otelcol-i (model: test, lxd)
#   otelcol-i    --otlp-------------->  otelcol-agg (model: agg, k8s)
#
# For each relation count R the script:
#   * relates/unrelates otelcol-i so that exactly R relations exist
#   * waits for the models to settle
#   * runs 1 cold-cache reconcile (cos-tool cache wiped) and N warm ones
# Finally it optionally exercises the two real-world scenarios: adding a relation and
# losing the pod (and with it the cos-tool cache).
#
# Usage:
#   tests/stress/run_matrix.sh --dry-run
#   tests/stress/run_matrix.sh --counts "1 3 5 10" --warm 3
#   tests/stress/run_matrix.sh --collect-only
set -euo pipefail

AGG_MODEL="${AGG_MODEL:-agg}"
AGG_APP="${AGG_APP:-otelcol-agg}"
AGG_UNIT="${AGG_UNIT:-${AGG_APP}/0}"
SRC_MODEL="${SRC_MODEL:-test}"
SRC_APP_PREFIX="${SRC_APP_PREFIX:-otelcol-}"
# Endpoint on the source (VM) side and the offer/endpoint on the aggregator side.
SRC_ENDPOINT="${SRC_ENDPOINT:-send-otlp}"
AGG_ENDPOINT="${AGG_ENDPOINT:-${AGG_MODEL}.${AGG_APP}:receive-otlp}"
COUNTS="${COUNTS:-1 3 5 10}"
WARM_RUNS="${WARM_RUNS:-3}"
CACHE_DIR="${CACHE_DIR:-/tmp/cosl-cos-tool}"
PERF_DIR="${PERF_DIR:-/tmp/otelcol-perf}"
OUT_DIR="${OUT_DIR:-./perf-data}"
SETTLE_TIMEOUT="${SETTLE_TIMEOUT:-2400}"
DRY_RUN=0
COLLECT_ONLY=0
SKIP_SCENARIOS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --counts) COUNTS="$2"; shift 2 ;;
    --warm) WARM_RUNS="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --collect-only) COLLECT_ONLY=1; shift ;;
    --skip-scenarios) SKIP_SCENARIOS=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

run() {
  echo "+ $*" >&2
  [[ $DRY_RUN -eq 1 ]] && return 0
  "$@"
}

log() { echo -e "\n=== $* ===" >&2; }

# ------------------------------------------------------------------ helpers
related_apps() {
  # Names of otelcol-i apps in SRC_MODEL currently related to the aggregator.
  juju status -m "$SRC_MODEL" --format=json 2>/dev/null |
    python3 -c "
import json,sys
data=json.load(sys.stdin)
prefix='${SRC_APP_PREFIX}'
out=[]
for name,app in data.get('applications',{}).items():
    if not name.startswith(prefix):
        continue
    rels=app.get('relations',{}).get('${SRC_ENDPOINT}',[])
    if rels:
        out.append(name)
print(' '.join(sorted(out)))
"
}

all_source_apps() {
  juju status -m "$SRC_MODEL" --format=json 2>/dev/null |
    python3 -c "
import json,sys
data=json.load(sys.stdin)
prefix='${SRC_APP_PREFIX}'
print(' '.join(sorted(n for n in data.get('applications',{}) if n.startswith(prefix))))
"
}

settle() {
  log "waiting for models to settle"
  [[ $DRY_RUN -eq 1 ]] && return 0
  # `juju wait-for` is not available on every client and `bc` may be missing, so poll
  # status and count non-idle units in Python. Two consecutive clean samples are required,
  # otherwise a hook that has not started yet reads as idle.
  local deadline=$((SECONDS + SETTLE_TIMEOUT))
  local clean=0
  while (( SECONDS < deadline )); do
    local busy=0 m n
    for m in "$SRC_MODEL" "$AGG_MODEL"; do
      n=$(juju status -m "$m" --format=json 2>/dev/null | python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    print(99); raise SystemExit
busy=0
for app in data.get('applications',{}).values():
    for u in (app.get('units') or {}).values():
        if u.get('juju-status',{}).get('current') != 'idle':
            busy+=1
        for sub in (u.get('subordinates') or {}).values():
            if sub.get('juju-status',{}).get('current') != 'idle':
                busy+=1
print(busy)
" 2>/dev/null) || n=99
      busy=$((busy + ${n:-99}))
    done
    if (( busy == 0 )); then
      clean=$((clean + 1))
      (( clean >= 2 )) && { echo "settled after ${SECONDS}s" >&2; return 0; }
    else
      clean=0
    fi
    sleep 10
  done
  echo "WARNING: still not idle after ${SETTLE_TIMEOUT}s, continuing" >&2
}

set_relation_count() {
  local target="$1"
  local current_apps all
  current_apps=$(related_apps || true)
  all=$(all_source_apps || true)
  local -a cur=($current_apps) every=($all)
  log "relations: have ${#cur[@]}, want ${target} (available apps: ${#every[@]})"
  if (( ${#every[@]} < target )); then
    echo "ERROR: only ${#every[@]} ${SRC_APP_PREFIX}* apps deployed, need ${target}" >&2
    exit 1
  fi
  # Remove extras.
  for ((i = target; i < ${#cur[@]}; i++)); do
    run juju remove-relation -m "$SRC_MODEL" "${cur[$i]}:${SRC_ENDPOINT}" "$AGG_ENDPOINT"
  done
  # Add missing, picking apps that are not related yet.
  local have=${#cur[@]}
  for app in "${every[@]}"; do
    (( have >= target )) && break
    if [[ " $current_apps " != *" $app "* ]]; then
      run juju add-relation -m "$SRC_MODEL" "${app}:${SRC_ENDPOINT}" "$AGG_ENDPOINT"
      have=$((have + 1))
    fi
  done
  settle
}

count_artifacts() {
  [[ $DRY_RUN -eq 1 ]] && { echo 0; return 0; }
  juju ssh -m "$AGG_MODEL" --container charm "$AGG_UNIT" \
    "ls -1 ${PERF_DIR}/*.json 2>/dev/null | wc -l" 2>/dev/null | tr -d '\r' | tail -1
}

fire() {
  local label="$1"
  echo "--- run: $label" >&2
  local before after
  before=$(count_artifacts)
  # `jhack fire` exits 120 when stdout is not a TTY even though it does fire the event,
  # so its exit code is ignored and progress is verified by the artifact count instead.
  run jhack fire "$AGG_UNIT" update-status -m "$AGG_MODEL" || true
  # Give the hook time to finish before the next one; Juju serialises hooks per unit.
  settle
  after=$(count_artifacts)
  if [[ "${after:-0}" == "${before:-0}" ]]; then
    echo "WARNING: no new perf artifact for '$label' (before=$before after=$after)" >&2
  else
    echo "    artifact ok ($before -> $after)" >&2
  fi
}

wipe_cache() {
  log "wiping cos-tool cache (cold run)"
  run juju ssh -m "$AGG_MODEL" --container charm "$AGG_UNIT" rm -rf "$CACHE_DIR"
}

collect() {
  log "collecting artifacts into $OUT_DIR"
  mkdir -p "$OUT_DIR"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "+ juju ssh ... tar cf - -C /tmp otelcol-perf | tar xf - -C $OUT_DIR" >&2
    return 0
  fi
  # `-C <dir> <operando>`: el directorio de trabajo y qué empaquetar son dos argumentos
  # distintos. `2>/dev/null` evita que los mensajes de juju contaminen el stream de tar.
  juju ssh -m "$AGG_MODEL" --container charm "$AGG_UNIT" \
    "tar cf - -C $(dirname "$PERF_DIR") $(basename "$PERF_DIR")" 2>/dev/null |
    tar xf - -C "$OUT_DIR"
  local n
  n=$(find "$OUT_DIR" -name '*.json' | wc -l)
  echo "artifacts recolectados: $n" >&2
  if [[ "$n" == "0" ]]; then
    echo "ERROR: no se recolectó ningún artifact; revisar $PERF_DIR en la unidad" >&2
    return 1
  fi
}

# ------------------------------------------------------------------ main
if [[ $COLLECT_ONLY -eq 1 ]]; then
  collect
  exit 0
fi

log "matrix: counts=[$COUNTS] warm_runs=$WARM_RUNS unit=$AGG_UNIT"
echo "reminder: set 'update-status-hook-interval=60m' on both models first" >&2

for r in $COUNTS; do
  set_relation_count "$r"
  wipe_cache
  fire "R=${r} cold"
  for ((w = 1; w <= WARM_RUNS; w++)); do
    fire "R=${r} warm#${w}"
  done
done

if [[ $SKIP_SCENARIOS -eq 0 ]]; then
  log "scenario: add one relation on top of the current count (the 30-minute case)"
  current=$(related_apps || true)
  read -r -a cur <<<"$current"
  set_relation_count $(( ${#cur[@]} + 1 ))

  log "scenario: pod recreation (loses the cos-tool cache in /tmp)"
  run juju ssh -m "$AGG_MODEL" --container charm "$AGG_UNIT" ls "$PERF_DIR" >/dev/null || true
  echo "NOTE: recreate the pod manually if desired:" >&2
  echo "  kubectl -n $AGG_MODEL delete pod ${AGG_APP}-0" >&2
fi

collect
log "now build the report"
echo "python tests/stress/perf_report.py $OUT_DIR --slope --to 300 --md informe-cuellos-de-botella.md" >&2
