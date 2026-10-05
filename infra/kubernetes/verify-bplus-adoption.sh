#!/usr/bin/env bash
# Architecture B+ release blocker, live: an execution worker dies AFTER it
# launched a run, and the engine's retry ADOPTS that run instead of launching a
# second one (ADR-014 D11, spec section 20).
#
# A real governed run (OpenSRE, which works for minutes) is dispatched by the
# engine. Once its agent Pod is Running, the execution worker's Pod is deleted
# with no grace period -- the process dies holding the Activity, and nothing
# acknowledges it. The Deployment brings up a replacement; the engine times the
# Activity out on its heartbeat and retries it there. Asserted on what exists:
#
#   one_runtime_throughout  never more than one proxy and one agent Pod for the
#                           run, sampled across the whole takeover
#   same_pods               no Pod name ever seen for the run, in any sample
#                           across the takeover, is one that was not there
#                           before the kill -- adopted, never relaunched. (A
#                           single before/after comparison was timing-bound: a
#                           run that finished right after adoption left nothing
#                           to compare.)
#   adopted_same_generation the replacement logged the adoption under the
#                           generation the first worker launched with
#   retried_by_engine       the engine's own history shows attempt >= 2
#   completed               the run finished `done`
#   nothing_left            no Pod of the run remains afterwards
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SYSTEM_NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
RUN_NS="${ANDYUR_KUBERNETES_NAMESPACE:-andyur-runs}"
AGENT="${ANDYUR_ADOPTION_AGENT:-opensre-sre}"
DEMO="${ANDYUR_ADOPTION_DEMO:-demos/opensre}"
INPUT_FILE="${ANDYUR_ADOPTION_INPUT:-alert.json}"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
. "$HERE/lib/gate.sh"

input="$(cat "$ROOT/$DEMO/$INPUT_FILE")"
trigger="$(operator api POST "/agents/$AGENT/trigger" --data "$(python3 -c 'import json,sys; print(json.dumps({"reason": "bplus adoption gate", "input": json.loads(sys.argv[1])}))' "$input")")"
run_id="$(printf '%s' "$trigger" | json_field run_id)"
run_label="$(cd "$ROOT" && .venv/bin/python -c 'import sys; from andyur.daemon.kubernetes_manifests import _digest; print(_digest(sys.argv[1]))' "$run_id")"
echo "run $run_id" >&2

pods() { kubectl get pods -n "$RUN_NS" -l "andyur.run/id=$run_label" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort; }

for _ in $(seq 1 300); do
  running="$(kubectl get pods -n "$RUN_NS" -l "app.kubernetes.io/component=agent,andyur.run/id=$run_label" \
    --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  [ "${running:-0}" -gt 0 ] && break
  sleep 2
done
[ "${running:-0}" -gt 0 ] || { echo "the run's agent Pod never ran" >&2; exit 1; }
before="$(pods)"
victim="$(kubectl get pod -n "$SYSTEM_NS" -l app=andyur-temporal-execution-worker -o jsonpath='{.items[0].metadata.name}')"
generation="$(kubectl logs -n "$SYSTEM_NS" "$victim" -c execution-worker 2>/dev/null \
  | grep -F "run $run_id: launched under generation" | tail -1 | sed -E 's/.*generation (exec-[0-9a-f]+).*/\1/')"
echo "launched by $victim under ${generation:-?}; killing it" >&2
kubectl delete pod -n "$SYSTEM_NS" "$victim" --grace-period=0 --force >/dev/null 2>&1

# Watch the takeover and the rest of the run, sampling the run's Pods.
max_proxies=0; max_agents=0; state=""; deadline=$((SECONDS + 1500))
seen="$before"
while (( SECONDS < deadline )); do
  seen="$(printf '%s\n%s\n' "$seen" "$(pods)" | grep . | sort -u)"
  p="$(kubectl get pods -n "$RUN_NS" -l "andyur.run/id=$run_label,app.kubernetes.io/component=proxy" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  a="$(kubectl get pods -n "$RUN_NS" -l "andyur.run/id=$run_label,app.kubernetes.io/component=agent" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  (( p > max_proxies )) && max_proxies=$p
  (( a > max_agents )) && max_agents=$a
  if [ -z "${after:-}" ]; then
    replacement="$(kubectl get pod -n "$SYSTEM_NS" -l app=andyur-temporal-execution-worker --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [ -n "$replacement" ] && [ "$replacement" != "$victim" ] && \
       kubectl logs -n "$SYSTEM_NS" "$replacement" -c execution-worker 2>/dev/null | grep -qF "run $run_id: adopted under generation"; then
      after=adopted
      adopted_line="$(kubectl logs -n "$SYSTEM_NS" "$replacement" -c execution-worker | grep -F "run $run_id: adopted under generation" | tail -1)"
    fi
  fi
  state="$(operator api GET "/runs/$run_id" 2>/dev/null | json_field state 2>/dev/null || true)"
  case "$state" in done|failed|cancelled) break;; esac
  sleep 3
done
sleep 20
left="$(pods | grep -c . || true)"

attempt="$(kubectl exec -n "$SYSTEM_NS" deploy/andyur-temporal -c temporal -- \
  temporal workflow show --workflow-id "andyur-run-$run_id" --namespace andyur \
  --address 127.0.0.1:7236 --output json 2>/dev/null | python3 -c '
import json, sys
doc = json.loads(sys.stdin.read() or "{}")
events = doc.get("events", doc if isinstance(doc, list) else [])
top = 0
for e in events:
    attrs = e.get("activityTaskStartedEventAttributes") or {}
    top = max(top, int(attrs.get("attempt", 0) or 0))
print(top)')"

VERDICT=PASS
[ "$max_proxies" -le 1 ] && [ "$max_agents" -le 1 ] || VERDICT=FAIL
[ -n "${after:-}" ] && [ "$(printf '%s\n' "$before" | grep . | sort -u)" = "$seen" ] || VERDICT=FAIL
[ -n "$generation" ] && printf '%s' "${adopted_line:-}" | grep -qF "$generation" || VERDICT=FAIL
[ "${attempt:-0}" -ge 2 ] || VERDICT=FAIL
[ "$state" = done ] || VERDICT=FAIL
[ "${left:-1}" -eq 0 ] || VERDICT=FAIL

.venv/bin/python - "$VERDICT" "$run_id" "$max_proxies" "$max_agents" "$before" "$seen" "$generation" "${adopted_line:-}" "${attempt:-0}" "$state" "${left:-1}" "$STARTED" <<'PY'
import hashlib, json, platform, subprocess, sys
from datetime import datetime, timezone
(verdict, run_id, maxp, maxa, before, seen, generation, adopted_line,
 attempt, state, left, started) = sys.argv[1:13]
sources = ("infra/kubernetes/verify-bplus-adoption.sh",
           "andyur/daemon/engine_executor.py", "andyur/daemon/kubernetes_controller.py",
           "andyur/daemon/governed_kubernetes.py", "andyur/daemon/orchestrator.py",
           "andyur/server/coordinator.py", "andyur/orchestration/temporal/execution.py",
           "andyur/orchestration/temporal/workflows.py")
server = subprocess.run(["kubectl", "config", "view", "--minify", "-o",
                         "jsonpath={.clusters[0].cluster.server}"],
                        capture_output=True, text=True).stdout
print(json.dumps({
    "gate": "bplus-adoption-after-worker-death", "verdict": verdict, "run_id": run_id,
    "one_runtime_throughout": int(maxp) <= 1 and int(maxa) <= 1,
    "max_proxy_pods": int(maxp), "max_agent_pods": int(maxa),
    "same_pods": sorted(set(before.split())) == sorted(set(seen.split())),
    "pods_before": sorted(before.split()), "pods_seen": sorted(set(seen.split())),
    "generation": generation, "adopted_same_generation": bool(generation) and generation in adopted_line,
    "activity_attempt": int(attempt), "retried_by_engine": int(attempt) >= 2,
    "run_state": state, "completed": state == "done", "nothing_left": int(left) == 0,
    "platform": platform.platform(), "started_at": started,
    "finished_at": datetime.now(timezone.utc).isoformat(),
    "api_server_sha256": hashlib.sha256(server.encode()).hexdigest(),
    "source_sha256": {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in sources},
}, indent=2, sort_keys=True))
PY
[ "$VERDICT" = PASS ]
