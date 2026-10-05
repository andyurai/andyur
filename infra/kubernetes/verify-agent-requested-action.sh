#!/usr/bin/env bash
# THE AGENT ASKED. Live proof, against the in-cluster control plane, that a
# consequential action was initiated BY A STOCK WORKLOAD through the generic
# tool path -- and not by this gate, and not by any adapter written for the
# workload.
#
# WHAT MAKES THIS DIFFERENT FROM THE `action` LANE. That lane
# (verify-consequential-action.py) drives `andyur.server.actionrequests`
# in-process with a hand-minted grant: it proves the DECISION is sound, and it
# is silent on who asked. The Aug-30 readiness review's finding was exactly
# that gap -- "no live gate shows an agent initiating the request through the
# generic tool path". This gate closes it.
#
# WHY THE ROW ITSELF IS THE PROOF, and not a claim about the gate's own
# restraint. `POST /runs/{id}/actions` REFUSES AN OPERATOR (app.py,
# request_run_action: 403, "a consequential action is requested BY A RUN").
# This gate holds an operator credential and nothing else -- no run token, no
# run SVID -- so it is structurally incapable of writing the row it reads back.
# The row exists because the workload's tool call created it. That is a
# property of the server's authorization, checkable by anyone, rather than a
# promise about what this script did not do.
#
# NO WORKLOAD-SPECIFIC ANYTHING. The workload is stock upstream Goose at its
# pinned digest, handed the platform's own MCP tool service through the generic
# `configuration.files` mechanism every exec/v1 agent has (demos/goose/agent.json,
# unchanged by this gate). `request_rollback` is a tool of the ONE platform tool
# server -- driver.build_platform_server -- which toolservice.build_app serves
# verbatim over streamable HTTP. The in-process path and the stock-workload path
# are the same object, so a tool cannot exist for one and not the other.
#
#   ON OPENSRE. The review named OpenSRE. Unmodified OpenSRE cannot be handed an
#   arbitrary tool: its surface is a fixed registry of named IntegrationSpecs
#   resolved from ~/.opensre and the environment, its only MCP clients are
#   hard-wired to GitHub and X, and `opensre investigate --help` exposes no tool
#   option. Granting it this tool would require either upstream MCP support or
#   the OpenSRE-specific adapter the review forbids. Goose is the stock workload
#   that CAN take a generic tool, so Goose is the one that proves the generic
#   path. This is recorded in the artifact as `workload_substitution` rather
#   than glossed.
#
# THE CLUSTER SIDE IS REAL. A disposable Deployment is created with two
# revisions; the platform patches it back with ITS OWN ServiceAccount under
# rbac-consequential-action.yaml, rendered in an owned unique namespace. The
# assertion is the API server's view of the pod template afterwards, not
# anything Andyur said about itself.
#
# Prints one JSON line on stdout. Writes no artifact on failure.
set -euo pipefail
SYSTEM_NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
RUN_NS="${ANDYUR_KUBERNETES_NAMESPACE:-andyur-runs}"
GATE="agent-requested-action"
# A unique namespace, with the example RBAC rendered for this target only.
TARGET_NS="andyur-action-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
TARGET_UID=""
TARGET_DEPLOY="checkout-service"
# THE WORKLOAD IS DATA, as it is for verify-exec-workload.sh. Goose is the
# default because it was the first stock workload that could take a generic
# tool; verify-hermes-requested-action.sh runs this same gate against Hermes
# Agent. Nothing below branches on which one it is: a second workload that
# needed a different CODE path through this gate would be the adapter the
# header forbids, not a parameter.
AGENT="${ANDYUR_ACTION_AGENT:-goose-agent}"
REGISTRY_AGENT_ID="${ANDYUR_ACTION_REGISTRY_ID:-agt_goose}"
DEMO="${ANDYUR_ACTION_DEMO:-demos/goose}"
INPUT_FILE="${ANDYUR_ACTION_INPUT:-rollback-input.json}"
MODEL="${ANDYUR_ACTION_MODEL:-qwen3-andyur:latest}"
WORKLOAD="${ANDYUR_ACTION_WORKLOAD:-Goose}"
TIMEOUT="${ANDYUR_ACTION_TIMEOUT:-900}"
# alpine/socat is already on this node (the ollama shim runs it), so the
# disposable Deployment needs no pull and the gate does not measure the
# registry. What differs between its two revisions is an env value: the pod
# template IS the thing a rollback restores, and a template difference is
# observable without a second image.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${ANDYUR_PY:-$ROOT/.venv/bin/python}"
fail() { echo "$GATE FAILED: $*" >&2; exit 1; }
[[ -x "$PY" ]] || fail "set ANDYUR_PY to the Python interpreter with gate dependencies installed"
GATE_CONTEXT="rancher-desktop"
[[ "$(kubectl config current-context)" == "$GATE_CONTEXT" ]] || fail "expected the rancher-desktop context"
# Pin every subsequent call, including teardown: another session may switch its
# current context while the workload is running.
kubectl() { command kubectl --context "$GATE_CONTEXT" "$@"; }
FILLER_IMAGE="$(kubectl get deployment andyur-ollama -n "$SYSTEM_NS" \
  -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)"
# PORTABLE mktemp: a TEMPLATE with X's, not `-t PREFIX`. BSD mktemp treats the
# -t argument as a prefix and appends randomness; GNU mktemp treats it as a
# template and REFUSES one with fewer than three X's -- "mktemp: too few X's".
# So `mktemp -t andyur-...` worked on the author's macOS and failed every time
# this gate ran on a Linux CI runner.
WORK_ERR="$(mktemp "${TMPDIR:-/tmp}/andyur-action-err-XXXXXX")"

# This gate never changes shared StatefulSet credentials or shared RBAC. The
# operator must have opted into token mounting before starting it. Teardown
# removes only the unique namespace created here, using the API-server UID
# precondition; wrong context or failed creation therefore deletes nothing.
release_resources() {
  [[ -n "$TARGET_UID" ]] || return 0
  ANDYUR_OTEL=on ANDYUR_GATE_TRACEPARENT="${trace_ctx:-}" \
    ANDYUR_GATE_RUN_ID="${run_id:-}" ANDYUR_GATE_AGENT_ID="$AGENT" \
    "$PY" "$HERE/action_gate_resources.py" "$GATE_CONTEXT" "$TARGET_NS" "$TARGET_UID" || return 1
  TARGET_UID=""
}
cleanup() {
  local rc=$?
  rm -f "$WORK_ERR"
  release_resources || rc=1
  exit $rc
}
trap cleanup EXIT

. "$HERE/lib/gate.sh"
[[ -n "$FILLER_IMAGE" ]] || fail "could not read an image already present on the node from deployment/andyur-ollama; is the control plane up?"
kubectl get statefulset andyur-server -n "$SYSTEM_NS" >/dev/null 2>&1 || fail "no andyur-server StatefulSet in $SYSTEM_NS; bring the in-cluster control plane up first"
[[ "$(kubectl get statefulset andyur-server -n "$SYSTEM_NS" -o jsonpath='{.spec.template.spec.automountServiceAccountToken}')" == true ]] \
  || fail "control plane has not opted into consequential actions. The gate never patches shared credentials. An authorized operator must first enable automountServiceAccountToken on StatefulSet andyur-server in $SYSTEM_NS and wait for its rollout (see rbac-consequential-action.yaml)."
fetch_user_token

# ---------------------------------------------------------------- the target
# Two revisions, so "rolled back" has somewhere to go. revision 1 carries
# REVISION=one and revision 2 carries REVISION=two; a rollback must restore one.
TARGET_UID="$(kubectl create namespace "$TARGET_NS" -o jsonpath='{.metadata.uid}')" \
  || fail "could not create an owned namespace; existing namespaces are never adopted"
[[ -n "$TARGET_UID" ]] || fail "namespace creation returned no UID; refusing unbound cleanup"
render_target() {  # revision label
  cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $TARGET_DEPLOY
  namespace: $TARGET_NS
spec:
  replicas: 1
  revisionHistoryLimit: 5
  selector: {matchLabels: {app: $TARGET_DEPLOY}}
  template:
    metadata: {labels: {app: $TARGET_DEPLOY}}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: $FILLER_IMAGE
          command: ["sleep", "infinity"]
          env: [{name: REVISION, value: "$1"}]
          resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {memory: 64Mi}}
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 65532
            capabilities: {drop: [ALL]}
            seccompProfile: {type: RuntimeDefault}
YAML
}
render_target one | kubectl apply -f - >/dev/null
kubectl -n "$TARGET_NS" rollout status "deployment/$TARGET_DEPLOY" --timeout=180s >/dev/null \
  || fail "the disposable target never became ready on its first revision"
render_target two | kubectl apply -f - >/dev/null
kubectl -n "$TARGET_NS" rollout status "deployment/$TARGET_DEPLOY" --timeout=180s >/dev/null \
  || fail "the disposable target never became ready on its second revision"
revision_env() { kubectl -n "$TARGET_NS" get "deployment/$TARGET_DEPLOY" \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="REVISION")].value}'; }
before="$(revision_env)"
[[ "$before" == "two" ]] || fail "the target should be on revision two before the run; it reads '$before'"
replicasets_before="$(kubectl -n "$TARGET_NS" get replicasets -o name | wc -l | tr -d ' ')"
(( replicasets_before >= 2 )) || fail "the target has $replicasets_before ReplicaSet(s); a rollback needs a history to roll back TO"

# ------------------------------------------------ the platform's own credential
"$PY" - "$ROOT/infra/kubernetes/rbac-consequential-action.yaml" "$TARGET_NS" "$SYSTEM_NS" <<'PY' | kubectl create -f - >/dev/null \
  || fail "could not apply the rollback Role"
# A YAML STREAM, not JSON documents glued together with `---`.
#
# This printed json.dumps(item) followed by a literal "---" per document. kubectl
# sniffs the first character, sees `{`, decodes the whole stream as JSON and then
# fails on the separator: "invalid character '-' in numeric literal". It happened
# to work with the kubectl of the day and broke with a stricter one, which is the
# signature of input that was ambiguous all along -- a JSON document is valid
# YAML, so emitting YAML is unambiguous for both parsers.
import sys, yaml
items = []
for item in yaml.safe_load_all(open(sys.argv[1])):
    item["metadata"]["namespace"] = sys.argv[2]
    for subject in item.get("subjects", []):
        subject["namespace"] = sys.argv[3]
    items.append(item)
yaml.safe_dump_all(items, sys.stdout)
PY
fetch_user_token
for i in $(seq 1 30); do
  operator api GET /agents >/dev/null 2>&1 && break
  sleep 3
done

# ------------------------------------------------- the run namespace is proved
# A RUN CANNOT LAUNCH WITHOUT A FRESH CONTAINMENT STAMP, and applying the
# manifests deliberately resets it -- so a gate run straight after a deploy
# triggers into a worker that refuses, and the run fails with
# `namespace 'andyur-runs' lacks a fresh, namespace-bound active NetworkPolicy
# verification`. True, and about the deploy that had just happened rather than
# about anything this gate is measuring.
#
# Waited for here rather than assumed: the reconciler re-proves containment on
# its own cycle, and this gate's job starts after that.
stamp_deadline=$((SECONDS + ${ANDYUR_ACTION_STAMP_WAIT:-420}))
while (( SECONDS < stamp_deadline )); do
  [[ "$(kubectl get namespace "$RUN_NS" -o jsonpath='{.metadata.labels.andyur\.network-policy/verified}' 2>/dev/null)" == "true" ]] && break
  sleep 10
done
[[ "$(kubectl get namespace "$RUN_NS" -o jsonpath='{.metadata.labels.andyur\.network-policy/verified}' 2>/dev/null)" == "true" ]] \
  || fail "namespace $RUN_NS is still not marked containment-verified, so no run
can launch. Either andyur-netpol-reconciler is not running, or it withdrew the
stamp -- its log names which check failed, and that would be a containment
problem in this cluster rather than anything this gate is about."

# ------------------------------------------------------------------- the run
agents_json="$(operator api GET /agents 2>"$WORK_ERR")"
[[ -n "$agents_json" ]] || fail "GET /agents returned nothing after the rollout. stderr: $(tail -3 "$WORK_ERR" | tr '\n' ' ')"
if ! printf '%s' "$agents_json" | python3 -c 'import json,sys; sys.exit(0 if any(a.get("name")==sys.argv[1] for a in json.load(sys.stdin)) else 1)' "$AGENT" 2>/dev/null; then
  operator api POST /agents --data "$(python3 -c 'import json,sys; print(json.dumps({"name": sys.argv[1], "registry_agent_id": sys.argv[2], "description": sys.argv[3] + " (exec/v1) from the governed snapshot"}))' "$AGENT" "$REGISTRY_AGENT_ID" "$WORKLOAD")" >/dev/null
fi
# THE AGENT MUST BE IDLE, and if it is not, say WHICH run is holding it.
#
# `POST /trigger` answers 409 "agent is not idle, or a conversation cap was hit"
# -- one message for two quite different situations, and the gate echoed it
# three times over three different underlying causes. Every time, the real
# state was a run stuck in `pending` from an EARLIER attempt that could never be
# assigned (an unreachable catalog, once), which pins its agent indefinitely:
# there is no operator endpoint that cancels a run that never started.
#
# So the gate names it. It does NOT clear it: a gate that deletes the state
# standing in its way is a gate that can no longer fail for that reason.
runs_json="$(operator api GET "/agents/$AGENT/runs" 2>/dev/null || true)"
blocking="$(printf '%s' "$runs_json" | python3 -c '
import json, sys
try:
    runs = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
runs = runs if isinstance(runs, list) else runs.get("runs", [])
stuck = [r for r in runs if r.get("state") in ("pending", "running")]
print(" ".join(f"{r[\"id\"]}({r[\"state\"]})" for r in stuck))
' 2>/dev/null || true)"
[[ -z "$blocking" ]] || fail "agent '$AGENT' is not idle: $blocking.
A run that never started pins its agent and there is no endpoint that cancels
one, so this has to be cleared before the gate can trigger. That is a platform
gap, recorded here rather than worked around."

# THE SCOPE AND THE PIN ARE ASSERTED HERE, by the operator, at the one endpoint
# `auth.require` refuses a run token at. They are sealed into the run before it
# exists and travel in its signed grant. The agent reads its target from a
# prompt; the platform reads it from the grant; only the second decides. Note
# that the input below NAMES the same target, so the run is not a test of
# whether the model can guess -- it is a test of who is obeyed when it asks.
# WHETHER A MODEL CALLS A TOOL IS THE MODEL'S DECISION, and this gate is not a
# claim about that. It is a claim about the PLATFORM: that when a stock workload
# does call the tool, the request reaches the control plane through the generic
# path, is decided from authority the agent cannot influence, and moves the
# cluster. So a run in which the model simply did not call the tool is not a
# platform failure and must not be recorded as one -- it is retried, a bounded
# number of times, and the count goes IN THE ARTIFACT.
#
# Bounded, and small. "Retry until it works" would turn a genuine regression --
# the tool missing from the served registry, the bearer refused, the endpoint
# 403ing the run -- into a slow green, because those failures also produce no
# row. Two attempts distinguish "the model did not ask" from "the model could
# not"; a third would only be patience.
ATTEMPTS_ALLOWED="${ANDYUR_ACTION_ATTEMPTS:-2}"
started=$(date +%s)
attempt=0; run_id=""; body=""; state=""; summary=""; error=""; actions_json=""
while (( attempt < ATTEMPTS_ALLOWED )); do
  attempt=$((attempt + 1))
  trigger="$(operator api POST "/agents/$AGENT/trigger" --data "$(
    python3 - "$ROOT/$DEMO/$INPUT_FILE" "$TARGET_NS" "$TARGET_DEPLOY" "$attempt" <<'PY'
import json, sys
raw = json.load(open(sys.argv[1]))
raw["target"] = {"namespace": sys.argv[2], "deployment": sys.argv[3]}
print(json.dumps({
    "reason": f"agent-requested consequential action gate (attempt {sys.argv[4]})",
    # WHAT THE RUN IS GRANTED, and it is not only the rollback.
    #
    # A run's scope is its WHOLE authority, not an addition to some default. The
    # first version granted `deployments:rollback` alone, and the run died
    # before it started: `GET /agents/{name}/context` requires `files:read`
    # (U2), so a run that may roll a deployment back and nothing else cannot
    # read its own instructions. That is the narrowing working exactly as
    # designed, and the gate asking for the wrong thing.
    #
    # `files:read` is what the runner needs to load the agent's mind. It is not
    # widened beyond that: no `files:write`, because this run is asked to read
    # an incident and make one request, and a grant that covers what the work
    # does not need is not a grant this gate should be modelling.
    "scope": ["files:read", "deployments:rollback"],
    "subject_context": {"namespace": sys.argv[2], "deployment": sys.argv[3]},
    "input": raw,
}))
PY
  )")"
  run_id="$(printf '%s' "$trigger" | json_field run_id)" || fail "the trigger did not answer with a run: $trigger"
  [[ -n "$run_id" ]] || fail "could not read the run id: $trigger"
  deadline=$((SECONDS + TIMEOUT))
  while (( SECONDS < deadline )); do
    body="$(operator api GET "/runs/$run_id" 2>/dev/null || true)"
    state="$(printf '%s' "$body" | json_field state 2>/dev/null || true)"
    case "$state" in done|failed|cancelled) break;; esac
    sleep 3
  done
  summary="$(printf '%s' "$body" | json_field summary)" || fail "could not read the run's summary"
  error="$(printf '%s' "$body" | json_field error)" || fail "could not read the run's error field"
  # ----------------------------------------------------------- what was asked
  # READ, never written: this is the operator-visible listing (owner-gated). The
  # WRITE side of this resource refuses an operator outright, which is why a row
  # here can only have come from the run.
  actions_json="$(operator api GET "/runs/$run_id/actions" 2>"$WORK_ERR")"
  [[ -n "$actions_json" ]] || fail "GET /runs/$run_id/actions returned nothing. stderr: $(tail -3 "$WORK_ERR" | tr '\n' ' ')"
  if printf '%s' "$actions_json" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin) else 1)' 2>/dev/null; then
    break
  fi
  # RETRY ONLY WHAT RETRYING IS FOR. The second attempt exists because whether a
  # model calls a tool is the model's decision -- it is not a way to have
  # another go at a run that never STARTED. A run still `pending` after the
  # timeout is a platform failure, and re-triggering it produced a 409 ("agent
  # is not idle") that named the retry rather than the stall: the gate reported
  # a busy agent when what had happened was that no run was ever assigned.
  # ONLY a clean finish is "the model chose not to ask". A run that FAILED did
  # not decline the tool -- something broke -- and retrying it hides which.
  case "$state" in
    done) ;;
    failed|cancelled) fail "run $run_id ended '$state' -- the run broke, so
nothing can be concluded about whether an agent would have asked. The run's
error was: $(printf '%s' "$error" | head -c 400)" ;;
    *) fail "run $run_id never left '$state' after ${TIMEOUT}s -- nothing was
asked because nothing ran. This is not the model declining to call the tool.
Look at the worker's assignment log and the server's registry resolution; the
governed catalog must be pullable for a Kubernetes run to be assigned at all." ;;
  esac
  echo "NOTE: attempt $attempt reached '$state' without asking (the model did not call the tool)" >&2
done
finished=$(date +%s)

# The consequence is asynchronous even after the row says allowed: the patch
# returns before the API server has settled the new ReplicaSet. Read the
# template back until it moves or the window closes -- the same discipline
# andyur/rollback.py applies, and for the same reason.
after="$before"
for i in $(seq 1 40); do
  after="$(revision_env)"
  [[ "$after" != "$before" ]] && break
  sleep 3
done

EXPECTED_SPANS="run $AGENT,server.start_run,runner.serve,execfront POST,action.decide,mcp.tool request_rollback"
trace_ctx="$(printf '%s' "$body" | json_field trace_ctx)" || fail "could not read the run's trace context"
if [[ -n "$trace_ctx" ]]; then
  trace="$(kubectl exec -i -n "$SYSTEM_NS" deployment/andyur-operator -- python - "http://andyur-jaeger:16686" "$trace_ctx" --wait 120 --expect "$EXPECTED_SPANS" \
             < "$ROOT/infra/observability/trace_readback.py" 2>/dev/null | tail -1 || true)"
else
  trace='{"error": "no_trace_ctx_on_run_record"}'
fi

# Teardown is part of the gate, not a best-effort action after publishing PASS.
# Its kubernetes.cleanup span joins the stored run trace. The operator's first
# signals for a leak/refusal are action_gate.cleanup.decided (closed reason) and
# andyur.dependency.{calls,failures,duration} with operation=cleanup.
release_resources || fail "owned namespace cleanup failed; no evidence written"
EVIDENCE="${ANDYUR_ACTION_EVIDENCE:-$HERE/result-agent-requested-action-$(date +%Y-%m-%d)-$(uname -s | tr A-Z a-z)-$(uname -m).json}"
python3 - "$ROOT" "$GATE" "$run_id" "$state" "$summary" "$error" "$actions_json" \
         "$TARGET_NS" "$TARGET_DEPLOY" "$before" "$after" "$trace" "$started" "$finished" \
         "$EVIDENCE" "$attempt" "$ATTEMPTS_ALLOWED" "$DEMO" "$INPUT_FILE" "$WORKLOAD" <<'PY'
import hashlib, json, pathlib, platform, sys
(root, gate, run_id, state, summary, error, actions_raw, ns, deploy,
 before, after, trace, started, finished, evidence, attempts, attempts_allowed,
 demo, input_file, workload) = sys.argv[1:]
ROOT = pathlib.Path(root)
try:
    trace = json.loads(trace or "{}")
except ValueError:
    trace = {"error": "readback_failed", "raw": trace[-300:]}
spans = trace.get("spans", [])
rows = json.loads(actions_raw)
if isinstance(rows, dict):
    rows = rows.get("actions", rows.get("items", []))

# AT LEAST ONE request, for THIS tool, and EVERY one of them on the pin.
#
# Not "exactly one". The gate's input asks once and says so twice, but how many
# times a model calls a tool is the model's decision, and failing the PLATFORM's
# claim because a model was chatty would be reporting the wrong thing. What
# must hold regardless of how many times it asked is that every request landed
# on the target the run was PINNED to -- which is the actual property: the agent
# reads its target from a prompt, the platform reads it from the signed grant,
# and only the second decides.
#
# The decision, the reason and the result are read from the FIRST row, the one
# that moved the cluster. Every row is in the artifact.
target = f"{ns}/{deploy}"
mine = [r for r in rows if r.get("tool") == "rollback_deployment"]
one = mine[0] if mine else None

# The agent's own call, seen at the MCP boundary in the run's trace. The row
# proves the platform recorded a request from the run; THIS proves the request
# entered through the generic tool service the stock workload speaks to, rather
# than through some other in-process caller.
tool_spans = sorted({s["name"] for s in spans if s.get("name", "").startswith("mcp.tool ")})
mcp_initiated = "mcp.tool request_rollback" in tool_spans
decided_spans = [s for s in spans if s.get("name") == "action.decide"]

checks = {
    # the row exists at all -- and could not have been written by this gate
    "row_recorded": one is not None,
    "every_row_targets_the_pin": bool(mine) and all(r.get("target") == target for r in mine),
    "decision_allowed": bool(one) and one.get("decision") == "allowed",
    "reason_write_authorized": bool(one) and one.get("decision_reason") == "write_authorized",
    "result_succeeded": bool(one) and one.get("result") == "succeeded",
    # the API server's own view, before and after
    "cluster_moved": before == "two" and after == "one",
    # who asked, seen at the tool boundary
    "agent_initiated_over_mcp": mcp_initiated,
    "decision_is_a_span": bool(decided_spans),
    "run_completed": state == "done",
    "trace_expected_present": trace.get("expected_present") is True,
}
sources = ["infra/kubernetes/verify-agent-requested-action.sh",
           "infra/kubernetes/action_gate_resources.py",
           "infra/kubernetes/lib/gate.sh",
           "infra/kubernetes/rbac-consequential-action.yaml",
           "infra/kubernetes/control-plane.yaml",
           f"{demo}/agent.json", f"{demo}/{input_file}",
           "andyur/actions.py", "andyur/rollback.py",
           "andyur/server/actionrequests.py",
           "andyur/server/kubernetes_deployments.py",
           "andyur/runner/driver.py", "andyur/runner/toolservice.py",
           "infra/observability/trace_readback.py"]
ok = all(checks.values())
image_ref = json.loads((ROOT / demo / "agent.json").read_text())["runtime"]["image"]["ref"]
document = {
    "gate": gate,
    "claim": "a stock workload, through the generic MCP tool path, initiated a "
             "consequential action that the platform decided and performed",
    "workload": {"name": workload,
                 "image": f"{image_ref} (pinned digest, {demo}/agent.json)",
                 "modified": False, "adapter_added": False},
    "workload_substitution": {
        "review_named": "OpenSRE",
        "used": workload,
        "why": "unmodified OpenSRE has a fixed IntegrationSpec registry and only "
               "GitHub/X-specific MCP clients; it cannot be handed an arbitrary "
               "platform tool without upstream support or the workload-specific "
               f"adapter this work forbids. {workload} takes a generic streamable-http "
               "MCP server through exec/v1 configuration.files, unchanged."},
    "why_the_gate_could_not_have_asked":
        "POST /runs/{id}/actions refuses an operator with 403; this gate holds "
        "only an operator credential, so the row it reads back can only have "
        "been created by the run.",
    "run_id": run_id, "state": state, "error": error or None,
    # WHICH ATTEMPT ASKED. Whether a model calls a tool is the model's decision,
    # so a run that simply did not ask is retried; the count is here rather than
    # hidden, because "it worked on the second try" is a different sentence from
    # "it worked", and only one of them is what a reader would assume.
    "attempts": int(attempts), "attempts_allowed": int(attempts_allowed),
    "summary_excerpt": summary[:400],
    "target": target,
    "pod_template_revision": {"before": before, "after": after},
    "action_rows": rows,
    "tool_calls_observed": tool_spans,
    "checks": checks,
    "trace": trace,
    "elapsed_seconds": int(finished) - int(started),
    "not_covered": "the approval-gated outcome and the denial outcome against a "
                   "real cluster; those are the `action` lane, which drives the "
                   "decision module directly with hand-minted grants.",
    "host": platform.platform(),
    "source_sha256": {s: hashlib.sha256((ROOT / s).read_bytes()).hexdigest() for s in sources},
    "started_at_epoch": int(started), "finished_at_epoch": int(finished),
    "ok": ok}
print(json.dumps(document, sort_keys=True))
# A FAILED RUN IS NEVER RECORDED. The artifact is the claim; writing one for a
# run whose checks did not all hold would put a false claim in the tree, and
# evidence_currency would then report it as current.
if ok:
    pathlib.Path(evidence + ".tmp").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    pathlib.Path(evidence + ".tmp").replace(evidence)
    sys.stderr.write(f"evidence {evidence}\n")
if not ok:
    sys.stderr.write("FAILED checks: " + ", ".join(k for k, v in checks.items() if not v) + "\n")
sys.exit(0 if ok else 1)
PY
