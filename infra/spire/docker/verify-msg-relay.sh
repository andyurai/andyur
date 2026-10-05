#!/usr/bin/env bash
# MULTI-TURN AGENT-TO-AGENT MESSAGE RELAY on the container-attested SPIRE stack.
#
# Two agents resolve one incident by messaging each other, and every "turn" is a
# separate attested run:
#
#   turn 1  sre-oncall is paged, triages with obs/tickets, finds a capacity
#           cause it is NOT entitled to fix, and assigns a remediation task
#           to `capacity`
#   turn 2  the task wakes `capacity` as a NEW run (own SVID, own ceiling,
#           inherited pin and -- U4 -- inherited user); it applies a bounded
#           scale, closes the task with the result, and assigns a verify-task
#           back
#   turn 3  that task wakes sre-oncall again (another new run); it re-checks
#           the metric and comments the outcome on the ticket
#
# The relay rides on TASKS, not messages: tasks are the delegation channel that
# carries the user across the hop, and a run without a user cannot mint any
# resource token. See ROADMAP.md.
#
# What is gated: the wake chain itself (one workflow, increasing depth, the
# incident pin inherited unchanged), one distinct per-run SVID per turn, both
# agents' refusals frozen with live credentials (each with a positive control),
# the bounded scale actually happening, and no credential material in the
# retained artifacts. The turn cap is enforced twice: the server refuses work
# past ANDYUR_MAX_WORKFLOW_RUNS=10, and this harness stops launching and halts
# the workflow at the same number, because a bound only the bounded process
# enforces is not a bound.
#
# This harness plays the WORKER itself (heartbeat -> assignment -> register the
# per-run SPIRE entry -> launch the runner container), which is what lets it
# hold each run's token long enough to freeze that run's refusals while the run
# is live -- a token cannot be minted for a finished run.
#
# DEMO HARNESS, NOT A CI GATE: unlike verify-sre-registry.sh it does not carry
# stale-lock recovery or ownership-fingerprint process reclamation; it refuses
# to start beside a live instance of itself and cleans up only what it created.
# The shared SPIRE stack must already be up (`./run.sh spire-docker up`).
#
# Usage: ./run.sh msg-demo    (or run this file directly)
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NET="andyur-spire-net"
SOCK="andyur-spire-sockets"
TD="andyur.local"
WORK="$(mktemp -d)"
TAG="$(basename "$WORK" | tr -cd '[:alnum:]' | tail -c 10)"
SERVER="andyur-msg-server-$TAG"
SERVER_ROLE="msg-server-$TAG"
OPERATOR_ROLE="msg-operator-$TAG"
WORKER_ROLE="msg-worker-$TAG"
BASE="http://127.0.0.1:18689"
RUN_SECRET="$(openssl rand -hex 32)"
ONCALL="sre-oncall"
CAPACITY="capacity"
MAX_TURNS=10
# one relay turn = a full local-30B reasoning pass; 900s measured too short
RUN_TTL="${ANDYUR_RUN_TTL_SECONDS:-1800}"
ARTIFACT_ROOT="${ANDYUR_MSG_ARTIFACT_DIR:-$HERE/data/msg-relay-demo}"
ARTIFACT_KEEP="${ANDYUR_MSG_ARTIFACT_KEEP:-10}"
ARTIFACT_DIR=""
PASS=0
FAIL=0
EXPECTED_PASS=25
WF_ID=""

if [ "${ANDYUR_LLM:-ollama}" != ollama ]; then
  echo "the relay demo runs on local Ollama only (ANDYUR_LLM=ollama); the" >&2
  echo "api/LiteLLM path is exercised by ./run.sh sre-demo" >&2
  exit 1
fi

say() { printf '\n== %s ==\n' "$*"; }
ok() { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
entry() {
  local sid="$1" out; shift
  out="$(docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
    -parentID "spiffe://$TD/agent/node" -spiffeID "$sid" -jwtSVIDTTL 1200 \
    -entryExpiry "$(( $(date +%s) + 3600 ))" \
    "$@" 2>&1)" || {
      printf '%s' "$out" | grep -q 'AlreadyExists' || { echo "$out" >&2; return 1; }
    }
}

operator_api() {
  local method="$1" path="$2" data="${3:-}"
  docker run --rm --network "$NET" --label "andyur.role=$OPERATOR_ROLE" \
    -v "$SOCK:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_SERVER_URL="http://$SERVER:8642" \
    ${data:+-e ANDYUR_API_DATA="$data"} \
    --entrypoint python andyur-runner -c '
import os,sys,httpx
from andyur import identity
method,path=sys.argv[1:3]
kw={"headers":identity.auth_header(),"timeout":20}
if "ANDYUR_API_DATA" in os.environ: kw["content"]=os.environ["ANDYUR_API_DATA"]
r=httpx.request(method, os.environ["ANDYUR_SERVER_URL"]+path,
                headers={**kw.pop("headers"),"content-type":"application/json"}, **kw)
print(r.text)
raise SystemExit(0 if r.is_success else 1)
' "$method" "$path"
}

# The retained bundle must hold the story and none of the credentials. Same
# scanner contract as the SRE gate: refuse a vacuous scan, then refuse any
# retained run token, SVID, signing secret, or JWT-shaped material.
scan_artifacts() {
  ARTIFACT_DIR="$ARTIFACT_DIR" CREDS_DIR="$WORK/creds" \
    RUN_SECRET_VALUE="$RUN_SECRET" python3 - <<'PY'
import os, pathlib, re
root = pathlib.Path(os.environ["ARTIFACT_DIR"])
required = {"chain", "server.log", "obs.log", "tix.log", "capacity.log",
            "probes-oncall.log", "probes-capacity.log"}
present = {p.name for p in root.iterdir() if p.is_file()}
if missing := required - present:
    raise SystemExit(f"artifact scan is vacuous; missing {sorted(missing)}")
if not any(p.name.startswith("runner-") for p in root.iterdir()):
    raise SystemExit("artifact scan is vacuous; no runner logs retained")
secrets = [os.environ["RUN_SECRET_VALUE"].encode()]
creds = pathlib.Path(os.environ["CREDS_DIR"])
if creds.is_dir():
    for f in creds.iterdir():
        v = f.read_bytes().strip()
        if v:
            secrets.append(v)
for path in root.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    data = path.read_bytes()
    for secret in secrets:
        if secret and secret in data:
            raise SystemExit(f"credential material retained in {path.name}")
    if re.search(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", data):
        raise SystemExit(f"JWT-shaped material retained in {path.name}")
PY
}

prune_artifacts() {
  ARTIFACT_ROOT="$ARTIFACT_ROOT" ARTIFACT_KEEP="$ARTIFACT_KEEP" python3 - <<'PY'
import os, pathlib, re, shutil
root = pathlib.Path(os.environ["ARTIFACT_ROOT"])
keep = int(os.environ["ARTIFACT_KEEP"])
owned = re.compile(r"(?:[0-9a-f]{12}|failed-[A-Za-z0-9]+)$")
dirs = [p for p in root.iterdir()
        if p.is_dir() and not p.is_symlink() and owned.fullmatch(p.name)]
for path in sorted(dirs, key=lambda p: p.stat().st_mtime, reverse=True)[keep:]:
    shutil.rmtree(path)
for path in root.rglob("*"):
    if not path.is_symlink():
        path.chmod(0o700 if path.is_dir() else 0o600)
PY
}

preserve_artifacts() {
  local first_run
  first_run="$(awk 'NR==1{print $1}' "$WORK/chain" 2>/dev/null || true)"
  ARTIFACT_DIR="$ARTIFACT_ROOT/${first_run:-failed-$TAG}"
  mkdir -p "$ARTIFACT_DIR"
  cp "$WORK"/chain "$WORK"/*.log "$WORK"/run-*.json "$ARTIFACT_DIR/" 2>/dev/null || true
  docker logs "$SERVER" >"$ARTIFACT_DIR/server.log" 2>&1 || true
  printf 'workflow_id=%s\nserver=%s\nturn_cap=%s\n' \
    "$WF_ID" "$SERVER" "$MAX_TURNS" >"$ARTIFACT_DIR/metadata.env"
  prune_artifacts
}

live_runs() {
  docker ps --filter "name=andyur-msgrun-" --format '{{.Names}}' 2>/dev/null \
    | sed 's/^andyur-msgrun-//'
}

cleanup() {
  local rc=$?
  if [ -n "$ARTIFACT_ROOT" ] && [ -f "$ARTIFACT_ROOT/.andyur-msg-relay-artifacts" ]; then
    preserve_artifacts || rc=1
  fi
  if [ "$rc" -ne 0 ]; then
    echo "--- server diagnostics ---" >&2
    docker logs "$SERVER" 2>&1 | tail -60 >&2 || true
  fi
  for name in $(docker ps -aq --filter "name=andyur-msgrun-" 2>/dev/null); do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
  docker rm -f "$SERVER" >/dev/null 2>&1 || true
  for pidfile in "$WORK"/pids/*.pid; do
    [ -f "$pidfile" ] || continue
    kill "$(cat "$pidfile")" 2>/dev/null || true
  done
  # every entry this harness created carries either one of its role labels or a
  # run id recorded in the chain file; delete exactly those
  selectors="docker:label:andyur.role:$SERVER_ROLE docker:label:andyur.role:$OPERATOR_ROLE docker:label:andyur.role:$WORKER_ROLE"
  if [ -f "$WORK/chain" ]; then
    while read -r run_id _; do
      [ -n "$run_id" ] && selectors="docker:label:andyur.run_id:$run_id $selectors"
    done <"$WORK/chain"
  fi
  for selector in $selectors; do
    ids="$(docker exec andyur-spire-server /opt/spire/bin/spire-server entry show \
      -selector "$selector" -output json 2>/dev/null \
      | python3 -c 'import json,sys; print("\n".join(
          e["id"] for e in json.load(sys.stdin).get("entries", [])))' 2>/dev/null || true)"
    for id in $ids; do
      docker exec andyur-spire-server /opt/spire/bin/spire-server \
        entry delete -entryID "$id" >/dev/null 2>&1 || true
    done
  done
  rm -rf "$WORK"
  return "$rc"
}
trap cleanup EXIT

docker inspect andyur-spire-server >/dev/null 2>&1 \
  && docker inspect andyur-spire-agent >/dev/null 2>&1 \
  || { echo "start the container SPIRE stack first: ./run.sh spire-docker up"; exit 1; }
docker network inspect "$NET" >/dev/null
[ -z "$(docker ps -q --filter 'name=andyur-msg-server-' --filter 'name=andyur-msgrun-')" ] \
  || { echo "another msg-relay run appears to be live (andyur-msg-* containers); refusing"; exit 1; }
mkdir -p "$WORK/creds" "$WORK/pids"
if [ -e "$ARTIFACT_ROOT" ]; then
  [ -d "$ARTIFACT_ROOT" ] && [ ! -L "$ARTIFACT_ROOT" ] && [ -O "$ARTIFACT_ROOT" ] \
    && [ -f "$ARTIFACT_ROOT/.andyur-msg-relay-artifacts" ] \
    || { echo "refusing unowned or unmarked artifact root $ARTIFACT_ROOT" >&2; exit 1; }
  chmod 700 "$ARTIFACT_ROOT"
else
  mkdir -m 700 -p "$ARTIFACT_ROOT"
  : >"$ARTIFACT_ROOT/.andyur-msg-relay-artifacts"
fi

say "ensure the shared trace backend is ready"
if ! curl -sf http://127.0.0.1:16686/api/services >/dev/null 2>&1; then
  docker compose -f "$HERE/infra/docker-compose.yml" up -d jaeger >/dev/null
fi
for _ in $(seq 1 30); do
  curl -sf http://127.0.0.1:16686/api/services >/dev/null 2>&1 && break
  sleep 1
done
curl -sf http://127.0.0.1:16686/api/services >/dev/null \
  || { echo "Jaeger did not become ready on http://127.0.0.1:16686"; exit 1; }
ok "Jaeger ready"

say "build the shipped server and runner artifacts"
docker build -q -f "$HERE/Dockerfile.server" -t andyur-server "$HERE" >/dev/null
bash "$HERE/run.sh" sandbox-image --quiet >/dev/null
ok "images built"

entry "spiffe://$TD/control-plane" -selector "docker:label:andyur.role:$SERVER_ROLE"
entry "spiffe://$TD/operator" -selector "docker:label:andyur.role:$OPERATOR_ROLE"
entry "spiffe://$TD/worker" -selector "docker:label:andyur.role:$WORKER_ROLE"
for role_and_expected in "$SERVER_ROLE:spiffe://$TD/control-plane" \
                         "$OPERATOR_ROLE:spiffe://$TD/operator" \
                         "$WORKER_ROLE:spiffe://$TD/worker"; do
  role="${role_and_expected%%:*}"; expected_role="${role_and_expected#*:}"
  got=""
  for _ in $(seq 1 15); do
    got="$(docker run --rm --network "$NET" --label "andyur.role=$role" \
      -v "$SOCK:/run/spire/sockets:ro" \
      -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
      --entrypoint python andyur-runner -c '
import jwt
from andyur import identity
print(jwt.decode(identity.fetch_token(), options={"verify_signature":False})["sub"])
' 2>/dev/null || true)"
    [ "$got" = "$expected_role" ] && break
    sleep 1
  done
  [ "$got" = "$expected_role" ] \
    || { echo "$role identity did not propagate (got ${got:-none})"; exit 1; }
done

say "start the real server image (delegation allow-list, 10-run workflow cap)"
docker run -d --name "$SERVER" --network "$NET" --label "andyur.role=$SERVER_ROLE" \
  --add-host host.docker.internal:host-gateway \
  -v "$SOCK:/run/spire/sockets:ro" \
  -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  -e ANDYUR_PROFILE=dev -e ANDYUR_AGENT_AUTH=on -e ANDYUR_ASSERTED_USER=on \
  -e ANDYUR_REQUIRE_RUN_SVID=on -e ANDYUR_RUN_TOKEN_SECRET="$RUN_SECRET" \
  -e ANDYUR_DELEGATIONS="$ONCALL:$CAPACITY;$CAPACITY:$ONCALL" \
  -e ANDYUR_MAX_WORKFLOW_RUNS="$MAX_TURNS" \
  -e ANDYUR_MAX_DELEGATION_DEPTH="$MAX_TURNS" \
  -e ANDYUR_RUN_TTL_SECONDS="$RUN_TTL" \
  -e ANDYUR_OTEL_ENDPOINT=http://host.docker.internal:4318 \
  -p 127.0.0.1:18689:8642 andyur-server >/dev/null
for _ in $(seq 1 40); do curl -sf "$BASE/health" >/dev/null && break; sleep 1; done
curl -sf "$BASE/health" >/dev/null || { docker logs "$SERVER"; exit 1; }
ok "server healthy"

say "start the three real resource servers"
for url in http://127.0.0.1:8797/mcp http://127.0.0.1:8798/mcp http://127.0.0.1:8799/mcp; do
  curl -s --max-time 1 -o /dev/null "$url" 2>/dev/null \
    && { echo "refusing occupied resource endpoint $url"; exit 1; }
done
ANDYUR_SERVER_URL="$BASE" ANDYUR_OBS_PORT=8797 ANDYUR_TOOL_HOST=0.0.0.0 \
  "$HERE/.venv/bin/python" "$HERE/demos/sre-triage/observability.py" \
  >"$WORK/obs.log" 2>&1 &
echo $! >"$WORK/pids/obs.pid"
ANDYUR_SERVER_URL="$BASE" ANDYUR_TICKETS_PORT=8798 ANDYUR_TOOL_HOST=0.0.0.0 \
  "$HERE/.venv/bin/python" "$HERE/demos/sre-triage/tickets.py" \
  >"$WORK/tix.log" 2>&1 &
echo $! >"$WORK/pids/tix.pid"
ANDYUR_SERVER_URL="$BASE" ANDYUR_CAPACITY_PORT=8799 ANDYUR_TOOL_HOST=0.0.0.0 \
  "$HERE/.venv/bin/python" "$HERE/demos/sre-triage/capacity.py" \
  >"$WORK/capacity.log" 2>&1 &
echo $! >"$WORK/pids/capacity.pid"
for _ in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:8797/mcp \
    && curl -s -o /dev/null http://127.0.0.1:8798/mcp \
    && curl -s -o /dev/null http://127.0.0.1:8799/mcp && break
  sleep 1
done
curl -s -o /dev/null http://127.0.0.1:8797/mcp \
  && curl -s -o /dev/null http://127.0.0.1:8798/mcp \
  && curl -s -o /dev/null http://127.0.0.1:8799/mcp \
  || { echo "resource readiness failed"; cat "$WORK"/obs.log "$WORK"/tix.log "$WORK"/capacity.log; exit 1; }
ok "resources reachable"

say "materialize both agents from their approved definitions"
operator_api POST /agents \
  "{\"name\":\"$ONCALL\",\"description\":\"relay demo on-call\",\"registry_agent_id\":\"agt_oncall_relay\"}" \
  >/dev/null
operator_api POST /agents \
  "{\"name\":\"$CAPACITY\",\"description\":\"relay demo capacity\",\"registry_agent_id\":\"agt_capacity\"}" \
  >/dev/null
oncall_ceiling="$(operator_api GET /agents/$ONCALL/ceiling)"
echo "$oncall_ceiling" | grep -q 'resource:telemetry' \
  && ! echo "$oncall_ceiling" | grep -q 'resource:capacity' \
  && ok "oncall ceiling materialized and excludes capacity" \
  || bad "oncall ceiling wrong: $oncall_ceiling"
cap_ceiling="$(operator_api GET /agents/$CAPACITY/ceiling)"
echo "$cap_ceiling" | grep -q 'resource:capacity' \
  && ! echo "$cap_ceiling" | grep -q 'resource:tickets' \
  && ok "capacity ceiling materialized and excludes tickets" \
  || bad "capacity ceiling wrong: $cap_ceiling"

say "page the on-call agent (the only externally triggered turn)"
# files:read/files:write are the runner's own needs (loading the agent context,
# writing the mind), same grants the SRE demo's trigger carries. tasks:write is
# the relay channel: task delegation is what carries the user across hops (U4).
trigger='{"reason":"PAGE: INC-4471 checkout-service 5xx spike since 14:02Z. Triage; escalate remediation you are not entitled to perform.","acting_user":"dana","subject_context":{"service":"checkout-service"},"scope":["files:read","files:write","obs:read","tickets:read","tickets:comment","tasks:write","messages:write"]}'
operator_api POST "/agents/$ONCALL/trigger" "$trigger" >/dev/null || {
  echo "trigger refused"; exit 1; }

# --- the worker loop: heartbeat -> assignment -> attest -> launch -> probe ---
say "drive the wake chain as the worker (turn cap $MAX_TURNS)"
: >"$WORK/chain"
launched=0
probed_oncall=0
probed_capacity=0
quiet=0
deadline=$((SECONDS + 3600))
while :; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    bad "wake chain did not quiesce within 60 minutes"
    [ -z "$WF_ID" ] || operator_api POST "/workflows/$WF_ID/halt" '' >/dev/null 2>&1 || true
    break
  fi
  running="$(live_runs | python3 -c 'import json,sys
print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')"
  # A single failed beat must not kill the chain: the real worker retries, so
  # this one does too. Only a persistent failure (5 consecutive) is a finding.
  set +e
  hb="$(RUNNING="$running" docker run --rm --network "$NET" \
    --label "andyur.role=$WORKER_ROLE" \
    -v "$SOCK:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e SERVER="http://$SERVER:8642" -e TAG="$TAG" -e RUNNING="$running" \
    --entrypoint python andyur-runner -c '
import json, os, httpx
from andyur import identity
running = json.loads(os.environ["RUNNING"])
r = httpx.post(os.environ["SERVER"] + "/worker/heartbeat",
    headers=identity.auth_header(), timeout=15,
    json={"worker_id": "msg-harness-" + os.environ["TAG"], "slots": 2,
          "slots_free": max(0, 2 - len(running)), "running": running,
          "profile": "prod"})
r.raise_for_status()
out = r.json()
print(json.dumps([{k: a.get(k) for k in ("id", "agent", "run_token", "workflow_id")}
                  for a in out.get("assignments", [])]))
' 2>>"$WORK/heartbeat-errors.log")"
  hb_rc=$?
  set -e
  if [ "$hb_rc" -ne 0 ]; then
    hb_fails=$((${hb_fails:-0} + 1))
    if [ "$hb_fails" -ge 5 ]; then
      bad "worker heartbeat failed $hb_fails times in a row"
      tail -5 "$WORK/heartbeat-errors.log" >&2 || true
      break
    fi
    sleep 5
    continue
  fi
  hb_fails=0
  count="$(printf '%s' "$hb" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
  if [ "$count" -gt 0 ]; then
    quiet=0
    for i in $(seq 0 $((count - 1))); do
      run_id="$(printf '%s' "$hb" | python3 -c "import json,sys; print(json.load(sys.stdin)[$i]['id'])")"
      agent="$(printf '%s' "$hb" | python3 -c "import json,sys; print(json.load(sys.stdin)[$i]['agent'])")"
      token="$(printf '%s' "$hb" | python3 -c "import json,sys; print(json.load(sys.stdin)[$i]['run_token'])")"
      wf="$(printf '%s' "$hb" | python3 -c "import json,sys; print(json.load(sys.stdin)[$i]['workflow_id'] or '')")"
      [ -n "$WF_ID" ] || WF_ID="$wf"
      if [ "$launched" -ge "$MAX_TURNS" ]; then
        bad "server assigned turn $((launched + 1)) past the $MAX_TURNS cap"
        operator_api POST "/workflows/$WF_ID/halt" '' >/dev/null 2>&1 || true
        break 2
      fi
      launched=$((launched + 1))
      printf '%s %s\n' "$run_id" "$agent" >>"$WORK/chain"
      printf '%s' "$token" >"$WORK/creds/$run_id.token"
      entry "spiffe://$TD/agent/$agent/run/$run_id" \
        -selector "docker:label:andyur.run_id:$run_id" \
        -selector "docker:label:andyur.agent:$agent"
      expected="spiffe://$TD/agent/$agent/run/$run_id"
      svid=""
      for _ in $(seq 1 15); do
        svid="$(docker run --rm --network "$NET" \
          --label "andyur.run_id=$run_id" --label "andyur.agent=$agent" \
          -v "$SOCK:/run/spire/sockets:ro" \
          -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
          --entrypoint python andyur-runner -c '
from andyur import identity
print(identity.fetch_token())
' 2>/dev/null || true)"
        sub="$(SVID="$svid" python3 -c '
import jwt,os
try: print(jwt.decode(os.environ["SVID"], options={"verify_signature":False})["sub"])
except Exception: pass
')"
        [ "$sub" = "$expected" ] && break
        sleep 1
      done
      [ "$sub" = "$expected" ] \
        || { echo "per-run SVID did not propagate for $run_id (got ${sub:-none})"; exit 1; }
      printf '%s' "$svid" >"$WORK/creds/$run_id.svid"
      printf '%s\n' "$sub" >>"$WORK/svid-subs"
      echo "  turn $launched: $agent run $run_id"
      docker run --rm --name "andyur-msgrun-$run_id" --network "$NET" \
        --label "andyur.run_id=$run_id" --label "andyur.agent=$agent" \
        --add-host host.docker.internal:host-gateway \
        -v "$SOCK:/run/spire/sockets:ro" \
        -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
        -e ANDYUR_SERVER_URL="http://$SERVER:8642" -e ANDYUR_RUN_TOKEN="$token" \
        -e IS_SANDBOX=1 \
        -e ANDYUR_OTEL_ENDPOINT=http://host.docker.internal:4318 \
        -e ANDYUR_LLM=ollama \
        -e ANDYUR_OLLAMA_URL="${ANDYUR_OLLAMA_URL:-http://host.docker.internal:11434}" \
        -e ANDYUR_RUN_TTL_SECONDS="$RUN_TTL" \
        andyur-runner --agent "$agent" --run-id "$run_id" \
        >"$WORK/runner-$run_id.log" 2>&1 &
      # freeze this side's refusals while its run is live (the runner has whole
      # minutes of model time ahead of it; the probes need seconds)
      if [ "$agent" = "$ONCALL" ] && [ "$probed_oncall" = 0 ]; then
        probed_oncall=1
        ANDYUR_PROBE_RUN_TOKEN="$token" ANDYUR_PROBE_SVID="$svid" \
          ANDYUR_SERVER_URL="$BASE" \
          "$HERE/.venv/bin/python" "$HERE/infra/msg_relay_probe.py" --role oncall \
          >"$WORK/probes-oncall.log" 2>&1 || true
      elif [ "$agent" = "$CAPACITY" ] && [ "$probed_capacity" = 0 ]; then
        probed_capacity=1
        ANDYUR_PROBE_RUN_TOKEN="$token" ANDYUR_PROBE_SVID="$svid" \
          ANDYUR_SERVER_URL="$BASE" ANDYUR_CAPACITY_PORT=8799 \
          "$HERE/.venv/bin/python" "$HERE/infra/msg_relay_probe.py" --role capacity \
          >"$WORK/probes-capacity.log" 2>&1 || true
      fi
    done
  elif [ -z "$(live_runs)" ]; then
    quiet=$((quiet + 1))
    # the server heartbeat drain re-drives a refused wakeup on a 30s tick, so a
    # quiet spell shorter than that proves nothing; 80s of silence does
    if [ "$quiet" -ge 16 ]; then
      break
    fi
  else
    quiet=0
  fi
  sleep 5
done

say "the chain, as the server recorded it"
turns="$(wc -l <"$WORK/chain" | tr -d ' ')"
sed 's/^/  /' "$WORK/chain"
if [ "$turns" -ge 3 ] && [ "$turns" -le "$MAX_TURNS" ]; then
  ok "wake chain quiesced after $turns turns (cap $MAX_TURNS)"
else
  bad "wake chain ran $turns turns (want 3..$MAX_TURNS)"
fi
first_three="$(awk '{print $2}' "$WORK/chain" | head -3 | paste -sd, -)"
[ "$first_three" = "$ONCALL,$CAPACITY,$ONCALL" ] \
  && ok "turns alternate: paged oncall -> woken capacity -> woken oncall" \
  || bad "unexpected turn order: $first_three"

all_done=1; one_wf=1; depth_ok=1; pin_ok=1
prev_depth=-1
while read -r run_id agent; do
  rec="$(operator_api GET "/runs/$run_id")" || { all_done=0; continue; }
  printf '%s\n' "$rec" >"$WORK/run-$run_id.json"
  state="$(printf '%s' "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))')"
  wf="$(printf '%s' "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("workflow_id") or "")')"
  depth="$(printf '%s' "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("depth") or 0)')"
  pin="$(printf '%s' "$rec" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("subject_context") or "")')"
  case "$state" in pending|running|failed) all_done=0 ;; esac
  [ "$wf" = "$WF_ID" ] || one_wf=0
  [ "$depth" -ge "$prev_depth" ] || depth_ok=0
  prev_depth="$depth"
  printf '%s' "$pin" | grep -q 'checkout-service' || pin_ok=0
done <"$WORK/chain"
[ "$all_done" = 1 ] && ok "every turn's run completed" || bad "a turn's run is not complete"
[ "$one_wf" = 1 ] && ok "one workflow spans the whole chain ($WF_ID)" \
  || bad "chain crossed workflows"
[ "$depth_ok" = 1 ] && ok "delegation depth never decreases along the chain" \
  || bad "depth went backwards: forged parent?"
[ "$pin_ok" = 1 ] && ok "the incident pin (checkout-service) reached every turn unchanged" \
  || bad "a turn ran without the inherited pin"

uniq_svids="$(sort -u "$WORK/svid-subs" | wc -l | tr -d ' ')"
[ "$uniq_svids" = "$turns" ] \
  && ok "one distinct per-run SVID per turn ($uniq_svids)" \
  || bad "SVID subs not distinct per turn ($uniq_svids of $turns)"

say "the delegated work, server-owned"
to_cap="$(operator_api GET "/tasks?assignee=$CAPACITY")"
printf '%s' "$to_cap" | python3 -c "import json,sys
ts=[t for t in json.load(sys.stdin) if t.get('creator')=='$ONCALL']
raise SystemExit(0 if ts else 1)" \
  && ok "oncall's remediation task recorded for capacity" \
  || bad "no task $ONCALL -> $CAPACITY on the server"
printf '%s' "$to_cap" | python3 -c "import json,sys
ts=[t for t in json.load(sys.stdin)
    if t.get('creator')=='$ONCALL' and t.get('state')=='closed' and t.get('result')]
raise SystemExit(0 if ts else 1)" \
  && ok "capacity closed the remediation task with a result" \
  || bad "the remediation task was never closed with a result"

say "the refusals, frozen with live credentials"
for expected_probe in "ONCALL-TELEMETRY-MINT ALLOWED" "ONCALL-CAPACITY-MINT REFUSED"; do
  grep -q "$expected_probe" "$WORK/probes-oncall.log" 2>/dev/null \
    && ok "$expected_probe" || bad "missing probe result: $expected_probe"
done
for expected_probe in "CAPACITY-READ ALLOWED" "CAPACITY-TICKETS-MINT REFUSED" \
                      "PIN-SCALE REFUSED" "CEILING-SCALE REFUSED"; do
  grep -q "$expected_probe" "$WORK/probes-capacity.log" 2>/dev/null \
    && ok "$expected_probe" || bad "missing probe result: $expected_probe"
done

say "the outcome the relay was for"
grep -q "SCALED checkout-service" "$WORK/capacity.log" \
  && ok "capacity applied a bounded scale to checkout-service" \
  || bad "no scale was applied"
grep -q "COMMENT on INC-4471" "$WORK/tix.log" \
  && ok "oncall commented the incident ticket" \
  || bad "no comment landed on INC-4471"
egress_ok=1
while read -r run_id _; do
  grep -q "\[runner\] tool egress: sidecar" "$WORK/runner-$run_id.log" || egress_ok=0
done <"$WORK/chain"
[ "$egress_ok" = 1 ] && ok "sidecar egress active on every turn" \
  || bad "a turn ran without sidecar egress"

say "retention"
preserve_artifacts
scan_artifacts && ok "retained bundle contains no credential material" \
  || bad "credential material found in retained artifacts"

say "result: $PASS passed, $FAIL failed"
first_run="$(awk 'NR==1{print $1}' "$WORK/chain" 2>/dev/null || true)"
echo "  workflow:  $WF_ID"
echo "  artifacts: $ARTIFACT_DIR"
echo "  trace:     http://localhost:16686/search?service=andyur-server"
[ "$FAIL" -eq 0 ] && [ "$PASS" -eq "$EXPECTED_PASS" ]
