#!/usr/bin/env bash
# AUTONOMOUS MULTI-TURN AGENT-TO-AGENT DEMO. One page, zero orchestration.
#
# This script does exactly one thing to the platform: it pages the on-call
# agent. Everything after that is Andyur running itself -- the REAL daemon
# (sandbox + SPIRE registrar) launches each turn as an attested container, the
# on-call agent decides to escalate, its message wakes the capacity agent, the
# reply wakes on-call again, and the chain quiesces on its own under the
# server's 10-run workflow cap. The script's only remaining job is to NARRATE:
# it announces each run the daemon launches, each message as it lands, and each
# effect on the mock resources, then prints where to see the full trace.
#
#   turn 1  sre-oncall triages INC-4471, finds a capacity cause it is not
#           entitled to fix (its ceiling has no capacity actions), and assigns
#           a remediation TASK to `capacity`
#   turn 2  the task wakes `capacity` (own run, own SVID, inherited pin AND
#           inherited user -- U4 carries the paged human across the hop); it
#           applies a bounded scale, closes the task with the result, and
#           assigns a verify-task back
#   turn 3  that task wakes sre-oncall; it re-checks the metric and comments
#           the outcome on the ticket
#
# Delegation rides on TASKS, not messages, deliberately: tasks are the channel
# that carries the delegated user (U4), and a run without a user cannot mint
# resource tokens at all. See ROADMAP.md on the messaging channel.
#
# The deterministic security assertions (frozen refusals, per-turn SVID
# distinctness, credential-free artifacts) live in the companion gate,
# ./run.sh msg-verify -- proof and story are separate commands on purpose.
#
# Needs the shared SPIRE stack: ./run.sh spire-docker up
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NET="andyur-spire-net"
SOCK="andyur-spire-sockets"
TD="andyur.local"
WORK="$(mktemp -d)"
SERVER="andyur-msgdemo-server"
DAEMON="andyur-msgdemo-daemon"
SERVER_ROLE="msgdemo-server"
OPERATOR_ROLE="msgdemo-operator"
WORKER_ROLE="msgdemo-worker"
BASE="http://127.0.0.1:18689"
RUN_SECRET="$(openssl rand -hex 32)"
ONCALL="sre-oncall"
CAPACITY="capacity"
MAX_TURNS=10
# a relay turn is one full triage/remediate/verify pass of a local 30B reasoning
# model; the 900s default TTL measured too short for exactly that
RUN_TTL="${ANDYUR_RUN_TTL_SECONDS:-1800}"

say() { printf '\n== %s ==\n' "$*"; }
tell() { printf '  %s\n' "$*"; }
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

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "--- daemon diagnostics ---" >&2
    docker logs "$DAEMON" 2>&1 | tail -40 >&2 || true
    echo "--- server diagnostics ---" >&2
    docker logs "$SERVER" 2>&1 | tail -40 >&2 || true
    # keep the whole story for the postmortem (runner logs, resource logs, chain)
    keep="$HERE/data/msg-relay-demo/demo-failed"
    rm -rf "$keep"; mkdir -p "$keep"
    docker logs "$DAEMON" >"$WORK/daemon.log" 2>&1 || true
    docker logs "$SERVER" >"$WORK/server.log" 2>&1 || true
    cp "$WORK"/*.log "$WORK/chain" "$keep/" 2>/dev/null || true
    echo "diagnostics retained in $keep" >&2
  fi
  docker rm -f "$DAEMON" >/dev/null 2>&1 || true
  for id in $(docker ps -aq --filter "name=andyur-run-" 2>/dev/null); do
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
  docker rm -f "$SERVER" >/dev/null 2>&1 || true
  for pidfile in "$WORK"/pids/*.pid; do
    [ -f "$pidfile" ] || continue
    kill "$(cat "$pidfile")" 2>/dev/null || true
  done
  for selector in "docker:label:andyur.role:$SERVER_ROLE" \
                  "docker:label:andyur.role:$OPERATOR_ROLE" \
                  "docker:label:andyur.role:$WORKER_ROLE"; do
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
[ -z "$(docker ps -q --filter "name=$SERVER" --filter "name=$DAEMON")" ] \
  || { echo "a msg-relay demo appears to be live; refusing"; exit 1; }
mkdir -p "$WORK/pids"

say "bring up the platform (server + REAL daemon + resources)"
if ! curl -sf http://127.0.0.1:16686/api/services >/dev/null 2>&1; then
  docker compose -f "$HERE/infra/docker-compose.yml" up -d jaeger >/dev/null
  for _ in $(seq 1 30); do
    curl -sf http://127.0.0.1:16686/api/services >/dev/null 2>&1 && break
    sleep 1
  done
fi
docker build -q -f "$HERE/Dockerfile.server" -t andyur-server "$HERE" >/dev/null
docker build -q -f "$HERE/Dockerfile.daemon" -t andyur-daemon "$HERE" >/dev/null
bash "$HERE/run.sh" sandbox-image --quiet >/dev/null
tell "images built"

entry "spiffe://$TD/control-plane" -selector "docker:label:andyur.role:$SERVER_ROLE"
entry "spiffe://$TD/operator" -selector "docker:label:andyur.role:$OPERATOR_ROLE"
entry "spiffe://$TD/worker" -selector "docker:label:andyur.role:$WORKER_ROLE"

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
tell "server up (delegation allow-list: $ONCALL<->$CAPACITY, workflow cap $MAX_TURNS)"

docker run -d --name "$DAEMON" --network "$NET" --label "andyur.role=$WORKER_ROLE" \
  --add-host host.docker.internal:host-gateway \
  -v "$SOCK:/run/spire/sockets:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  -e ANDYUR_PROFILE=dev \
  -e ANDYUR_AGENT_AUTH=on -e ANDYUR_RUN_TOKEN_SECRET="$RUN_SECRET" \
  -e ANDYUR_DEPLOYMENT=docker -e ANDYUR_SANDBOX=on -e ANDYUR_SPIRE_REGISTRAR=on \
  -e ANDYUR_SANDBOX_NETWORK="$NET" -e ANDYUR_SANDBOX_IMAGE=andyur-runner \
  -e ANDYUR_SPIRE_SERVER_CONTAINER=andyur-spire-server \
  -e ANDYUR_SERVER_URL="http://$SERVER:8642" \
  -e ANDYUR_OTEL_ENDPOINT=http://host.docker.internal:4318 \
  -e ANDYUR_LLM=ollama \
  -e ANDYUR_OLLAMA_URL="${ANDYUR_OLLAMA_URL:-http://host.docker.internal:11434}" \
  andyur-daemon >/dev/null
sleep 3
docker inspect -f '{{.State.Running}}' "$DAEMON" | grep -q true \
  || { docker logs "$DAEMON"; exit 1; }
tell "daemon up (sandbox + per-run SPIRE registrar): the platform can now act alone"

for port_and_script in "8797:observability.py" "8798:tickets.py" "8799:capacity.py"; do
  port="${port_and_script%%:*}"; script="${port_and_script#*:}"
  curl -s --max-time 1 -o /dev/null "http://127.0.0.1:$port/mcp" 2>/dev/null \
    && { echo "refusing occupied resource endpoint :$port"; exit 1; }
  ANDYUR_SERVER_URL="$BASE" ANDYUR_OBS_PORT=8797 ANDYUR_TICKETS_PORT=8798 \
    ANDYUR_CAPACITY_PORT=8799 ANDYUR_TOOL_HOST=0.0.0.0 \
    "$HERE/.venv/bin/python" "$HERE/demos/sre-triage/$script" \
    >"$WORK/${script%.py}.log" 2>&1 &
  echo $! >"$WORK/pids/${script%.py}.pid"
done
for _ in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:8797/mcp \
    && curl -s -o /dev/null http://127.0.0.1:8798/mcp \
    && curl -s -o /dev/null http://127.0.0.1:8799/mcp && break
  sleep 1
done
tell "resources up: telemetry, tickets, capacity (each a token-enforcing PEP)"

operator_api POST /agents \
  "{\"name\":\"$ONCALL\",\"description\":\"relay demo on-call\",\"registry_agent_id\":\"agt_oncall_relay\"}" \
  >/dev/null
operator_api POST /agents \
  "{\"name\":\"$CAPACITY\",\"description\":\"relay demo capacity\",\"registry_agent_id\":\"agt_capacity\"}" \
  >/dev/null
tell "agents materialized from the registry: $ONCALL (obs+tickets), $CAPACITY (capacity only)"

say "page the on-call agent -- the last thing this script tells the platform to do"
trigger='{"reason":"PAGE: INC-4471 checkout-service 5xx spike since 14:02Z. Triage; escalate remediation you are not entitled to perform.","acting_user":"dana","subject_context":{"service":"checkout-service"},"scope":["files:read","files:write","obs:read","tickets:read","tickets:comment","tasks:write","messages:write"]}'
operator_api POST "/agents/$ONCALL/trigger" "$trigger" >/dev/null \
  || { echo "trigger refused"; exit 1; }
tell "paged. watching the andyur work (turn cap $MAX_TURNS, server-enforced)..."

# --- the narrator: observe, never drive -------------------------------------
: >"$WORK/seen-runs"
: >"$WORK/seen-msgs"
: >"$WORK/seen-effects"
turns=0
quiet=0
deadline=$((SECONDS + 2700))
scaled=0
while :; do
  [ "$SECONDS" -lt "$deadline" ] || { tell "(timed out waiting for quiesce)"; break; }
  moved=0
  # new runs the daemon launched (primary/sidecar containers, not agent halves)
  for name in $(docker ps --filter "name=andyur-run-" --format '{{.Names}}' 2>/dev/null); do
    run_id="${name#andyur-run-}"
    grep -q "^$run_id\$" "$WORK/seen-runs" 2>/dev/null && continue
    agent="$(docker inspect -f '{{index .Config.Labels "andyur.agent"}}' "$name" 2>/dev/null || true)"
    [ -n "$agent" ] || continue
    echo "$run_id" >>"$WORK/seen-runs"
    echo "$run_id $agent" >>"$WORK/chain"
    turns=$((turns + 1))
    moved=1
    tell "turn $turns: daemon launched $agent as attested run $run_id (spiffe://$TD/agent/$agent/run/$run_id)"
    # the daemon runs containers --rm, so follow the log NOW or lose the story
    docker logs -f "$name" >"$WORK/runner-$run_id.log" 2>&1 &
  done
  # new delegated work, read from the server as the operator: tasks carry the
  # relay (they inherit the user, U4); messages are narrated too if agents use them
  for assignee in "$CAPACITY" "$ONCALL"; do
    work="$(operator_api GET "/tasks?assignee=$assignee" 2>/dev/null || echo '[]')"
    while IFS=$'\t' read -r tid creator state title result; do
      [ -n "$tid" ] || continue
      key="$tid:$state"
      grep -q "^$key\$" "$WORK/seen-msgs" 2>/dev/null && continue
      echo "$key" >>"$WORK/seen-msgs"
      moved=1
      if [ "$state" = "closed" ]; then
        tell "task closed by $assignee: \"$title\" -> $result"
      else
        tell "task: $creator -> $assignee [$state]: \"$title\""
      fi
    done < <(printf '%s' "$work" | python3 -c '
import json,sys
for t in json.load(sys.stdin):
    title = " ".join(t.get("title","").split())
    result = " ".join((t.get("result") or "").split())
    print("\t".join([t.get("id",""), t.get("creator",""), t.get("state",""),
                     title[:120], result[:120]]))
' 2>/dev/null)
    msgs="$(operator_api GET "/messages?recipient=$assignee" 2>/dev/null || echo '[]')"
    while IFS=$'\t' read -r mid sender body; do
      [ -n "$mid" ] || continue
      grep -q "^$mid\$" "$WORK/seen-msgs" 2>/dev/null && continue
      echo "$mid" >>"$WORK/seen-msgs"
      moved=1
      tell "message: $sender -> $assignee: \"$body\""
    done < <(printf '%s' "$msgs" | python3 -c '
import json,sys
for m in json.load(sys.stdin):
    body = " ".join(m.get("body","").split())
    print("\t".join([m.get("id",""), m.get("sender",""),
                     body[:160] + ("..." if len(body) > 160 else "")]))
' 2>/dev/null)
  done
  # effects on the mock world
  for logname in tickets capacity; do
    while read -r line; do
      [ -n "$line" ] || continue
      key="$(printf '%s' "$line" | cksum | cut -d' ' -f1)"
      grep -q "^$key\$" "$WORK/seen-effects" 2>/dev/null && continue
      echo "$key" >>"$WORK/seen-effects"
      moved=1
      tell "effect: $line"
      printf '%s' "$line" | grep -q 'SCALED checkout-service' && scaled=1
    done < <(grep -h -o -E '(COMMENT on [A-Z0-9-]+: .*|SCALED [a-z-]+ [a-z_]+ [0-9]+ -> [0-9]+)' \
      "$WORK/$logname.log" 2>/dev/null || true)
  done
  if [ "$moved" = 1 ]; then
    quiet=0
  elif [ "$turns" -ge 1 ] && [ -z "$(docker ps -q --filter 'name=andyur-run-' 2>/dev/null)" ]; then
    # the server's wakeup drain re-drives missed wakes on a 30s tick, so only a
    # silence longer than that means the chain is really over -- whether it
    # finished or stalled; the exit code below tells those apart honestly
    quiet=$((quiet + 1))
    [ "$quiet" -ge 14 ] && break
  fi
  sleep 5
done

say "what the andyur did on its own"
turns="$(wc -l <"$WORK/chain" 2>/dev/null | tr -d ' ' || echo 0)"
sed 's/^/  /' "$WORK/chain" 2>/dev/null || true
tell ""
tell "turns: $turns (cap $MAX_TURNS; every turn a separate attested run)"
[ "$scaled" = 1 ] && tell "remediation: capacity applied a bounded scale to checkout-service" \
  || tell "remediation: NO scale was applied"
tell "trace: http://localhost:16686/search?service=andyur-server"
tell "gate (frozen refusals, SVID distinctness): ./run.sh msg-verify"

# a demo that silently did nothing is worse than a failing one: honest exit
[ "$turns" -ge 3 ] && [ "$scaled" = 1 ]
