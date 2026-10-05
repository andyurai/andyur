#!/usr/bin/env bash
# Full end-to-end: a REAL agent run on the containerized SPIRE domain, so ONE
# Jaeger trace shows both the agent's work (runner phases + tool calls) AND the
# per-run identity decision (auth.require_run + auth.bind=match). Everything that
# needs an SVID is a container on the domain: server, daemon, runner, operator.
#
# Prereqs (checked below): host Jaeger (./run.sh jaeger) and Ollama with the model.
# Usage: ./verify-full-trace.sh   (add `down` to tear down)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET="andyur-spire-net"; SOCK="andyur-spire-sockets"; TD="andyur.local"
SECRET="full-trace-secret"; AGENT="probe"
OTLP="http://host.docker.internal:4318"; OLLAMA="http://host.docker.internal:11434"
MODEL="${ANDYUR_AGENT_MODEL:-llama3.2}"

say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
fail(){ bad "$@"; exit 1; }
entry(){ local sid="$1"; shift; docker exec andyur-spire-server /opt/spire/bin/spire-server \
  entry create -parentID "spiffe://$TD/agent/node" -spiffeID "$sid" \
  -x509SVIDTTL 3600 -jwtSVIDTTL 300 "$@" >/dev/null 2>&1 || true; }
op(){ docker run --rm --network "$NET" --label andyur.role=operator \
  -v "$SOCK:/run/spire/sockets:ro" -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  --entrypoint python andyur-server -c "$1" 2>&1; }
teardown(){ docker rm -f andyur-server andyur-daemon $(docker ps -aq --filter "name=andyur-run-" 2>/dev/null) >/dev/null 2>&1 || true
  bash "$HERE/verify-slice3.sh" down >/dev/null 2>&1 || true; }

if [ "${1:-up}" = "down" ]; then say "tearing down"; teardown; echo done; exit 0; fi
trap 'echo; echo "(stack left up; tear down: $0 down)"' EXIT
teardown

say "0. prereqs"
curl -sf http://localhost:16686/ >/dev/null 2>&1 && ok "host Jaeger up" || { bad "Jaeger down: ./run.sh jaeger"; exit 1; }
curl -sf http://localhost:11434/api/tags >/dev/null 2>&1 && ok "Ollama serving ($MODEL)" || { bad "Ollama down: ollama serve"; exit 1; }

say "1. containerized SPIRE"
bash "$HERE/verify-slice3.sh" up >/dev/null 2>&1 && ok "SPIRE up" || { bad "SPIRE failed"; exit 1; }

say "2. register role identities (server, worker, operator)"
entry "spiffe://$TD/control-plane" -selector "docker:label:andyur.role:server"
entry "spiffe://$TD/worker"        -selector "docker:label:andyur.role:worker"
entry "spiffe://$TD/operator"      -selector "docker:label:andyur.role:operator"
# WAIT UNTIL AN ENTRY ACTUALLY RESOLVES, bounded, rather than sleeping 6s and
# announcing it. The old line said "entries registered + propagating" having
# verified only the first half: registration is synchronous, propagation is not,
# and on a loaded host the containers started below then failed to get an SVID
# in a way that reads as a real identity refusal.
wait_entry() {  # $1 = image, $2 = SPIFFE ID; remaining args are docker labels
  local image="$1" sid="$2"; shift 2
  local deadline=$((SECONDS + 60))
  while [ $SECONDS -lt $deadline ]; do
    if docker run --rm --network "$NET" "$@" \
         -v "$SOCK:/run/spire/sockets:ro" \
         -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
         -e ANDYUR_SVID_TIMEOUT=5 \
         --entrypoint python "$image" -c \
         'from andyur import identity; identity.fetch_token()' >/dev/null 2>&1
    then
      return 0
    fi
    sleep 1
  done
  bad "$sid never propagated to the agent within 60s"
  return 1
}
wait_entry andyur-server "spiffe://$TD/control-plane" --label andyur.role=server || exit 1
wait_entry andyur-daemon "spiffe://$TD/worker" --label andyur.role=worker || exit 1
wait_entry andyur-server "spiffe://$TD/operator" --label andyur.role=operator || exit 1
ok "server, worker, and operator entries registered and resolved"

say "3. control-plane server (identity + agent-auth + OTEL + trace-auth)"
docker run -d --name andyur-server --network "$NET" --label andyur.role=server \
  --add-host host.docker.internal:host-gateway \
  -v "$SOCK:/run/spire/sockets:ro" -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  -e ANDYUR_PROFILE=dev \
  -e ANDYUR_AGENT_AUTH=on -e ANDYUR_RUN_TOKEN_SECRET="$SECRET" \
  -e ANDYUR_OTEL=on -e ANDYUR_OTEL_ENDPOINT="$OTLP" -e ANDYUR_TRACE_AUTH=on \
  andyur-server >/dev/null
# Capture-then-match. NEVER `docker logs X | grep -q PAT`: grep -q exits at the
# FIRST match, which SIGPIPEs docker while it is still writing, and under this
# script's pipefail the PIPELINE reports failure even though the pattern WAS
# found -- a healthy server read as down. Root-caused in 644b63f.
srv_up=0
for _ in $(seq 1 40); do
  srv_logs="$(docker logs andyur-server 2>&1 || true)"
  case "$srv_logs" in *"Application startup complete"*) srv_up=1; break ;; esac
  sleep 1
done
[ "$srv_up" = 1 ] && ok "server up" \
  || { bad "server never started"; docker logs andyur-server 2>&1 | tail -15; exit 1; }

say "4. worker daemon (sandbox + registrar, launches sibling runner containers)"
docker run -d --name andyur-daemon --network "$NET" --label andyur.role=worker \
  --add-host host.docker.internal:host-gateway \
  -v "$SOCK:/run/spire/sockets:ro" -v /var/run/docker.sock:/var/run/docker.sock \
  -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  -e ANDYUR_PROFILE=dev \
  -e ANDYUR_AGENT_AUTH=on -e ANDYUR_RUN_TOKEN_SECRET="$SECRET" \
  -e ANDYUR_DEPLOYMENT=docker -e ANDYUR_SANDBOX=on -e ANDYUR_SPIRE_REGISTRAR=on -e ANDYUR_SANDBOX_NETWORK="$NET" \
  -e ANDYUR_SANDBOX_IMAGE=andyur-runner -e ANDYUR_SPIRE_SERVER_CONTAINER=andyur-spire-server \
  -e ANDYUR_SERVER_URL=http://andyur-server:8642 \
  -e ANDYUR_OTEL=on -e ANDYUR_OTEL_ENDPOINT="$OTLP" -e ANDYUR_TRACE_AUTH=on \
  -e ANDYUR_LLM=ollama -e ANDYUR_AGENT_MODEL="$MODEL" -e ANDYUR_OLLAMA_URL="$OLLAMA" \
  andyur-daemon >/dev/null
# BOUNDED, and prove the daemon completed worker initialization rather than
# merely observing that its container existed at one instant.
daemon_up=0
for _ in $(seq 1 30); do
  daemon_logs="$(docker logs andyur-daemon 2>&1 || true)"
  case "$daemon_logs" in *"worker "*" up,"*) daemon_up=1; break ;; esac
  [ "$(docker inspect -f '{{.State.Running}}' andyur-daemon 2>/dev/null || true)" = true ] \
    || break
  sleep 1
done
if [ "$daemon_up" = 1 ] && \
   [ "$(docker inspect -f '{{.State.Running}}' andyur-daemon 2>/dev/null || true)" = true ]; then
  ok "daemon up (worker SVID, docker.sock)"
else
  bad "daemon never completed worker initialization"; docker logs andyur-daemon 2>&1 | tail -15; exit 1
fi

say "5. operator creates an agent and triggers a run"
out="$(op "
import httpx
from andyur import identity
h = identity.auth_header(); base='http://andyur-server:8642'
httpx.post(base+'/agents', json={'name':'$AGENT','description':'a tracing test agent; when triggered, briefly greet and stop'}, headers=h, timeout=20)
r = httpx.post(base+'/agents/$AGENT/trigger', json={'reason':'say hello and finish'}, headers=h, timeout=20)
print('RUN', r.status_code, r.text)
")"
echo "$out" | grep -qE "RUN 20[01]" && ok "triggered: $(echo "$out" | grep RUN)" || { bad "trigger failed: $out"; exit 1; }
RUN_ID="$(echo "$out" | grep -o '"\(id\|run_id\)":"[a-f0-9]*"' | head -1 | grep -o '[a-f0-9]\{8,\}')"
echo "     run id: $RUN_ID"

say "6. wait for the daemon to launch the runner + the run to finish"
state=""
for _ in $(seq 1 60); do
  state="$(op "
import httpx
from andyur import identity
r=httpx.get('http://andyur-server:8642/runs/$RUN_ID', headers=identity.auth_header(), timeout=10)
print(r.json().get('state'))" 2>/dev/null | tail -1)"
  echo "     state=$state"
  [ "$state" = "done" ] || [ "$state" = "failed" ] && break
  sleep 5
done
[ "$state" = "done" ] && ok "run completed" || fail "run ended state=$state"

say "7. fetch the run's trace from Jaeger + check the spans"
tctx="$(op "
import httpx
from andyur import identity
r=httpx.get('http://andyur-server:8642/runs/$RUN_ID', headers=identity.auth_header(), timeout=10)
print(r.json().get('trace_ctx') or '')" 2>/dev/null | tail -1)"
TRACE_ID="$(echo "$tctx" | cut -d- -f2)"
echo "     trace id: $TRACE_ID"
# Jaeger v2's v3 query API, by trace id, through the gates' shared helper
# (waits for the exporters' batches; a trace that never appears is a failure).
# WAIT FOR THE SPANS THIS GATE ASSERTS ON, not merely for the trace to exist.
#
# Without --expect the helper returns at FIRST SIGHT, and delivery is batched
# three times over (the process's BatchSpanProcessor, the collector's batch,
# Jaeger's) -- so the runner's spans, which flush when its container exits,
# routinely arrive after the server's. This gate then asserted on whatever
# happened to have landed: it passed on an idle machine and failed with "no
# runner spans" inside an RC run, against a run that had completed normally.
# A gate whose answer depends on how busy the host is answers a different
# question from the one it asks.
readback="$(.venv/bin/python infra/observability/trace_readback.py "http://localhost:16686" "$TRACE_ID" \
  --wait 120 --expect auth.require_run,auth.bind,runner.execute)" \
  || fail "trace $TRACE_ID not readable from Jaeger: $readback"
ops="$(printf '%s' "$readback" | .venv/bin/python -c "import json,sys; print(chr(10).join(json.load(sys.stdin)['span_names']))")"
echo "$ops" | sed 's/^/     span: /'
echo "$ops" | grep -q "auth.require_run" && ok "identity in the trace: auth.require_run present" || fail "no auth.require_run span"
echo "$ops" | grep -q "auth.bind" && ok "auth.bind present (the token<->SVID decision)" || fail "no auth.bind span"
echo "$ops" | grep -q "^runner" && ok "the agent's runner phases present" || fail "no runner spans"
echo "$ops" | grep -q "^tool:" && ok "agent tool calls present" || echo "     (note: no tool: spans -- small model may not have called tools)"

trap - EXIT
echo; echo "Open the full trace: http://localhost:16686/trace/$TRACE_ID"
say "done (stack up; tear down: $0 down)"
