#!/usr/bin/env bash
# END TO END: a real agent, a real model, every capability the platform claims.
#
# Why this exists. Everything else in this repository tests a part: unit tests
# for the control plane, attack harnesses for the boundaries, container probes
# for egress. All of them passed throughout a refactor of the coordination core
# -- and not one of them would have noticed if the platform could no longer run
# an agent at all. A test suite that proves every property except "it works" is
# the shape of a system that breaks in production and passes in CI.
#
# So this drives the real thing: the real server, the real worker daemon, the
# real runner, the real Claude Agent SDK, and a real model. It asserts the
# golden path AND the refusals, because a platform that runs agents but has
# stopped confining them is equally broken.
#
# Cost: nothing. It runs against a local Ollama model by default.
#
#   ./run.sh e2e            # everything (a few minutes: real model runs)
#   ./run.sh e2e fast       # skip the model-driven phases (~20 seconds)
#
# Needs LOCAL SPIRE, because identity is not optional and there is no flag that
# substitutes: `./run.sh spire-server` and `spire-agent` running, and
# `./run.sh spire-setup` done once for the role binaries and their registration
# entries. Every operator call here carries a JWT-SVID; the server and worker
# run under their role binaries so SPIRE can attest them.
#
# Isolated by construction: its own data directory, its own port, its own
# database. It never touches a running Andyur.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

MODE="${1:-full}"
PORT="${ANDYUR_E2E_PORT:-8799}"
BROKER_PORT="${ANDYUR_E2E_BROKER_PORT:-8798}"
WORK="${ANDYUR_E2E_DIR:-/tmp/andyur-e2e}"
# Default model follows the backend: the local one for ollama, and for api mode
# the caller must say which, because that call costs real money.
if [ "${ANDYUR_LLM:-ollama}" = "api" ]; then
  MODEL="${ANDYUR_AGENT_MODEL:?set ANDYUR_AGENT_MODEL when ANDYUR_LLM=api}"
else
  MODEL="${ANDYUR_AGENT_MODEL:-qwen3-andyur}"
fi
VENV="$HERE/.venv"
BASE="http://127.0.0.1:$PORT"

PASS=0; FAIL=0
ok()   { printf '    \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '    \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cleanup() {
  [ "${ANDYUR_E2E_ENV_PROBE:-}" = 1 ] && return
  pkill -f "andyur.daemon" 2>/dev/null
  pkill -f "uvicorn andyur.server.app:app --host 127.0.0.1 --port $PORT" 2>/dev/null
  pkill -f "andyur.broker" 2>/dev/null
  sleep 1
}
trap cleanup EXIT

# One environment for every child, so the server, daemon and runner agree.
export ANDYUR_PROFILE=dev
export ANDYUR_DATA_DIR="$WORK"
export ANDYUR_SERVER_URL="$BASE"
export ANDYUR_PORT="$PORT"
export ANDYUR_GRAPH=off
# Keep this lightweight harness independent of a collector by default, but do
# not override the framework setting when the caller is explicitly verifying
# telemetry against a real OTLP backend.
export ANDYUR_OTEL="${ANDYUR_OTEL:-off}"
# Overridable, so this harness can be pointed at a REAL model rather than only
# the local one. It used to export ollama unconditionally, which silently
# overrode a caller's ANDYUR_LLM=api and made an "API mode" run identical to the
# ollama run -- including reporting the model-proxy path as verified when that
# path was never entered.
# Sandbox mode: run each agent inside the locked-down container that production
# requires, instead of as a host process. Off by default because it needs a
# built image and Docker; `./run.sh e2e sandbox` turns it on.
#
# Worth the trouble: with this off, the containment configuration production
# MANDATES had never executed a real agent run. That is how a runner image
# missing fastapi shipped -- the runner imports the model proxy at top level, so
# it could not start at all in a container, and nothing noticed.
if [ "$MODE" = "sandbox" ]; then
  export ANDYUR_DEPLOYMENT=docker
  export ANDYUR_SANDBOX=on
  export ANDYUR_SANDBOX_IMAGE="${ANDYUR_SANDBOX_IMAGE:-andyur-runner}"
fi
# Off-sandbox the agents run on the host, which the daemon refuses by default:
# at the runner's uid an agent could exec a peer role's binary and be handed
# that role's SVID. This is the documented dev opt-out (README), accepted here
# because the agents are this harness's own scripted ones against a throwaway
# scratch andyur. Sandbox mode keeps the real isolation instead.
if [ "${ANDYUR_SANDBOX:-off}" != "on" ]; then
  export ANDYUR_ALLOW_UNISOLATED_AGENT=on
fi
export ANDYUR_LLM="${ANDYUR_LLM:-ollama}"
export ANDYUR_AGENT_MODEL="$MODEL"
export ANDYUR_MAX_TURNS="${ANDYUR_MAX_TURNS:-6}"
# Generous, because a local model on a loaded developer machine is slow and a
# TTL trip here looks exactly like a platform bug: the reaper marks the run
# terminal, the kill switch then correctly condemns it as unaccountable, and the
# output reads "run did not complete" with no hint that the cause was the clock.
export ANDYUR_RUN_TTL_SECONDS="${ANDYUR_RUN_TTL_SECONDS:-1200}"
export ANDYUR_AGENT_AUTH=on
# An explicit delegation policy, so the delegation phase exercises the allowlist
# rather than the "nothing configured" path.
export ANDYUR_DELEGATIONS="planner:helper"
# Shared by every process here. Without it each one generates its own random
# secret and no token minted by one verifies at another -- which is precisely
# what the production profile refuses to boot without, and what this script
# reproduced on its first run.
export ANDYUR_RUN_TOKEN_SECRET="e2e-fixed-secret-not-for-production"
export ANDYUR_BROKER_URL="http://127.0.0.1:$BROKER_PORT"
# The port the broker BINDS. Without this it bound its 8643 default while
# everything else pointed at $BROKER_PORT, so the broker was never actually on
# the model path -- and the assertion below passed anyway, because it only
# checked that a log file existed.
export ANDYUR_BROKER_PORT="$BROKER_PORT"
export ANDYUR_BROKER_UPSTREAM="${ANDYUR_BROKER_UPSTREAM:-http://127.0.0.1:11434}"

# Inert seam for freezing the child-process environment contract without
# starting or stopping any Andyur process. The live harness below remains the
# artifact-level proof; this makes a forced-off regression fail in ordinary CI.
if [ "${ANDYUR_E2E_ENV_PROBE:-}" = 1 ]; then
  printf 'ANDYUR_OTEL=%s\nANDYUR_OTEL_ENDPOINT=%s\n' \
    "$ANDYUR_OTEL" "${ANDYUR_OTEL_ENDPOINT:-}"
  exit 0
fi

# Raw curl, for the calls that are NOT the operator: /health and /healthz,
# anything presenting X-Andyur-Run-Token, and the broker's own endpoints. The
# operator calls go through op() below, because they must carry a JWT-SVID and
# curl cannot fetch one.
api() { curl -s --max-time 20 "$@"; }
jqp() { "$VENV/bin/python" -c "import json,sys;d=json.load(sys.stdin);$1"; }

# Operator calls carry a JWT-SVID, which curl cannot fetch: they go through the
# CLI's api verb, run under the operator role binary so the SPIRE unix attestor
# recognises the caller by executable path. The role binaries are bare Python
# interpreters, so the venv rides in on PYTHONPATH -- derived from the venv
# python itself, so no interpreter version is hardcoded here.
#
# --server pins every call to THIS harness's server. The CLI subprocess reads
# .env with override=True, so an exported ANDYUR_SERVER_URL can be silently
# replaced by a stray .env entry -- and this harness creating agents on your
# real Andyur is the wrong kind of end-to-end.
OPERATOR_PY="$HERE/infra/roles/bin/andyur-operator"
SERVER_PY="$HERE/infra/roles/bin/andyur-server"
WORKER_PY="$HERE/infra/roles/bin/andyur-worker"
# The broker's only SPIRE-facing duty (the run-liveness check) is production-
# only, so it mirrors run.sh: the role binary when built, the venv python
# otherwise -- older spire-setup runs did not build a broker binary.
BROKER_PY="$HERE/infra/roles/bin/andyur-broker"
[ -x "$BROKER_PY" ] || BROKER_PY="$VENV/bin/python"
SITE=""    # the venv's site-packages; resolved once by require_operator
op() {
  local method="$1" path="$2"; shift 2
  PYTHONPATH="$SITE:$HERE" "$OPERATOR_PY" -m andyur.cli api \
    --server "$BASE" "$method" "$path" "$@"
}

require_operator() {
  [ -x "$VENV/bin/python" ] || { echo "run ./run.sh setup first"; exit 1; }
  SITE="$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
  for bin in "$OPERATOR_PY" "$SERVER_PY" "$WORKER_PY"; do
    [ -x "$bin" ] || {
      echo "no role binary at $bin."
      echo "Start local SPIRE and build the roles (in this order):"
      echo "    ./run.sh spire-server      # terminal 1"
      echo "    ./run.sh spire-agent       # terminal 2"
      echo "    ./run.sh spire-setup       # role binaries + registration entries"
      exit 1; }
  done
  # FAIL FAST on a dead Workload API. Without this every op() call blocks for
  # the full SVID timeout and dies on a traceback that never names SPIRE.
  ANDYUR_SVID_TIMEOUT=5 PYTHONPATH="$SITE:$HERE" "$OPERATOR_PY" -c \
    'from andyur import identity; identity.fetch_token()' >/dev/null 2>&1 || {
    echo "could not fetch an operator SVID from the local SPIRE Workload API."
    echo "Is SPIRE up, and are the roles registered?"
    echo "    ./run.sh spire-server      # terminal 1"
    echo "    ./run.sh spire-agent       # terminal 2"
    echo "    ./run.sh spire-setup       # role binaries + registration entries"
    exit 1; }
}

# Wait until an agent reaches a state, or time out. Returns the last state seen.
wait_state() {   # $1 agent, $2 wanted, $3 seconds
  local end=$((SECONDS + $3)) s=""
  while [ $SECONDS -lt $end ]; do
    s=$(op GET /agents 2>/dev/null | jqp "print(next((a['state'] for a in d if a['name']=='$1'),'?'))" 2>/dev/null)
    [ "$s" = "$2" ] && { echo "$s"; return 0; }
    sleep 3
  done
  echo "$s"; return 1
}

require_operator

step "boot: control plane, model broker, worker"
rm -rf "$WORK"; mkdir -p "$WORK"
PYTHONPATH="$SITE:$HERE" "$BROKER_PY" -m andyur.broker >"$WORK/broker.log" 2>&1 &
PYTHONPATH="$SITE:$HERE" "$SERVER_PY" -m uvicorn andyur.server.app:app \
  --host 127.0.0.1 --port "$PORT" >"$WORK/server.log" 2>&1 &
for _ in $(seq 1 40); do api "$BASE/health" >/dev/null 2>&1 && break; sleep 0.5; done
api "$BASE/health" | grep -q '"ok":true' && ok "control plane is serving" \
  || { bad "control plane never came up"; tail -20 "$WORK/server.log"; exit 1; }
PYTHONPATH="$SITE:$HERE" "$WORKER_PY" -m andyur.daemon >"$WORK/daemon.log" 2>&1 &
# Ask the CONTROL PLANE whether a worker joined, not the worker's own log. The
# log check was `grep -q worker daemon.log`, which matches the word in any line
# including every failure message the daemon prints -- "worker did not join" was
# unreachable as long as the daemon started and complained about something.
for _ in $(seq 1 20); do
  [ "$(op GET /workers 2>/dev/null | jqp "print(len(d))" 2>/dev/null)" -ge 1 ] 2>/dev/null && break
  sleep 1
done
w=$(op GET /workers | jqp "print(len(d))")
[ "${w:-0}" -ge 1 ] && ok "a worker registered with the control plane ($w)" \
                    || bad "no worker registered with the control plane"

step "agents exist, and their status is DERIVED from their runs"
for a in scout planner helper; do
  op POST /agents \
    --data "{\"name\":\"$a\",\"description\":\"e2e $a\",\"scope\":\"answer briefly\"}" >/dev/null
done
n=$(op GET /agents | jqp "print(len(d))")
[ "$n" = "3" ] && ok "three agents created" || bad "expected 3 agents, saw $n"
# COUNT the idle agents rather than asking all() -- all() over an empty list is
# True, so an /agents call that returned nothing (or failed) read as "every
# agent is correctly idle".
idle=$(op GET /agents | jqp \
       "print(sum(1 for a in d if a['state']=='idle' and a['run_id'] is None))")
[ "$idle" = "3" ] && ok "all three new agents read as idle with no status row to seed" \
                  || bad "expected 3 idle agents, saw $idle"

step "the write boundary, against the live server with a real run token"
# A run token for a live run, minted the way the server does, then used to
# attempt the writes a compromised run would attempt.
RUN=$(op POST /agents/scout/trigger \
      --data '{"reason":"e2e: boundary probe"}' | jqp "print(d['run_id'])")
TOK=$("$VENV/bin/python" -c "
from andyur.server import runtoken
print(runtoken.mint('scout', '$RUN', None))")
code() { api -o /dev/null -w '%{http_code}' -X PUT "$BASE/agents/scout/files/$1" \
         -H 'Content-Type: application/json' -H "X-Andyur-Run-Token: $TOK" \
         -d '{"content":"probe"}'; }
[ "$(code memory/notes.md)" = "200" ] && ok "a run may write its memory" \
                                      || bad "a run cannot write its own memory"
[ "$(code artifacts/report.md)" = "200" ] && ok "a run may write its artifacts" \
                                          || bad "a run cannot write artifacts"
[ "$(code mcp.json)" = "403" ] && ok "a run may NOT grant itself tools" \
                               || bad "a run rewrote its own tool grants"
[ "$(code instructions.md)" = "403" ] && ok "a run may NOT rewrite its instructions" \
                                      || bad "a run rewrote its own instructions"
c=$(api -o /dev/null -w '%{http_code}' -X PUT "$BASE/agents/planner/files/memory/x.md" \
    -H 'Content-Type: application/json' -H "X-Andyur-Run-Token: $TOK" -d '{"content":"x"}')
[ "$c" = "403" ] && ok "a run may NOT touch another agent" || bad "cross-agent write allowed"

step "the kill switch destroys a live run and frees its agent"
WF=$(op GET "/runs/$RUN" | jqp "print(d['workflow_id'])")
op POST "/workflows/$WF/halt" >/dev/null
# A halted run may still record WHAT HAPPENED, but may no longer write memory:
# influence over every future run of this agent, persisted after the kill.
# Before this existed, the poison landed and stayed for up to one heartbeat.
hm=$(api -o /dev/null -w '%{http_code}' -X PUT "$BASE/agents/scout/files/memory/long_term.md" \
     -H 'Content-Type: application/json' -H "X-Andyur-Run-Token: $TOK" -d '{"content":"poison"}')
[ "$hm" = "403" ] || [ "$hm" = "401" ] && ok "a halted run cannot write memory ($hm)" \
                                       || bad "a halted run wrote memory ($hm)"
s=$(wait_state scout idle 45)
[ "$s" = "idle" ] && ok "the halted run's agent is free again (state=$s)" \
                  || bad "agent stuck in '$s' after halt"
st=$(op GET "/runs/$RUN" | jqp "print(d['state'])")
[ "$st" = "failed" ] || [ "$st" = "cancelled" ] && ok "the run record is terminal ($st)" \
                                                || bad "run left in '$st' after halt"

if [ "$MODE" = "fast" ]; then
  step "fast mode: skipping the model-driven phases"
else
  step "a real agent run, end to end, through the SDK and a real model"
  R2=$(op POST /agents/scout/trigger \
       --data '{"reason":"e2e: reply with one sentence about what you are, then finish"}' \
       | jqp "print(d['run_id'])")
  s=$(wait_state scout running 30)
  [ "$s" = "running" ] && ok "the worker picked it up and started it" \
                       || bad "run never started (state=$s)"
  s=$(wait_state scout idle 900)
  if [ "$s" = "idle" ]; then
    ok "the run completed"
  else
    bad "run did not finish (state=$s) -- if the run record says the TTL was"
    bad "  exceeded, the model was slow, not the platform broken"
  fi
  op GET "/runs/$R2" | jqp "
state, err, summary = d['state'], d['error'], d['summary'] or ''
print('    run state:', state, '| error:', err)
print('    summary  :', summary[:120])
import sys; sys.exit(0 if state == 'done' and summary else 1)" \
    && ok "the run produced a summary and reported done" \
    || bad "the run did not complete cleanly"
  mem=$(op GET /agents/scout/files/memory/short_term.md | jqp "print(len(d.get('content','')))")
  [ "$mem" -gt 20 ] && ok "the agent wrote its memory through the audited tool ($mem bytes)" \
                    || bad "no memory written by the run"
  tr=$(op GET "/agents/scout/files/runs/$R2/transcript.jsonl" | jqp "print(len(d.get('content','')))")
  [ "$tr" -gt 100 ] && ok "the episodic record was stored ($tr bytes)" \
                    || bad "no transcript stored"

  step "delegation: one agent hands work to another, and the allowlist decides"
  # Wait for planner to be free first. Triggering an agent that already has a
  # live run is REFUSED with 409 by the partial unique index, and this block
  # used to ignore that: the mint crashed, PTOK became empty, and both requests
  # below went through as OPERATOR -- who may delegate to anyone. The allowed
  # case then "passed" for the wrong reason and the refusal case failed. A test
  # that authenticates as nobody must not look like a passing test.
  wait_state planner idle 120 >/dev/null
  # The trigger is an OPERATOR call, so it goes through op(); the token is then
  # minted locally with the shared secret, the same way the boundary probe's
  # was. A refused trigger leaves PRUN empty, PTOK empty, and the check below
  # says so -- it must not quietly fall through to operator-authenticated calls.
  PRUN=$(op POST /agents/planner/trigger --data '{"reason":"e2e delegation"}' \
         | jqp "print(d['run_id'])" 2>/dev/null)
  PTOK=""
  [ -n "$PRUN" ] && PTOK=$("$VENV/bin/python" -c "
from andyur.server import runtoken
print(runtoken.mint('planner', '$PRUN', None))")
  if [ -z "$PTOK" ]; then
    bad "could not mint a planner run token; delegation checks would have run as operator"
  fi
  d1=$(api -o /dev/null -w '%{http_code}' -X POST "$BASE/tasks" \
       -H 'Content-Type: application/json' -H "X-Andyur-Run-Token: $PTOK" \
       -d '{"assignee":"helper","title":"e2e delegated task","detail":"say ok"}')
  [ "$d1" = "201" ] && ok "planner may delegate to helper (on the allowlist)" \
                    || bad "allowed delegation refused ($d1)"
  d2=$(api -o /dev/null -w '%{http_code}' -X POST "$BASE/tasks" \
       -H 'Content-Type: application/json' -H "X-Andyur-Run-Token: $PTOK" \
       -d '{"assignee":"scout","title":"not allowed","detail":"x"}')
  [ "$d2" = "403" ] && ok "planner may NOT delegate to scout (off the allowlist)" \
                    || bad "delegation policy did not refuse ($d2)"
  s=$(wait_state helper running 40)
  [ "$s" = "running" ] || [ "$s" = "queued" ] && ok "the assignee was woken to work it" \
                                              || bad "assignee never woken (state=$s)"
fi

if [ "$ANDYUR_LLM" = "api" ]; then
  step "the runner's model proxy carried the traffic"
  # Without this the api-mode run looks identical to the ollama run and the
  # proxy path can be reported as verified without ever being entered.
  if grep -qh "model proxy on" "$WORK"/runlogs/*.log 2>/dev/null; then
    ok "$(grep -ho 'model proxy on .*' "$WORK"/runlogs/*.log | head -1)"
  else
    bad "no run went through the model proxy -- the agent talked to the broker directly"
  fi
fi

if [ "${ANDYUR_SANDBOX:-off}" = "on" ]; then
  step "the run executed inside the locked-down container, not on the host"
  # Two contained shapes now: one container, or a two-container pod. Both name
  # the run's container, and the HOST shape says "on the host" and matches
  # neither -- so this still fails exactly when a run escapes to the host, which
  # is the property it exists for.
  if grep -qhE "in (container|pod) andyur-run-" "$WORK/daemon.log" 2>/dev/null; then
    ok "$(grep -hoE "launched run .* in (container|pod) andyur-run-\\S+" "$WORK/daemon.log" | head -1)"
  else
    bad "no run container was launched -- the run executed on the host"
  fi
  # In pod mode, assert the SECOND container really RAN. The obvious version of
  # this check greps daemon.log for "andyur-agent-", and it CANNOT FAIL: the only
  # thing that writes that substring is the launch line's own f-string, which is
  # emitted whether or not the agent container ever started -- on the very line
  # the check above already matched. Absence of evidence scored as proof, in a
  # check written to catch exactly that.
  #
  # So look for something only the agent container itself can produce: its own
  # log file, carrying the credential audit that andyur.agent prints from INSIDE
  # it. No agent container, no file, no line.
  # Whatever shape was asked for, the runner must SAY it took that shape. A run
  # that quietly executes less split than configured still works, which is why
  # this needs asserting rather than assuming.
  if [ "${ANDYUR_AGENT_SPLIT:-off}" != "off" ]; then
    if grep -qh "\[runner\] split=${ANDYUR_AGENT_SPLIT}" "$WORK"/runlogs/*.log 2>/dev/null; then
      ok "the runner reported the configured split shape (split=${ANDYUR_AGENT_SPLIT})"
    else
      bad "no run reported split=${ANDYUR_AGENT_SPLIT}; the runner silently took a"$'\n'"        different shape than the one configured"
    fi
  fi
  if [ "${ANDYUR_AGENT_SPLIT:-off}" = "pod" ]; then
    if ! ls "$WORK"/runlogs/*-agent.log >/dev/null 2>&1; then
      bad "no agent-container log exists -- the pod's second half never ran"
    elif grep -qh "\[runner\] agent env" "$WORK"/runlogs/*-agent.log 2>/dev/null; then
      ok "the pod's agent container ran and audited its own environment"
    else
      bad "the agent container produced no audit line: $(head -c 200 "$WORK"/runlogs/*-agent.log 2>/dev/null | tr '\n' ' ')"
    fi
  fi
  # The image must be able to START the runner. A missing dependency here is
  # invisible on the host, where the venv has everything.
  #
  # REQUIRE THE EVIDENCE. This used to pass whenever the grep found no import
  # error, which is also what happens with no container, no docker, and no logs
  # at all: absence of evidence was scored as proof. So look for the runner
  # actually announcing itself, and only then rule out an import failure.
  if ! grep -qh "\[runner\]" "$WORK"/runlogs/*.log 2>/dev/null; then
    bad "no runner ever produced a log line inside the image (nothing to check)"
  elif grep -qhE "ModuleNotFoundError|ImportError" "$WORK"/runlogs/*.log 2>/dev/null; then
    bad "the runner could not import inside the image: $(grep -hoE '(ModuleNotFoundError|ImportError).*' "$WORK"/runlogs/*.log | head -1)"
  else
    ok "the runner started inside the image with its dependencies satisfied"
  fi
fi

step "the agent holds no model credential at all"
# The runner serves a loopback forwarder and adds the credential itself, so
# there is nothing in the agent's environment to exfiltrate.
#
# THIS CHECK USED TO PROVE NOTHING. It grepped the run logs for
# `ANTHROPIC_AUTH_TOKEN=<value>`, a literal string no code path ever writes --
# the environment is handed to the subprocess through Popen(env=...) and never
# printed. So it passed whether the platform worked or not, and passed with no
# runlogs directory at all.
#
# Now the runner AUDITS the dict it is about to spawn the agent with -- the
# effective environment, os.environ merged under the SDK's overrides, which is
# where the leak actually was -- and prints the names of any credentials that
# survived. Names only: printing a value would create the leak this asserts
# against. See driver.agent_env_credentials, which is unit- and mutation-tested.
if [ "$MODE" = "fast" ]; then
  # A SKIP IS NOT A PASS. Scoring it as one inflated the total with a check that
  # asserts nothing -- the same standard the ollama branch below already applies
  # ("say so and score nothing"), applied inconsistently in the same commit.
  printf '    \033[90mn/a\033[0m   credential audit not exercised (fast mode runs no agent)\n'
elif ! grep -qh "\[runner\] agent env" "$WORK"/runlogs/*.log 2>/dev/null; then
  bad "no agent env audit was ever emitted -- nothing ran, so nothing is proven"
elif grep -qh "agent env HOLDS CREDENTIALS" "$WORK"/runlogs/*.log 2>/dev/null; then
  bad "the agent subprocess held: $(grep -hoE 'HOLDS CREDENTIALS: .*' "$WORK"/runlogs/*.log | head -1)"
elif grep -qh "agent HOLDS CREDENTIAL FILES" "$WORK"/runlogs/*.log 2>/dev/null; then
  # A credential the agent can READ is held, whether or not it is in the
  # environment. `subscription` off-sandbox put nothing in the environment and
  # handed the agent the operator's ~/.claude/.credentials.json, and this gate
  # scored that clean. See driver.agent_file_credentials.
  bad "the agent could read: $(grep -hoE 'HOLDS CREDENTIAL FILES: .*' "$WORK"/runlogs/*.log | head -1)"
elif [ "${ANDYUR_SANDBOX:-off}" = "on" ]; then
  ok "the runner audited the agent's environment and it held no credential"
else
  # SAY WHAT IS AND IS NOT PROVEN HERE. Off-sandbox the agent shares the
  # runner's uid, so it can read the runner's own /proc/<pid>/environ -- which
  # holds whatever the process was STARTED with, and no amount of scrubbing in
  # Python rewrites that. The audit is still meaningful (it proves the spawn
  # carries nothing), but the CONTAINMENT claim rests on the uid split, which
  # only exists in the container. Scoring this as a pass in both modes would
  # make a sandbox-only property look like an unconditional one.
  ok "the audited spawn carried no credential (host mode: the uid split that"
  printf '          makes this a boundary is sandbox-only; run ./run.sh e2e sandbox)\n'
fi

step "the model broker held the key, and the agent never did"
# Was: `grep -q andyur-broker broker.log || [ -f broker.log ]`. The second test
# passes whenever the file exists, which it always does -- the shell creates it
# on redirect before the broker writes a byte. So this reported "the broker ran
# as the model path" for every run including ones where the broker was dead on a
# different port. Ask the broker itself instead.
if [ "$ANDYUR_LLM" = "api" ]; then
  # Demand the broker's OWN health response, not merely something answering.
  # Accepting 401/404 meant any HTTP server on that port passed -- including a
  # different service, and including a stale broker from an earlier run.
  if [ "$(api -o /dev/null -w '%{http_code}' "$ANDYUR_BROKER_URL/healthz")" = "200" ]; then
    ok "the broker answered its own health check on the port the agent was pointed at"
  else
    bad "nothing is serving $ANDYUR_BROKER_URL -- the broker was not on the model path"
  fi
  # And that it actually CARRIED THIS RUN'S traffic. Listening is not serving:
  # the broker bound the right port for every run ever made while sitting off
  # the model path entirely. Ask /usage as the RUN (its own broker-purpose
  # credential, which is what scopes the answer) and require a non-zero count.
  # Asking anonymously would return anonymous's own zero and prove nothing.
  if [ -n "${R2:-}" ]; then
    BTOK=$("$VENV/bin/python" -c "
from andyur.server import runtoken
print(runtoken.mint('scout', '$R2', None, purpose=runtoken.PURPOSE_BROKER))")
    used=$(api "$ANDYUR_BROKER_URL/usage" -H "Authorization: Bearer $BTOK" \
           | jqp "print(d.get('calls', 0))")
    [ "${used:-0}" -gt 0 ] 2>/dev/null \
      && ok "the broker metered $used model call(s) for run $R2 -- it was on the path" \
      || bad "the broker metered no calls for run $R2 -- traffic bypassed it"
  fi
else
  # NOT a pass. It used to call ok() unconditionally, which inflated the count
  # with an assertion that asserts nothing; in ollama mode there is no brokered
  # path to verify, so say so and score nothing.
  printf '    \033[90mn/a\033[0m   brokered path not exercised (ANDYUR_LLM=%s)\n' "$ANDYUR_LLM"
fi
# grep -c PREFIXES EACH COUNT WITH ITS FILENAME once there are 2+ files, which
# is the normal case. `paste`+`bc` then choked on `path:0+path:2`, and the
# trailing `|| echo 0` turned that parse failure into a PASS -- so the harness's
# headline security claim was unfalsifiable exactly when there was traffic to
# check. -h suppresses the filenames; wc -l needs no arithmetic at all.
#
# AND IT MUST HAVE LOGS TO SEARCH. Fixing the arithmetic left the other half of
# the same defect in place: with no runlogs directory the grep matches nothing,
# the count is zero, and "no provider key appears in any run log" PASSED --
# which is exactly the absence-of-evidence scoring this file condemns twelve
# lines above, in the check immediately before it. Found by a red-team pass over
# the commit that wrote that comment.
if ! ls "$WORK"/runlogs/*.log >/dev/null 2>&1; then
  if [ "$MODE" = "fast" ]; then
    printf '    \033[90mn/a\033[0m   no run logs to search (fast mode runs no agent)\n'
  else
    bad "no run logs exist to search for a leaked key -- nothing is proven"
  fi
else
  # Match an ASSIGNMENT (`ANTHROPIC_API_KEY=<value>`), not the bare name. The
  # bare name legitimately appears in the Claude CLI's own startup notice ("...
  # because ANTHROPIC_API_KEY or another auth source is set ..."), which reaches
  # the runlog whenever an agent runs -- so the old name-only grep reported a leak
  # on every successful ollama run, in-process AND split alike. That is the exact
  # "assertion fires on the wrong thing" this file hunts elsewhere. An env leak
  # looks like KEY=value; the prose notice has no `=`. (The strong check below,
  # for the key's actual VALUE, is the real guard when a key is present.)
  leak=$(grep -hoE "ANTHROPIC_API_KEY=[^[:space:]'\"]+" "$WORK"/runlogs/*.log 2>/dev/null | wc -l | tr -d ' ')
  [ "${leak:-0}" = "0" ] && ok "no ANTHROPIC_API_KEY=<value> assignment appears in any run log" \
                         || bad "a provider key assignment appears in the run logs ($leak times)"
fi
# Stronger, when there is a real key to look for: the NAME never appearing is
# weak evidence (a leak prints the value, not the variable). Search every log
# the platform wrote for the secret itself.
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  vleak=$(grep -rhoF "$ANTHROPIC_API_KEY" "$WORK" 2>/dev/null | wc -l | tr -d ' ')
  [ "${vleak:-0}" = "0" ] && ok "the provider key's VALUE appears nowhere under $WORK" \
                          || bad "the provider key's value leaked into $WORK ($vleak times)"
fi

step "the platform is still consistent after all of it"
bad_rows=$("$VENV/bin/python" -c "
from andyur import db
with db.connect() as c:
    # every agent's derived state must match its runs; the view cannot drift,
    # so this is really asserting the index held under concurrent load
    dup = c.execute(\"SELECT agent, COUNT(*) n FROM runs \"
                    \"WHERE state IN ('pending','running') GROUP BY agent \"
                    \"HAVING COUNT(*) > 1\").fetchall()
print(len(dup))")
[ "$bad_rows" = "0" ] && ok "no agent ever held two live runs" \
                      || bad "$bad_rows agents hold multiple live runs"

echo
printf '%s\n' "----------------------------------------"
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || { echo "logs in $WORK"; exit 1; }
echo "END TO END: PASSED"
