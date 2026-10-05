#!/usr/bin/env bash
# Stand up a small, throwaway Andyur whose only job is to let you drive the token
# mint by hand and watch each authority term refuse something.
#
# This script does the BORING part only: a scratch database, a server, a handful
# of agents with deliberately different ceilings, and one live pinned run each.
# It then prints the run tokens and hands you back the keyboard. Every
# interesting request in docs/authority-runbook.md is one you type yourself.
#
#   ./run.sh authority-demo up       start it, print the tokens
#   ./run.sh authority-demo decode <jwt>   read a minted token's claims
#   ./run.sh authority-demo down     stop it and remove what it created
#
# By default this runs its OWN server on port 8655 against a scratch database, so
# it cannot disturb anything you have running. That is isolation, not a different
# product: same code, same schema, same endpoints.
#
# Every mode that talks to a server needs LOCAL SPIRE, because identity is not
# optional and there is no flag that substitutes: `./run.sh spire-server` and
# `spire-agent` running, and `./run.sh spire-setup` done once for the role
# binaries and their registration entries. `decode` works offline, and scratch
# `down` (kill + rm) needs nothing, so an orphaned demo server is always
# stoppable.
#
# With --real it uses your actual Andyur instead (port 8642, data/andyur.db), and
# `down` removes just the six agents it created via DELETE /agents/<name> rather
# than deleting a database. Use that when you want to satisfy yourself that this
# is the real system and not a special harness. It requires a stack started with
# agent-auth on:
#
#     ANDYUR_AGENT_AUTH=on ./run.sh up
#
# With agent-auth off, dev treats every caller as the operator and run tokens are
# not parsed at all, so there is no caller identity for the ceiling to apply to
# and the tour cannot demonstrate anything.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${HERE}/infra/ports.sh"
VENV="$HERE/.venv"
PY="$VENV/bin/python"

REAL=0
PREFIX=""
PREFIX_SET=0        # distinguishes "not supplied" from "supplied as empty"
CMD=""
DECODE_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --real)    REAL=1 ;;
    --prefix)  PREFIX="${2:-}"; PREFIX_SET=1; shift ;;
    --prefix=*) PREFIX="${1#--prefix=}"; PREFIX_SET=1 ;;
    up|down|decode) CMD="$1" ;;
    *) if [ "$CMD" = "decode" ] && [ -z "$DECODE_ARG" ]; then DECODE_ARG="$1"
       else echo "usage: ./run.sh authority-demo [up|down|decode <jwt>] [--real] [--prefix <p>]"; exit 1
       fi ;;
  esac
  shift
done
CMD="${CMD:-up}"

# This demo names the user its runs act for without an identity provider, so it
# must opt in: with no IdP, Andyur signs a token whose subject nobody
# authenticated, and that is off by default. The minted token says so
# (`andyur_sub_src: asserted`), and a resource server can refuse it on that
# basis. Both branches below start a server, so this belongs above them -- put
# inside one, the other comes up and cannot start a single run.
export ANDYUR_ASSERTED_USER=on

if [ "$REAL" = "1" ]; then
  export ANDYUR_DATA_DIR="${ANDYUR_DATA_DIR:-$HERE/data}"
  export ANDYUR_PORT="${ANDYUR_PORT:-8642}"
else
  export ANDYUR_DATA_DIR="${ANDYUR_DATA_DIR:-${TMPDIR:-/tmp}/andyur-authority-demo-${UID:-user}}"
  # Overridable so more than one scratch copy (or a test) can run at once.
  export ANDYUR_PORT="${ANDYUR_PORT:-8655}"
fi
export ANDYUR_PROFILE=dev
export ANDYUR_GRAPH=none
export ANDYUR_OTEL=off
# Agent-auth ON is the whole point: with it off, dev treats every caller as the
# operator, run tokens are not parsed at all, and there is no "caller" for the
# ceiling to apply to. The operator itself is proven by JWT-SVID against local
# SPIRE -- identity is not optional, and there is no flag that substitutes.
export ANDYUR_AGENT_AUTH=on
# Fixed so the server and anything else here agree. The default is a random
# per-process value, which is correct for production single-node and useless the
# moment a second process has to verify a token this one signed.
export ANDYUR_RUN_TOKEN_SECRET=authority-demo-secret

B="http://127.0.0.1:$ANDYUR_PORT"
PIDFILE="$ANDYUR_DATA_DIR/demo-server.pid"
PIDSTARTFILE="$ANDYUR_DATA_DIR/demo-server.started"
ENVFILE="$ANDYUR_DATA_DIR/tokens.env"
DEMO_SENTINEL="$ANDYUR_DATA_DIR/.andyur-authority-demo"

require_scratch_ownership() {
  [ ! -e "$ANDYUR_DATA_DIR" ] || [ -f "$DEMO_SENTINEL" ] || {
    echo "refusing non-demo scratch directory $ANDYUR_DATA_DIR (ownership marker absent)" >&2
    return 1
  }
}

stop_scratch_server() {
  local pid command expected_start actual_start state
  [ -f "$PIDFILE" ] || return 0
  [ -f "$PIDSTARTFILE" ] || {
    echo "refusing PID file without an invocation start fingerprint" >&2
    return 1
  }
  pid="$(cat "$PIDFILE")"
  case "$pid" in *[!0-9]*|'') return 0 ;; esac
  expected_start="$(cat "$PIDSTARTFILE")"
  actual_start="$(ps -p "$pid" -o lstart= 2>/dev/null || true)"
  [ -n "$actual_start" ] || { rm -f "$PIDFILE" "$PIDSTARTFILE"; return 0; }
  [ "$actual_start" = "$expected_start" ] || {
    echo "refusing stale PID $pid: process start fingerprint changed" >&2
    return 1
  }
  command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  case "$command" in
    *andyur.server.app:app*) kill "$pid" 2>/dev/null || true ;;
    "") ;;
    *) echo "refusing to kill PID $pid: it is not the authority-demo server" >&2
       return 1 ;;
  esac
  for _ in $(seq 1 50); do
    state="$(ps -p "$pid" -o state= 2>/dev/null || true)"
    case "$state" in
      ""|Z*) wait "$pid" 2>/dev/null || true
      rm -f "$PIDFILE" "$PIDSTARTFILE"; return 0
      ;;
    esac
    sleep 0.1
  done
  echo "authority-demo server PID $pid did not stop" >&2
  return 1
}

prepare_scratch_directory() {
  local remaining
  require_scratch_ownership
  if [ -e "$ANDYUR_DATA_DIR" ]; then
    [ -O "$ANDYUR_DATA_DIR" ] || {
      echo "refusing scratch directory not owned by this user" >&2; return 1
    }
    chmod 700 "$ANDYUR_DATA_DIR" || {
      echo "could not secure scratch directory permissions" >&2; return 1
    }
    stop_scratch_server
    # Keep the owned directory inode. Removing and recreating a predictable path
    # under /tmp creates a race in which another local user can acquire it.
    if ! rm -rf "$ANDYUR_DATA_DIR"/* "$ANDYUR_DATA_DIR"/.[!.]* \
         "$ANDYUR_DATA_DIR"/..?* 2>/dev/null; then
      echo "could not clear prior scratch state; refusing stale database" >&2
      return 1
    fi
    if ! remaining="$(find "$ANDYUR_DATA_DIR" -mindepth 1 -maxdepth 1 -print -quit)"; then
      echo "could not verify prior scratch cleanup" >&2
      return 1
    fi
    if [ -n "$remaining" ]; then
      echo "prior scratch state survived cleanup; refusing stale database" >&2
      return 1
    fi
  else
    mkdir -m 700 "$ANDYUR_DATA_DIR" || {
      echo "could not atomically acquire scratch directory $ANDYUR_DATA_DIR" >&2
      return 1
    }
  fi
  [ -O "$ANDYUR_DATA_DIR" ] || {
    echo "refusing scratch directory not owned by this user" >&2; return 1
  }
  chmod 700 "$ANDYUR_DATA_DIR"
  : > "$DEMO_SENTINEL"
}

# The six roles. Names are always PREFIX + role, and teardown deletes exactly
# those, never "every agent starting with the prefix" -- a prefix scan would take
# an agent of yours that merely sorts under it, and deletion has no undo.
ROLES="classifier specialist roamer bystander teller muzzled"

# `down` must target what `up` created, so the prefix is remembered alongside the
# tokens. An explicit --prefix still wins, for cleaning up after a run whose
# tokens file is gone.
if [ "$PREFIX_SET" = "0" ] && [ -f "$ENVFILE" ]; then
  PREFIX="$(sed -n 's/^export ANDYUR_DEMO_PREFIX=//p' "$ENVFILE" | tail -1)"
fi
[ "$PREFIX_SET" = "0" ] && PREFIX="${PREFIX:-demo-}"

# An EMPTY prefix would make teardown delete bare `classifier`, which is exactly
# the agent-of-yours-with-a-common-name case the prefix exists to prevent. The
# rest of the rule is the server's own name grammar, checked here so a bad prefix
# fails before it creates six agents that cannot be addressed.
case "$PREFIX" in
  "" ) echo "--prefix cannot be empty: teardown would delete unprefixed agents"; exit 1 ;;
esac
if ! printf '%s' "$PREFIX" | grep -Eq '^[a-z][a-z0-9_-]*$'; then
  echo "invalid --prefix '$PREFIX': must start with a lowercase letter and use only [a-z0-9_-]"
  exit 1
fi
if [ ${#PREFIX} -gt 40 ]; then
  echo "invalid --prefix '$PREFIX': too long (agent names are capped at 64 characters)"
  exit 1
fi

DEMO_AGENTS=""
for r in $ROLES; do DEMO_AGENTS="$DEMO_AGENTS $PREFIX$r"; done

# Operator calls carry a JWT-SVID, which curl cannot fetch: they go through the
# CLI's api verb, run under the operator role binary so the SPIRE unix attestor
# recognises the caller by executable path. The role binaries are bare Python
# interpreters, so the venv rides in on PYTHONPATH -- derived from the venv
# python itself, so no interpreter version is hardcoded here.
#
# --server pins every call to THIS script's server. The CLI subprocess reads
# .env with override=True, so an exported ANDYUR_SERVER_URL can be silently
# replaced by a stray .env entry -- and a teardown aimed at the wrong Andyur
# deletes real agents.
OPERATOR_PY="$HERE/infra/roles/bin/andyur-operator"
SERVER_PY="$HERE/infra/roles/bin/andyur-server"
SITE=""    # the venv's site-packages; resolved once by require_operator
api() {
  local method="$1" path="$2"; shift 2
  if [ -n "${ANDYUR_DEMO_API_TRACE:-}" ]; then
    printf '%s %s\n' "$method" "$path" >> "$ANDYUR_DEMO_API_TRACE"
  fi
  if [ -n "${ANDYUR_DEMO_TEST_FAIL_PATH:-}" ] \
     && [ "$path" = "$ANDYUR_DEMO_TEST_FAIL_PATH" ]; then
    echo "injected demo API failure for $method $path" >&2
    return 97
  fi
  case "$path" in
    /runs/*/token)
      if [ -n "${ANDYUR_DEMO_TEST_EMPTY_RUN_TOKEN:-}" ]; then
        printf '{"run_token":""}\n'; return 0
      fi ;;
  esac
  PYTHONPATH="$SITE:$HERE" "$OPERATOR_PY" -m andyur.cli api \
    --server "$B" "$method" "$path" "$@"
}

# The guard for the paths that TALK to a server. `decode` reads a token locally
# and scratch `down` is kill + rm -rf; neither needs SPIRE, so neither pays for
# it -- an orphaned scratch server must be stoppable on a machine whose role
# binaries are gone.
require_operator() {
  [ -x "$PY" ] || { echo "run ./run.sh setup first"; exit 1; }
  SITE="$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
  [ -x "$OPERATOR_PY" ] || {
    echo "no operator role binary at $OPERATOR_PY."
    echo "Start local SPIRE and build the roles (in this order):"
    echo "    ./run.sh spire-server      # terminal 1"
    echo "    ./run.sh spire-agent       # terminal 2"
    echo "    ./run.sh spire-setup       # role binaries + registration entries"
    exit 1; }
  # FAIL FAST on a dead Workload API. Without this every api() call blocks for
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

# Every live run of $1 is halted, and we WAIT for the agent to actually go quiet.
#
# This exists because the teardown below was unsynchronised and CI could not see
# it. The demo deliberately leaves its runs live -- there is no worker to finish
# them -- and DELETE /agents REFUSES while any run is pending or running,
# INCLUDING with force=true. That is deliberate server design, stated in
# app.py::delete_agent: "a run in flight has a runner behind it", and deleting
# the agent would turn a clean refusal into an untracked execution. The comment
# that used to sit here claimed force covered "precisely the wedged-run case".
# It never did, and the 409 body has always named the actual remedy: "finish or
# halt them and wait for a terminal state before deleting".
#
# It went unnoticed because the CI step that runs these tests piped pytest into
# `tee` under a shell with no pipefail, so it could not report a failing test.
# With that fixed the failure is immediate and reproducible on a 2-core runner.
halt_live_runs_of() {
  local a="$1" deadline live w
  # halt_workflow cancels a workflow's PENDING runs, which is what the demo's
  # runs are: nothing ever claims them. It deliberately does NOT touch a
  # RUNNING run, so the wait below can genuinely fail to converge and must say
  # so rather than shrug.
  for w in $(api GET "/runs?agent=$a&limit=200" 2>/dev/null | "$PY" -c '
import sys, json
try: rows = json.load(sys.stdin).get("runs", [])
except Exception: rows = []
print(" ".join(sorted({r["workflow_id"] for r in rows
                       if r.get("workflow_id") and r.get("state") in ("pending", "running")})))
' 2>/dev/null); do
    api POST "/workflows/$w/halt" >/dev/null 2>&1 || true
  done

  # BOUNDED, and expiry is an ERROR carrying the run ids and states. An
  # unbounded wait would hang the gate; a silently-expiring one would rebuild
  # exactly the false green this change exists to remove, one layer down.
  deadline=$(( $(date +%s) + ${ANDYUR_DEMO_HALT_TIMEOUT:-30} ))
  while :; do
    # FAILS CLOSED. An unreadable answer -- a 502, a dead server, an envelope
    # without "runs" -- is NOT "zero live runs", it is "unknown", and treating
    # it as zero would delete the agent on the strength of a failed request.
    # That is the same fail-open shape as the CI step this change came from, so
    # -1 keeps the loop waiting until the bounded deadline reports it.
    live=$(api GET "/runs?agent=$a&limit=200" 2>/dev/null | "$PY" -c '
import sys, json
try:
    body = json.load(sys.stdin)
    rows = body["runs"]
    print(sum(1 for r in rows if r.get("state") in ("pending", "running")))
except Exception:
    print(-1)
' 2>/dev/null)
    [ "${live:-0}" -eq 0 ] && return 0
    if [ "$(date +%s)" -ge "$deadline" ]; then
      if [ "${live:-0}" -lt 0 ]; then
        echo "  could not read $a's runs (server unreachable or bad response);"
        echo "  refusing to delete it on the strength of a failed request"
        return 1
      fi
      echo "  $a still has $live live run(s) ${ANDYUR_DEMO_HALT_TIMEOUT:-30}s after halt:"
      api GET "/runs?agent=$a&limit=200" 2>/dev/null | "$PY" -c '
import sys, json
try: rows = json.load(sys.stdin).get("runs", [])
except Exception: rows = []
for r in rows:
    if r.get("state") in ("pending", "running"):
        print("    %s  %s  workflow=%s" % (r.get("id"), r.get("state"), r.get("workflow_id")))
' 2>/dev/null
      return 1
    fi
    sleep 0.5
  done
}

# Delete exactly this prefix's six agents through the product's own endpoint.
# --force is kept because it is what the endpoint accepts, NOT because it
# bypasses the live-run refusal; halt_live_runs_of above is what makes the
# delete legal. Quiet unless something goes wrong, so `up` can call it to make
# itself repeatable.
remove_demo_agents() {
  local quiet="${1:-}" targets="${2:-$DEMO_AGENTS}" errf failed=0
  errf="$(mktemp)"
  for a in $targets; do
    if ! halt_live_runs_of "$a"; then
      failed=1
      echo "  could not quiesce $a; not deleting it"
      continue
    fi
    # --allow 404: absent is a fine answer for a teardown. Anything else non-2xx
    # is a real failure, and its explanation is SHOWN rather than re-parsed out
    # of prose -- grepping stderr for 'HTTP 404' would also match a 502 whose
    # error body happens to quote one.
    if api DELETE "/agents/$a?force=true" --allow 404 >/dev/null 2>"$errf"; then
      [ -n "$quiet" ] || echo "  removed $a (or it was already gone)"
    else
      failed=1
      echo "  could not delete $a:"
      sed 's/^/    /' "$errf"
    fi
  done
  rm -f "$errf"
  return "$failed"
}

# Resolve the approved definition through the registry API, then create a
# prefixed runtime INSTANCE bound to its immutable ID. The server applies the
# registry ceiling in the same database INSERT as the binding; the demo never
# copies or authors policy and never calls the legacy ceiling endpoint.
provision_registry_agent() {
  local role="$1" registry_id runtime_name="${PREFIX}$1" resolution
  registry_id=$(printf '%s' "$REGISTRY_CATALOG" | "$PY" -c '
import json, sys
name = sys.argv[1]
matches = [item["agent_id"] for item in json.load(sys.stdin).get("agents", [])
           if item.get("name") == name]
if len(matches) != 1:
    raise SystemExit(f"expected exactly one registry definition named {name!r}")
print(matches[0])
' "$role")
  resolution=$(api GET "/v1/registry/agents/$registry_id/resolve")
  printf '%s' "$resolution" | "$PY" -c '
import json, sys
expected_id, expected_name = sys.argv[1:3]
value = json.load(sys.stdin)
if value.get("agent_id") != expected_id or value.get("name") != expected_name:
    raise SystemExit("registry resolution does not match requested definition")
' "$registry_id" "$role"
  api POST /agents --data \
    "{\"name\":\"$runtime_name\",\"description\":\"registry:$registry_id\",\"registry_agent_id\":\"$registry_id\"}" \
    >/dev/null
  CREATED_AGENTS="$CREATED_AGENTS $runtime_name"
}

cleanup_failed_up() {
  trap - ERR
  # ERR is inherited by command-substitution subshells under `set -E`. Let the
  # original failure reach the top-level shell so cleanup happens exactly once.
  [ "${BASH_SUBSHELL:-0}" -eq 0 ] || return 0
  if [ "$REAL" = "1" ]; then
    echo "authority demo setup failed; removing this prefix's partial instances" >&2
    [ -z "$CREATED_AGENTS" ] || remove_demo_agents quiet "$CREATED_AGENTS" || true
  else
    echo "authority demo setup failed; stopping and removing its scratch server" >&2
    if stop_scratch_server; then
      # Only erase a directory this invocation marked as its own scratch state.
      [ -f "$DEMO_SENTINEL" ] && rm -rf "$ANDYUR_DATA_DIR"
    else
      echo "preserving scratch state because its server did not stop safely" >&2
    fi
  fi
}

json_token_field() {
  local field="$1"
  "$PY" -c '
import json, sys
field = sys.argv[1]
value = json.load(sys.stdin).get(field)
if not isinstance(value, str) or not value:
    raise SystemExit(f"response has no non-empty {field}")
print(value)
' "$field"
}

# agent, scope, pin -> run token for a live run of that agent.
#
# The actor rides on the trigger with everything else. In production it is the
# `sub` from the user's OIDC login instead, and this field is refused rather than
# merged (see ./run.sh user-idp for that path against a real Keycloak) -- the
# tour is about the MINT, not about standing up an identity provider.
live_run() {
  local agent="$1" scope="$2" pin="$3" resp rid errf
  # stderr goes to its OWN file, never folded into the success value: an
  # interpreter warning on fd 2 would otherwise corrupt the JSON and abort an
  # `up` whose runs the server actually created. Shown only on failure, where
  # it is the server's own explanation of why.
  errf="$(mktemp)"
  if ! resp=$(api POST "/agents/$agent/trigger" \
         --data "{\"reason\":\"authority demo\",\"acting_user\":\"alice\",\"scope\":$scope,\"subject_context\":$pin}" \
         2>"$errf"); then
    echo "could not start a run for '$agent': $(cat "$errf")" >&2
    rm -f "$errf"; return 1
  fi
  rid=$(printf '%s' "$resp" | "$PY" -c 'import sys,json;print(json.load(sys.stdin).get("run_id",""))' 2>/dev/null || true)
  if [ -z "$rid" ]; then
    echo "could not start a run for '$agent': $resp" >&2
    rm -f "$errf"; return 1
  fi
  if ! resp=$(api POST "/runs/$rid/token" 2>"$errf"); then
    echo "could not mint a run token for '$agent': $(cat "$errf")" >&2
    rm -f "$errf"; return 1
  fi
  rm -f "$errf"
  printf '%s' "$resp" | json_token_field run_token 2>/dev/null \
    || { echo "could not mint a run token for '$agent': $resp" >&2; return 1; }
}

case "$CMD" in
  decode)
    # No signature check: this is for READING a token you were just handed, not
    # for trusting one. The resource server is the party that verifies.
    "$PY" - "$DECODE_ARG" <<'PYEOF'
import base64, json, sys
part = sys.argv[1].split(".")[1]
print(json.dumps(json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))), indent=2))
PYEOF
    ;;

  down)
    if [ "$REAL" = "1" ]; then
      require_operator          # this branch DELETEs through the API
      remove_demo_agents
      echo "your Andyur is otherwise untouched (./run.sh reset clears everything)"
    else
      require_scratch_ownership
      stop_scratch_server
      rm -rf "$ANDYUR_DATA_DIR"
      echo "removed $ANDYUR_DATA_DIR"
    fi
    ;;

  up)
    require_operator
    command -v sqlite3 >/dev/null || { echo "this demo needs sqlite3 on PATH"; exit 1; }
    CREATED_AGENTS=""
    if [ "$REAL" = "1" ]; then
      curl -sf "$B/health" >/dev/null 2>&1 || {
        echo "no Andyur on $B. Start one with:"
        echo "    ANDYUR_AGENT_AUTH=on ./run.sh up"; exit 1; }
      echo "using your real Andyur at $B (data: $ANDYUR_DATA_DIR)"
      # Start from a known state. Without this, a second `up` with the same prefix
      # dies on the trigger: the agents already hold live runs, and an agent may
      # only have one. Scratch mode gets this for free by deleting its database.
      remove_demo_agents quiet
      trap cleanup_failed_up ERR
    fi
    if [ "$REAL" = "0" ]; then
    prepare_scratch_directory
    trap cleanup_failed_up ERR
    # Refuse an unknown listener. Killing whatever happens to own the configured
    # port would let a demo typo terminate an unrelated service.
    if port_held "$ANDYUR_PORT"; then
      echo "port $ANDYUR_PORT is already in use; choose another ANDYUR_PORT" >&2
      exit 1
    fi
    # From this point onward every failure must stop the process and remove the
    # private state, including startup/health failures before registry access.
    # The server runs under ITS role binary too: validating a caller's JWT-SVID
    # needs the trust bundle from the Workload API, and SPIRE only serves an
    # attested workload -- a framework-python server would 401 every operator.
    # Checked HERE because a missing binary backgrounds a "no such file" into
    # server.log and surfaces twelve seconds later as a generic failure.
    [ -x "$SERVER_PY" ] || {
      echo "no server role binary at $SERVER_PY (./run.sh spire-setup)"; exit 1; }
    PYTHONPATH="$SITE:$HERE" \
      "$SERVER_PY" -m uvicorn andyur.server.app:app \
      --host 127.0.0.1 --port "$ANDYUR_PORT" \
      > "$ANDYUR_DATA_DIR/server.log" 2>&1 &
    echo $! > "$PIDFILE"
    ps -p "$!" -o lstart= > "$PIDSTARTFILE"
    printf "starting the demo server"
    for _ in $(seq 1 40); do
      curl -sf "$B/health" >/dev/null 2>&1 && break; printf "."; sleep 0.3
    done; echo

    curl -sf "$B/health" >/dev/null || {
      echo "the server did not come up; see $ANDYUR_DATA_DIR/server.log"; exit 1; }
    fi

    # The harness is a registry CLIENT, never a second definition/policy source.
    # A failure at any later role cleans every exact prefixed instance created by
    # this invocation; unrelated names remain untouched.
    REGISTRY_CATALOG=$(api GET /v1/registry/agents)
    for role in $ROLES; do provision_registry_agent "$role"; done

    ALL='["files:read","files:write","payments:transfer"]'
    TOK_CLASSIFIER=$(live_run "${PREFIX}classifier" "$ALL" '{"account":"447"}')
    TOK_SPECIALIST=$(live_run "${PREFIX}specialist" "$ALL" '{"account":"447"}')
    TOK_ROAMER=$(live_run    "${PREFIX}roamer"    "$ALL" '{"account":"999"}')
    TOK_BYSTANDER=$(live_run "${PREFIX}bystander" "$ALL" '{"account":"447"}')

    # Two grants minted from the 447 run, for two different delegatees. Having a
    # grant per delegatee is what lets you test the holder check and the re-pin
    # check separately: the holder check fires first, so re-pinning can only be
    # demonstrated by the agent the grant was actually minted for.
    if [ -n "${ANDYUR_DEMO_TEST_EMPTY_ACCESS_TOKEN:-}" ]; then
      GRANT_SPECIALIST=$(printf '{"access_token":""}' | json_token_field access_token)
    else
      GRANT_SPECIALIST=$(curl -fsS -X POST "$B/oauth/token" \
      -H "X-Andyur-Run-Token: $TOK_CLASSIFIER" -H 'content-type: application/json' \
      -d '{"audience":"tool:bank","actor":"'${PREFIX}'specialist"}' \
      | json_token_field access_token)
    fi
    GRANT_ROAMER=$(curl -fsS -X POST "$B/oauth/token" \
      -H "X-Andyur-Run-Token: $TOK_CLASSIFIER" -H 'content-type: application/json' \
      -d '{"audience":"tool:bank","actor":"'${PREFIX}'roamer"}' \
      | json_token_field access_token)

    cat > "$ENVFILE" <<EOF
export B=$B
export ANDYUR_DEMO_PREFIX=$PREFIX
export TOK_CLASSIFIER=$TOK_CLASSIFIER
export TOK_SPECIALIST=$TOK_SPECIALIST
export TOK_ROAMER=$TOK_ROAMER
export TOK_BYSTANDER=$TOK_BYSTANDER
export GRANT_SPECIALIST=$GRANT_SPECIALIST
export GRANT_ROAMER=$GRANT_ROAMER
EOF
    trap - ERR

    if [ "$REAL" = "1" ]; then
      REAL_FLAG=" --real"
      TEARDOWN="deletes the six ${PREFIX} agents and nothing else"
    else
      REAL_FLAG=""
      TEARDOWN="stops the demo server and removes $ANDYUR_DATA_DIR"
    fi
    cat <<EOF

the authority demo is up on $B

  agent                    ceiling                   its run is pinned to
  ${PREFIX}classifier      actions: files:read       account 447
  ${PREFIX}specialist      (unset = unrestricted)    account 447
  ${PREFIX}roamer          (unset = unrestricted)    account 999
  ${PREFIX}bystander       (unset = unrestricted)    account 447
  ${PREFIX}teller          audiences: tool:bank      (no run)
  ${PREFIX}muzzled         actions: []  (deny all)   (no run)
  ${PREFIX}ghost           does not exist at all

Every agent carries the '${PREFIX}' prefix, and \`down\` deletes exactly those six
names. Run a second copy beside this one with --prefix <something-else>.

Every run acts for alice and is entitled to files:read, files:write and
payments:transfer. So in the runbook, anything that comes back NARROWER than
that was narrowed by a ceiling or by the pin, never by the entitlement.

Load the tokens into your shell:

    source $ENVFILE

Then walk docs/authority-runbook.md. Read a minted token with:

    ./run.sh authority-demo decode \$GRANT_SPECIALIST

Stop it with ($TEARDOWN):

    ./run.sh authority-demo down$REAL_FLAG
EOF
    ;;

  *) echo "usage: ./run.sh authority-demo [up|down|decode <jwt>]"; exit 1 ;;
esac
