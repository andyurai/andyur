#!/usr/bin/env bash
# LIVE gate for the operator console BFF. Assumes the control plane is up
# (./run.sh up). Starts the console as the operator role binary, then drives
# the real BFF over HTTP: the launch token must exchange exactly once for the
# session secret, every fence (no secret, cross-origin, wrong Host, dot
# segment, off-allowlist route or method, oversized body) must refuse BY NAME
# with the protocol headers the status requires, the served page must pass
# the same inline check the unit tests apply, and catalog -> create -> trigger
# -> delete must work through the proxy. A REAL gate: any failed assertion
# exits nonzero.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Telemetry ON is the deployed default and an exit criterion: the refusals
# this gate provokes are read back from the collector at the end.
export ANDYUR_OTEL=on
JAEGER="${ANDYUR_JAEGER_UI:-http://localhost:16686}"
# THE INTERPRETER THIS GATE RUNS UNDER, resolvable from a checkout that is not
# this one. It was hard-wired to "$HERE/.venv/bin/python", so a reviewer who
# extracted the tree at a frozen SHA to re-run the gate got the ORIGINAL
# checkout's venv or nothing at all (ROADMAP.md 31). An exported
# VIRTUAL_ENV wins, then this tree's own venv, then whatever `python3` is.
PY="${ANDYUR_PY:-}"
if [ -z "$PY" ] && [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
  PY="$VIRTUAL_ENV/bin/python"
fi
[ -z "$PY" ] && [ -x "$HERE/.venv/bin/python" ] && PY="$HERE/.venv/bin/python"
[ -z "$PY" ] && PY="$(command -v python3 || true)"
[ -x "$PY" ] || { echo "no usable python: set ANDYUR_PY to one"; exit 1; }
. "$HERE/infra/lib/console-gate.sh"
PORT="${CONSOLE_PORT:-8651}"
BASE="http://127.0.0.1:$PORT"

command -v curl >/dev/null || { echo "curl required"; exit 1; }
# The control plane the console will proxy, resolved by the same code the
# console uses (ANDYUR_SERVER_URL, else ANDYUR_HOST/ANDYUR_PORT, https under
# ANDYUR_MTLS), so the precheck cannot disagree with the console.
CP=$("$PY" -c 'from andyur.config import SERVER_URL; print(SERVER_URL)')
case "$CP" in https://*) echo "this gate probes plain HTTP; under ANDYUR_MTLS use ./run.sh console-modes"; exit 1;; esac
# Same reason, for the other mode this gate cannot drive: under user-auth the
# console blocks on the IdP login before it prints a usable session, and this
# gate then reported "no launch token" after fifteen seconds -- a true statement
# about the wrong thing. Say which gate covers that instead of timing out.
if [ "$("$PY" -c 'from andyur import config; print("on" if config.USER_AUTH else "off")')" = "on" ]; then
  echo "ANDYUR_USER_AUTH is on: this gate drives the single-operator console."
  echo "The admin/user modes are proven by ./run.sh console-modes (real Keycloak)."
  exit 1
fi
curl -sf "$CP/health" >/dev/null 2>&1 \
  || { echo "control plane not up at $CP -- run ./run.sh up first"; exit 1; }
CAP=$("$PY" -c 'from andyur.console.server import MAX_BODY_BYTES; print(MAX_BODY_BYTES)')

# Stamped BEFORE the console starts, so the collector read-back at the end can
# be bounded to spans this run produced. A second of slack absorbs clock skew
# between this shell and the collector.
GATE_START=$(( $(console_now_us) - 1000000 ))

echo "== starting the console (operator-attested) =="
LOG="$HERE/data/logs/console-gate.log"; mkdir -p "$(dirname "$LOG")"
"$HERE/andyur-cli" console --no-browser --port "$PORT" >"$LOG" 2>&1 &
CONSOLE_PID=$!
trap 'kill "$CONSOLE_PID" 2>/dev/null; echo "(console stopped)"' EXIT
for _ in $(seq 1 30); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
TOKEN=$(console_launch_token "$LOG")
[ -n "$TOKEN" ] && ok "console up; captured the single-use launch token" \
  || { bad "no launch token in the launch log"; exit 1; }

echo "== the launch token exchanges exactly once =="
JT="-H content-type:application/json"
SECRET=$(console_exchange "$BASE" "$TOKEN")
[ -n "$SECRET" ] && ok "POST /session exchanged the token for a session secret" \
  || { bad "the exchange yielded no secret"; exit 1; }
if grep -qF "$SECRET" "$LOG"; then bad "the launch log carries the session secret"; else ok "the session secret never reached the launch log"; fi
want launch_spent "$(reason $JT -X POST -d "{\"launch\":\"$TOKEN\"}" "$BASE/session")" "second exchange refused by name"
want launch_unknown "$(reason $JT -X POST -d '{"launch":"guess"}' "$BASE/session")" "guessed token refused by name"
want cross_origin "$(reason $JT -X POST -d "{\"launch\":\"$TOKEN\"}" -H 'Origin: http://evil.example' "$BASE/session")" "cross-origin exchange refused"
want method_not_allowed "$(reason "$BASE/session")" "GET /session refused by name"
want POST "$(header allow "$BASE/session")" "  with Allow"
H=(-H "$SESSION_HEADER: $SECRET")

echo "== security fences (each refusal named) =="
want 200 "$(code "$BASE/healthz")"                              "healthz (no secret needed)"
want 401 "$(code "$BASE/api/agents")"                          "/api/agents WITHOUT the secret"
want bad_session "$(reason "$BASE/api/agents")"                "  reason"
want 'ConsoleSession realm="andyur-console"' "$(header www-authenticate "$BASE/api/agents")" "  with a WWW-Authenticate challenge"
want 401 "$(code -H "$SESSION_HEADER: wrong" "$BASE/api/agents")" "/api/agents WRONG secret"
want cross_origin "$(reason "${H[@]}" -H 'Origin: http://evil.example' "$BASE/api/agents")" "cross-origin refused"
want bad_host "$(reason "${H[@]}" -H "Host: evil.example:$PORT" "$BASE/api/agents")" "DNS-rebinding Host refused"
want bad_path "$(reason "${H[@]}" "$BASE/api/agents/%2E%2E")" "dot segment refused"
# /api/workers is ON the allowlist (the server admin-gates it under user-auth);
# ceiling WRITE, the token endpoint and unlisted methods are never console routes.
want not_a_console_route "$(reason "${H[@]}" -X PUT "$BASE/api/agents/foo/ceiling")" "off-allowlist ceiling write"
want not_a_console_route "$(reason "${H[@]}" -X POST "$BASE/api/oauth/token")"  "off-allowlist /api/oauth/token"
want not_a_console_route "$(reason "${H[@]}" -X PATCH "$BASE/api/agents")"      "unlisted method refused by name"
want not_a_console_route "$(reason "${H[@]}" -X OPTIONS "$BASE/api/agents")"    "preflight refused by name"
BIG=$(mktemp); head -c $((CAP+1)) /dev/zero >"$BIG"
want body_too_large "$(reason "${H[@]}" $JT -X POST --data-binary "@$BIG" "$BASE/api/agents")" "oversized body ($((CAP+1)) bytes) refused"
want close "$(header connection "${H[@]}" $JT -X POST --data-binary "@$BIG" "$BASE/api/agents")" "  and the connection is closed"
rm -f "$BIG"

echo "== the page carries nothing inline and the CSP forbids it =="
want 200 "$(code "$BASE/")" "the page is served"
want "text/html; charset=utf-8" "$(header content-type "$BASE/")" "  as HTML"
want "$("$PY" -c 'from andyur.console.server import _CSP; print(_CSP)')" "$(header content-security-policy "$BASE/")" "CSP is exactly the module's"
if console_page_is_clean "$BASE" "$PY"; then ok "served page passes the inline check (pagecheck)"; else bad "served page has inline script/style/handlers"; fi
if curl -s "$BASE/" | grep -qiE "bearer |spiffe://|$SECRET|$TOKEN"; then
  bad "served HTML leaks a credential/secret"; else ok "served HTML carries no credential/secret"; fi
want 200 "$(code "$BASE/app.js")"  "app.js served"
want 200 "$(code "$BASE/app.css")" "app.css served"
want no-store "$(header cache-control "${H[@]}" "$BASE/api/me")" "API responses are no-store"

echo "== the real flow through the BFF =="
want 200 "$(code "${H[@]}" "$BASE/api/v1/registry/agents")"   "catalog list proxied"
NAME="console_gate_$$"
# Body-carrying calls: build the JSON in a variable and post it with a single,
# un-nested curl (nesting -d '{json with spaces}' inside want "$(code ...)"
# splits the body on the comma/space -- a shell-quoting trap, not a proxy bug).
CBODY="{\"name\":\"$NAME\",\"description\":\"console gate\"}"
want 201 "$(curl -s -o /dev/null -w '%{http_code}' "${H[@]}" $JT -X POST -d "$CBODY" "$BASE/api/agents")" "create via console"
want 200 "$(code "${H[@]}" "$BASE/api/agents/$NAME")"         "detail via console"
TBODY='{"reason":"console gate"}'
want 201 "$(curl -s -o /dev/null -w '%{http_code}' "${H[@]}" $JT -X POST -d "$TBODY" "$BASE/api/agents/$NAME/trigger")" "trigger via console"
want 200 "$(code "${H[@]}" -X POST "$BASE/api/agents/$NAME/pause")"  "pause via console"
want 200 "$(code "${H[@]}" -X POST "$BASE/api/agents/$NAME/resume")" "resume via console"
want 200 "$(code "${H[@]}" -X DELETE "$BASE/api/agents/$NAME?force=true")" "delete via console (query forwarded)"

# ARM THE NEGATIVE CONTROL: a SECOND console process, inside the same time
# window, emitting the same kind of refusal. The read-back must not return it.
DECOY_LOG="$HERE/data/logs/console-gate-decoy.log"
DECOY_PORT=$(( PORT + 7 ))
"$HERE/andyur-cli" console --no-browser --port "$DECOY_PORT" >"$DECOY_LOG" 2>&1 &
DECOY_PID=$!
trap 'kill "$CONSOLE_PID" "$DECOY_PID" 2>/dev/null; echo "(console stopped)"' EXIT
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$DECOY_PORT/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
DECOY_INSTANCE=$(console_instance_id "http://127.0.0.1:$DECOY_PORT")
curl -s -o /dev/null -H "Origin: http://evil.example" \
  "http://127.0.0.1:$DECOY_PORT/api/agents" 2>/dev/null     # a real cross_origin refusal
DECOY_TRACE=""
for _ in $(seq 1 20); do
  DECOY_TRACE=$(console_span_reasons "$JAEGER" "$PY" "$GATE_START" "$DECOY_INSTANCE" \
                | awk '$1=="cross_origin"{print $2; exit}')
  [ -n "$DECOY_TRACE" ] && break
  sleep 1
done
[ -n "$DECOY_TRACE" ] && ok "negative control armed: a second console emitted a real refusal in this window (trace $DECOY_TRACE)" \
  || bad "negative control could NOT be armed: the decoy console's refusal never reached the collector"

echo "== the refusals above, read back from the collector =="
# BOUND TO THIS RUN. GATE_START is stamped before the first request, and the
# read-back asks the collector only for the window since then. Without it the
# query is unbounded -- Jaeger ignores `lookback` -- so every reason below
# passed against spans from a previous run and this block could not fail.
EXPECT="launch_spent launch_unknown cross_origin method_not_allowed bad_session bad_host bad_path not_a_console_route body_too_large"
TRACES="$HERE/data/logs/console-gate-traces.txt"
# BatchSpanProcessor exports on a 5 s schedule; poll rather than sleep once.
INSTANCE=$(console_instance_id "$BASE")
[ -n "$INSTANCE" ] && ok "read-back bound to THIS console process ($INSTANCE)" \
  || bad "the console reports no instance_id: the read-back can only be bound by time"
for _ in $(seq 1 30); do
  console_span_reasons "$JAEGER" "$PY" "$GATE_START" "$INSTANCE" >"$TRACES"
  missing=""
  for r in $EXPECT; do grep -q "^$r " "$TRACES" || missing="$missing $r"; done
  [ -z "$missing" ] && break
  sleep 1
done
# A saturated query window is INCONCLUSIVE, not empty: `limit` keeps the newest
# traces, so a busy collector can return a full page that excludes ours, and
# reading that as "nothing was exported" is a false RED.
if grep -q '^!saturated ' "$TRACES"; then
  bad "the collector query window was saturated ($(grep '^!saturated ' "$TRACES")); the read-back is INCONCLUSIVE, not failed -- narrow the window or raise the limit"
elif [ -s "$TRACES" ]; then
  for r in $EXPECT; do
    tid=$(awk -v r="$r" '$1==r {print $2; exit}' "$TRACES")
    start=$(awk -v r="$r" '$1==r {print $3; exit}' "$TRACES")
    if [ -n "$tid" ] && [ "${start:-0}" -ge "$GATE_START" ]; then
      ok "span with andyur.console.reason=$r read back from THIS run (trace $tid)"
    else
      bad "no span carrying andyur.console.reason=$r emitted since this gate started"
    fi
  done
  # NEGATIVE CONTROL, and it has to be one that CAN fail. The first version
  # asserted the absence of `upstream_timeout`; nothing in this repository ever
  # emits it, so its absence held whether or not the read-back bounded
  # anything. This one provokes a REAL refusal -- the same reason, in the same
  # window -- from a SECOND console process, which is the exact hazard the bound
  # exists for: `service=andyur-console` is shared by every console on the
  # machine, and three worktrees ran on this one in a day. If the decoy's trace
  # is read back, the read-back is not bound to this run and every PASS above is
  # answering for someone else's process.
  if [ -n "$DECOY_TRACE" ]; then
    if grep -q "$DECOY_TRACE" "$TRACES"; then
      bad "another console process's refusal was read back (trace $DECOY_TRACE): the read-back is NOT bound to this run"
    else
      ok "a second console's refusal in the same window is NOT read back (the bound is real)"
    fi
  else
    bad "the negative control could not be armed: no decoy refusal reached the collector"
  fi
  ok "trace ids recorded in $TRACES"
else
  bad "no console spans emitted since this gate started at $JAEGER (is Jaeger up? ./run.sh up starts it)"
fi

echo
if [ "$FAILURES" -eq 0 ]; then echo "console gate GREEN ($PASSES assertions)"; exit 0
else echo "console gate RED ($FAILURES failed)"; exit 1; fi
