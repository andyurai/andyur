#!/usr/bin/env bash
# PROVE the other half of the handshake: that a resource server REFUSES.
#
# Andyur mints narrow, audience-bound, pinned tokens. Until this ran, nothing
# checked any of it -- every constraint was self-asserted, and a token minted for
# one target was as good as a token minted for any other. This drives real
# Andyur-minted tokens at a real MCP server running the PEP from
# demos/authority-tool/ and asserts what it lets through and what it turns away.
#
#   ./run.sh resource-verify
#
# Exits non-zero if any case fails, so it can gate a release.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$HERE/infra/ports.sh"
VENV="$HERE/.venv"
PORT="${ANDYUR_TOOL_PORT:-8795}"
# ADR 002: an MCP tool's audience IS its canonical resource identifier, so this
# is derived from the port rather than being a second copy of the same fact.
AUD="${ANDYUR_TOOL_AUDIENCE:-http://127.0.0.1:${ANDYUR_TOOL_PORT:-8795}/mcp}"
WORK="$(mktemp -d)"
DEMO_DIR="${ANDYUR_DATA_DIR:-/tmp/andyur-authority-demo}"
PASS=0; FAIL=0

cleanup() {
  [ -n "${TOOL_PID:-}" ] && kill "$TOOL_PID" 2>/dev/null
  [ "${STARTED_DEMO:-0}" = "1" ] && bash "$HERE/infra/authority-demo.sh" down >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

check() { # name, expected-substring, actual
  if printf '%s' "$3" | grep -qF -- "$2"; then
    printf '  ok   %s\n' "$1"; PASS=$((PASS+1))
  else
    printf '  FAIL %s\n         wanted: %s\n         got:    %s\n' "$1" "$2" "${3:0:160}"
    FAIL=$((FAIL+1))
  fi
}

echo "resource PEP verification"
echo "-------------------------"

# The demo server gives us runs that are bound to a user, which the mint needs.
# NOTHING ELSE MAY HOLD THE PORT. The readiness loop below curls it, and curl
# succeeds against whatever answers -- so a stale server from an earlier run made
# six of seven checks pass against code that was NOT the code under test. Only an
# incidental log-grep failure stopped a full false green.
if port_held "$PORT"; then
  echo "port $PORT is already held by another process:"
  lsof -i "tcp:$PORT" | sed 's/^/  /'
  echo "refusing to verify -- the result would describe that process, not this code"
  exit 1
fi

if [ ! -f "$DEMO_DIR/tokens.env" ]; then
  echo "starting the authority demo (it supplies user-bound runs)"
  bash "$HERE/infra/authority-demo.sh" up >/dev/null 2>&1 || {
    echo "could not start the authority demo"; exit 1; }
  STARTED_DEMO=1
fi
if [ ! -f "$DEMO_DIR/tokens.env" ]; then
  echo "no tokens at $DEMO_DIR/tokens.env after starting the demo"
  echo "(set ANDYUR_DATA_DIR if the demo writes elsewhere)"
  exit 1
fi
# shellcheck disable=SC1091
source "$DEMO_DIR/tokens.env"

ANDYUR_SERVER_URL="$B" ANDYUR_TOOL_AUDIENCE="$AUD" ANDYUR_TOOL_PORT="$PORT" \
  "$VENV/bin/python" "$HERE/demos/authority-tool/tool_server.py" \
  >"$WORK/tool.log" 2>&1 &
TOOL_PID=$!
for _ in $(seq 1 40); do
  kill -0 "$TOOL_PID" 2>/dev/null || break
  curl -s -o /dev/null "http://127.0.0.1:$PORT/mcp" && break
  sleep 0.25
done
# FAIL FAST if our own server died. Without this the checks run against whatever
# else answers the port, and a bind failure reads as a passing verification.
if ! kill -0 "$TOOL_PID" 2>/dev/null; then
  echo "the tool server exited before serving:"
  sed 's/^/  /' "$WORK/tool.log"
  exit 1
fi
echo "tool server on :$PORT enforcing audience $AUD, andyur at $B"
echo

OUT="$("$VENV/bin/python" "$HERE/infra/resource_pep_probe.py" 2>&1)"
echo "$OUT" | sed 's/^/  /'
echo

check "a token minted for this server is accepted"        "ACCEPTED whoami"        "$OUT"
check "the pinned account is allowed"                     "ALLOWED balance(447)"   "$OUT"
check "a DIFFERENT account is refused by the pin"         "REFUSED balance(999)"   "$OUT"
check "an action above the grant is refused"              "REFUSED transfer"       "$OUT"
check "a token minted for ANOTHER target is refused"      "REJECTED wrong-audience" "$OUT"
check "a forged token is refused"                         "REJECTED garbage"       "$OUT"
check "the server said WHY it refused the audience"       "InvalidAudienceError"   "$(cat "$WORK/tool.log")"

echo
echo "----------------------------------------"
echo "passed: $PASS   failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then echo "RESOURCE PEP: FAILED"; exit 1; fi
echo "RESOURCE PEP: PASSED"
echo
echo "What this proves: a token is only spendable at the target it names, only"
echo "for the actions it was granted, and only against the resource it was"
echo "pinned to -- enforced by the RESOURCE, not by Andyur's word for it."
echo "Still bearer: cnf is not minted, so possession remains sufficient."
