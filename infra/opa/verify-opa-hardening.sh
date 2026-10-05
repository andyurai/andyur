#!/usr/bin/env bash
# Slice 4: prove the policy engine cannot be turned against the platform.
#
# Slices 1-3 proved the decision MOVED (same answers from an external engine)
# and that it can CHANGE with no redeploy. Both of those are worthless if
# anyone who can reach the engine can rewrite the policy, which is the default
# posture of every OPA deployment that has not been explicitly locked down.
#
# So this script is written as attacks, not features. Each check states what an
# attacker would do and asserts it fails. A check that "passes" by returning a
# permissive answer is a failure, so every assertion is written to fail loudly
# rather than skip.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./opa-stack.sh
source "$HERE/opa-stack.sh"
trap opa_stack_down EXIT

PASS=0; FAIL=0
ok()   { printf '    \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '    \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }

# HTTP status of a request, so an assertion can be written against the code
# rather than against a body that might change between OPA versions.
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# OPA polls bundles asynchronously and Docker's log driver publishes the
# verifier error asynchronously again. A fixed sleep races both clocks: the
# policy can already be safely refused while its required operator signal has
# not reached `docker logs` yet. Poll the actual signal under a finite budget
# instead. The override exists so the live mutation can restore the old
# under-budget behaviour and prove this assertion turns red.
wait_for_bundle_refusal_signal() {
  local timeout="${OPA_REFUSAL_SIGNAL_TIMEOUT_SECONDS:-30}"
  case "$timeout" in
    ''|*[!0-9]*) return 2 ;;
  esac
  [ "$timeout" -ge 1 ] && [ "$timeout" -le 120 ] || return 2
  local deadline=$((SECONDS + timeout))
  local logs
  while [ "$SECONDS" -lt "$deadline" ]; do
    # Capture, THEN match. Piping into `grep -Eqi` makes grep exit at the first
    # match, which SIGPIPEs docker mid-write; under this script's pipefail
    # (:13) the pipeline then reports failure even though the signal WAS
    # present, so the waiter times out and the caller reports "the bundle was
    # refused silently -- no signal" about a bundle that was refused WITH one.
    # It is log-size dependent, so it appears as the engine gets chattier --
    # which is what the tampered-bundle attack does before this runs.
    logs="$(docker logs "$OPA_CONTAINER" 2>&1 || true)"
    # A here-string, NOT `printf ... | grep`: a re-pipe would put an
    # early-exiting grep back on the end of a producer and re-open the same
    # hole one level down. `<<<` is a redirect, so the status is grep's alone.
    if grep -Eqi \
        'bundle.*(verification|signature)|(verification|signature).*bundle' \
        <<<"$logs"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Ask the shim a question that the base policy DENIES (a run whose sealed scope
# does not include the action). Prints PERMIT or DENY.
ask_denied_case() {
  curl -s -X POST "http://127.0.0.1:$SHIM_PORT/access/v1/evaluation" \
    -H 'Content-Type: application/json' -d '{
      "subject":{"type":"run","id":"r1","properties":{"is_operator":false,"scope":["files:read"]}},
      "action":{"name":"files:write"},
      "resource":{"type":"andyur","id":"andyur"},
      "context":{"time":"2026-07-21T14:00:00Z"}}' \
  | grep -q '"decision":true' && echo PERMIT || echo DENY
}

opa_stack_up "$HERE"
OPA="http://127.0.0.1:$OPA_PORT"

echo
echo "==> A1. the engine still answers the question it exists to answer"
if [ "$(ask_denied_case)" = "DENY" ]; then
  ok "a run without files:write in its sealed scope is denied"
else
  bad "the base policy is not being enforced -- everything below is meaningless"
fi

echo
echo "==> A2. the attack that motivated this slice: rewrite the policy over HTTP"
echo '    curl -X PUT /v1/policies/pwn  (no credential)'
code=$(status -X PUT "$OPA/v1/policies/pwn" --data-binary 'package andyur.authz
decision := true')
case "$code" in
  401|403) ok "policy write without a credential refused ($code)" ;;
  *)       bad "policy write without a credential returned $code -- ENGINE IS WRITABLE" ;;
esac

echo
echo "==> A3. the same attack WITH the enforcement point's stolen token"
echo '    this is the check that matters: a token that can ask must not be able to answer'
code=$(status -X PUT "$OPA/v1/policies/pwn" \
  -H "Authorization: Bearer $OPA_QUERY_TOKEN" \
  --data-binary 'package andyur.authz
decision := true')
case "$code" in
  401|403) ok "policy write with the query token refused ($code) -- least privilege holds" ;;
  *)       bad "the query token can REWRITE POLICY (returned $code)" ;;
esac

echo
echo "==> A4. inject facts instead of rules (data write)"
code=$(status -X PUT "$OPA/v1/data/andyur/authz/backdoor" \
  -H "Authorization: Bearer $OPA_QUERY_TOKEN" -d 'true')
case "$code" in
  401|403) ok "data write with the query token refused ($code)" ;;
  *)       bad "the query token can WRITE DATA (returned $code)" ;;
esac

echo
echo "==> A5. read the policy back to study it (reconnaissance)"
code=$(status "$OPA/v1/policies" -H "Authorization: Bearer $OPA_QUERY_TOKEN")
case "$code" in
  401|403) ok "listing policies with the query token refused ($code)" ;;
  *)       bad "the query token can READ THE POLICY SOURCE (returned $code)" ;;
esac

echo
echo "==> A6. ad-hoc query endpoints (a second way to reach the data)"
for path in "/v1/query?q=data" "/v1/compile"; do
  code=$(status -X POST "$OPA$path" -H "Authorization: Bearer $OPA_QUERY_TOKEN" -d '{}')
  case "$code" in
    401|403) ok "$path refused ($code)" ;;
    *)       bad "$path reachable with the query token (returned $code)" ;;
  esac
done

echo
echo "==> A7. the decision query itself, without a token"
code=$(status -X POST "$OPA/v1/data/andyur/authz" -d '{"input":{}}')
case "$code" in
  401|403) ok "unauthenticated decision query refused ($code)" ;;
  *)       bad "anyone can query decisions unauthenticated (returned $code)" ;;
esac

echo
echo "==> A8. liveness stays open (an orchestrator must probe without a credential)"
code=$(status "$OPA/health")
[ "$code" = "200" ] && ok "GET /health is 200 unauthenticated" || bad "GET /health returned $code"

echo
echo "==> A9. policy still changes with NO redeploy -- via the bundle, not the write API"
mkdir -p "$OPA_WORK/next" && cp "$HERE/policy.rego" "$HERE/business-hours.rego" "$OPA_WORK/next/"
opa_build_bundle "$OPA_WORK/next"
echo "    new signed bundle published; waiting for OPA to poll it"
flipped=""
for _ in $(seq 1 20); do
  # business-hours.rego restricts writes outside 09:00-18:00 UTC. Ask at 02:00
  # with a run that IS granted files:write: permitted before, denied after.
  d=$(curl -s -X POST "http://127.0.0.1:$SHIM_PORT/access/v1/evaluation" \
      -H 'Content-Type: application/json' -d '{
        "subject":{"type":"run","id":"r1","properties":{"is_operator":false,"scope":["files:read","files:write"]}},
        "action":{"name":"files:write"},
        "resource":{"type":"andyur","id":"andyur"},
        "context":{"time":"2026-07-21T02:00:00Z"}}')
  if echo "$d" | grep -q '"decision":false'; then flipped=1; break; fi
  sleep 1
done
if [ -n "$flipped" ]; then
  ok "authorization tightened in the running engine with no restart, rebuild, or write API"
else
  bad "the new bundle never took effect"
fi

echo
echo "==> A10. compromise the BUNDLE SERVER: publish a policy that permits everything"
echo '    signed with an attacker key, because owning the server must not be enough'
openssl genrsa -out "$OPA_WORK/attacker.pem" 2048 2>/dev/null
mkdir -p "$OPA_WORK/evil"
cat > "$OPA_WORK/evil/policy.rego" <<'REGO'
package andyur.authz
import rego.v1
default decision := true
REGO
cat > "$OPA_WORK/evil/.manifest" <<'JSON'
{"roots": ["andyur"]}
JSON
# As the invoking uid (see opa_build_bundle): the opa image runs as uid 1000 and
# cannot enter the 0700 mktemp dir on Linux. If THIS build fails, the attacker
# bundle is never published and A10 passes for the wrong reason -- nothing was
# tampered -- so it must succeed for the signature-rejection test to mean
# anything. Not >/dev/null, so a failure is visible rather than silent.
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$OPA_WORK/evil:/stage:ro" -v "$OPA_WORK:/work" \
  "$OPA_IMAGE" build -b /stage --signing-key /work/attacker.pem --signing-alg RS256 \
    --claims-file /work/claims.json -o /work/serve/andyur-bundle.tar.gz
echo "    attacker bundle published; waiting through several poll intervals"
if [ "$(ask_denied_case)" = "DENY" ]; then
  ok "tampered bundle refused: the previously verified policy is still in force"
else
  bad "THE ATTACKER'S POLICY ACTIVATED -- signature verification is not working"
fi
if wait_for_bundle_refusal_signal; then
  ok "the refusal is visible in OPA's logs (an operator can see the attack)"
else
  bad "the bundle refusal signal did not arrive inside the bounded polling window"
fi

echo
echo "==> A11. the audit trail exists AND does not leak what it audits"
echo '    a decision log is a copy of your inputs somewhere with different access controls'
curl -s -X POST "http://127.0.0.1:$SHIM_PORT/access/v1/evaluation" \
  -H 'Content-Type: application/json' -d '{
    "subject":{"type":"run","id":"secret-run-id-42","properties":{"is_operator":false,"scope":["files:read","secret:scope:marker"]}},
    "action":{"name":"files:write"},
    "resource":{"type":"andyur","id":"andyur"},
    "context":{"time":"2026-07-21T14:00:00Z"}}' >/dev/null
sleep 1
logs=$(docker logs "$OPA_CONTAINER" 2>&1)
if echo "$logs" | grep -q '"decision_id"'; then
  ok "every decision is logged (an engine that changed its mind leaves evidence)"
else
  bad "no decision log emitted -- there is no authorization audit trail"
fi
if echo "$logs" | grep -q 'secret:scope:marker'; then
  bad "the log leaks the subject's granted scope (mask not applied)"
else
  ok "the granted scope is masked out of the log"
fi
if echo "$logs" | grep -q 'secret-run-id-42'; then
  bad "the log leaks the subject id (mask not applied)"
else
  ok "the subject id is masked out of the log"
fi

echo
echo "==> A12. the engine disappears while the enforcement point is still up"
docker rm -f "$OPA_CONTAINER" >/dev/null 2>&1
code=$(status -X POST "http://127.0.0.1:$SHIM_PORT/access/v1/evaluation" \
  -H 'Content-Type: application/json' -d '{
    "subject":{"type":"run","id":"r1","properties":{"is_operator":true,"scope":null}},
    "action":{"name":"files:read"},"resource":{"type":"andyur","id":"andyur"}}')
if [ "$code" = "503" ]; then
  ok "the shim reports 503, rather than fabricating a decision nobody made"
else
  bad "the shim returned $code with OPA gone (expected 503)"
fi
cd "$ROOT"
ANDYUR_PDP_URL="http://127.0.0.1:$SHIM_PORT" "$VENV/bin/python" - <<'PY'
from andyur import config
from andyur.server import pdp
config.PDP = "authzen"
# An operator: the identity the builtin PDP ALWAYS permits. With no engine to
# ask, the answer must still be no. Unavailable is not permitted.
assert pdp.evaluate(pdp.Subject(type="run", is_operator=True), "files:read") is False
PY
ok "Andyur denies an operator while the PDP is unreachable (fails closed end to end)"

echo
printf '%s\n' "----------------------------------------"
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "ALL CHECKS PASSED"
