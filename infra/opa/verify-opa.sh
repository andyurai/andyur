#!/usr/bin/env bash
# Slice 2 proof: the external PDP (OPA behind an AuthZEN shim) returns EXACTLY
# the same decisions as the builtin PDP, for every case the test suite covers.
#
# The claim being tested is "the decision moved, the behaviour did not". So we
# run the same inputs through both and diff. A single disagreement fails.
#
# Since slice 4 this runs against the HARDENED stack (signed bundle, token auth,
# deny-by-default engine API). That is deliberate: an equivalence proved against
# a permissive dev deployment would not tell you the production one agrees.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./opa-stack.sh
source "$HERE/opa-stack.sh"
trap opa_stack_down EXIT

opa_stack_up "$HERE"
echo "    shim advertising: $(curl -s "http://127.0.0.1:$SHIM_PORT/.well-known/authzen-configuration" | tr -d '\n')"

echo "==> comparing builtin vs authzen over every case"
cd "$ROOT"
ANDYUR_PDP_URL="http://127.0.0.1:$SHIM_PORT" "$VENV/bin/python" - <<'PY'
import itertools, sys
from andyur import config
from andyur.server import pdp

CASES = []
# run subject: operator, null scope, "*", a granted action, a withheld action
for is_op, scope in itertools.product(
        [False, True],
        [None, ["*"], ["files:read"], ["files:read", "tasks:write"], []]):
    for action in ["files:read", "files:write", "tasks:write", "messages:write"]:
        CASES.append((pdp.Subject(type="run", id="r1", is_operator=is_op, scope=scope),
                      action))
# user subject: entitlement variations
for ent in [["*"], ["files:read"], ["files:read", "files:write"], []]:
    for action in ["files:read", "files:write", "email:send"]:
        CASES.append((pdp.Subject(type="user", entitlements=ent), action))
# unknown subject type must deny in both
CASES.append((pdp.Subject(type="mystery"), "files:read"))

fails = []
for subject, action in CASES:
    config.PDP = "builtin"
    want = pdp.evaluate(subject, action)
    config.PDP = "authzen"
    got = pdp.evaluate(subject, action)
    if want != got:
        fails.append((subject, action, want, got))

print(f"    {len(CASES)} cases compared")
for subject, action, want, got in fails:
    print(f"    MISMATCH {subject} action={action}: builtin={want} authzen={got}")
if fails:
    sys.exit(1)

# and the batch path, which is the one the grant uses
config.PDP = "builtin"
b = pdp.evaluate_all(pdp.Subject(type="user", entitlements=["files:read"]),
                     ["files:read", "files:write"])
config.PDP = "authzen"
a = pdp.evaluate_all(pdp.Subject(type="user", entitlements=["files:read"]),
                     ["files:read", "files:write"])
assert b == a == [True, False], f"batch mismatch: builtin={b} authzen={a}"
print("    batch path agrees too")
PY

echo "==> the decider now explains itself (AuthZEN reason_admin)"
reason=$(curl -s -X POST "http://127.0.0.1:$SHIM_PORT/access/v1/evaluation" \
  -H 'Content-Type: application/json' -d '{
    "subject":{"type":"run","id":"r1","properties":{"is_operator":false,"scope":["files:read"]}},
    "action":{"name":"files:write"},
    "resource":{"type":"andyur","id":"andyur"},
    "context":{"time":"2026-07-21T14:00:00Z"}}')
echo "    $reason"
echo "$reason" | grep -q 'reason_admin' || { echo "    no reason_admin in the denial"; exit 1; }

echo "==> proving fail-closed: stop the PDP, expect deny"
kill "$SHIM_PID" 2>/dev/null || true
SHIM_PID=""
sleep 1
cd "$ROOT"
ANDYUR_PDP_URL="http://127.0.0.1:$SHIM_PORT" "$VENV/bin/python" - <<'PY'
from andyur import config
from andyur.server import pdp
config.PDP = "authzen"
# An operator, who the builtin PDP always permits. With the PDP unreachable the
# answer must still be deny: unavailable is not permitted.
assert pdp.evaluate(pdp.Subject(type="run", is_operator=True), "files:read") is False
print("    PDP down -> denied (fail closed)")
PY

echo
echo "ALL CHECKS PASSED"
