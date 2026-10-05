#!/usr/bin/env bash
# Slice 3: authorization changes with no redeploy.
#
# Nothing about Andyur changes during this script. No restart, no rebuild, no
# code edit. A policy module is published and the SAME request flips from
# permit to deny; publish the original again and it flips back.
#
# Since slice 4 the change arrives as a SIGNED BUNDLE that OPA pulls, not as a
# PUT to OPA's write API. That API is now refused for every caller, including
# the one holding the engine's own token, because an inbound path that can
# rewrite policy is a path an attacker can use to rewrite policy. Moving the
# change to a pull keeps the property that made this demo worth building --
# authorization is data, not code -- while removing the hole it used to rely on.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./opa-stack.sh
source "$HERE/opa-stack.sh"
trap opa_stack_down EXIT

# A single run, granted files:write, asking to write. Only the time varies.
ask () {  # $1 = ISO time, prints "PERMIT" or "DENY"
  local d
  d=$(curl -s -X POST "http://127.0.0.1:$SHIM_PORT/access/v1/evaluation" \
    -H 'Content-Type: application/json' -d "{
      \"subject\":{\"type\":\"run\",\"id\":\"r1\",
                   \"properties\":{\"is_operator\":false,
                                   \"scope\":[\"files:read\",\"files:write\"]}},
      \"action\":{\"name\":\"files:write\"},
      \"resource\":{\"type\":\"andyur\",\"id\":\"andyur\"},
      \"context\":{\"time\":\"$1\"}}" | tr -d ' ')
  case "$d" in
    *'"decision":true'*)  echo "PERMIT" ;;
    *'"decision":false'*) echo "DENY" ;;
    *) echo "?? ($d)" ;;
  esac
}

# Wait for a published bundle to be polled and activated, then report. Polling
# is what makes this safe: OPA reaches out on its own schedule, so the engine
# never needs an inbound mutation path.
wait_for () {  # $1 = expected verdict at 02:00 UTC
  for _ in $(seq 1 20); do
    [ "$(ask 2026-07-21T02:00:00Z)" = "$1" ] && return 0
    sleep 1
  done
  return 1
}

opa_stack_up "$HERE"

echo
echo "    a run granted files:write, asking to write:"
printf '      14:00 UTC  ->  %s\n' "$(ask 2026-07-21T14:00:00Z)"
printf '      02:00 UTC  ->  %s\n' "$(ask 2026-07-21T02:00:00Z)"

echo
echo "==> publishing a business-hours restriction as a signed bundle"
mkdir -p "$OPA_WORK/next" && cp "$HERE/policy.rego" "$HERE/business-hours.rego" "$OPA_WORK/next/"
opa_build_bundle "$OPA_WORK/next"
wait_for DENY || { echo "    bundle never activated"; exit 1; }
echo "    activated. Andyur was not restarted, rebuilt, or edited."

echo
echo "    the same run, the same request:"
printf '      14:00 UTC  ->  %s\n' "$(ask 2026-07-21T14:00:00Z)"
printf '      02:00 UTC  ->  %s\n' "$(ask 2026-07-21T02:00:00Z)"
printf '      02:00 UTC, files:READ (not a write)  ->  %s\n' \
  "$(curl -s -X POST "http://127.0.0.1:$SHIM_PORT/access/v1/evaluation" \
      -H 'Content-Type: application/json' -d '{
        "subject":{"type":"run","id":"r1","properties":{"is_operator":false,"scope":["files:read","files:write"]}},
        "action":{"name":"files:read"},"resource":{"type":"andyur","id":"andyur"},
        "context":{"time":"2026-07-21T02:00:00Z"}}' | grep -q '"decision":true' && echo PERMIT || echo DENY)"

echo
echo "==> publishing the base policy again (the restriction is withdrawn)"
mkdir -p "$OPA_WORK/back" && cp "$HERE/policy.rego" "$OPA_WORK/back/"
opa_build_bundle "$OPA_WORK/back"
wait_for PERMIT || { echo "    rollback never activated"; exit 1; }
printf '      02:00 UTC  ->  %s\n' "$(ask 2026-07-21T02:00:00Z)"

echo
echo "Authorization changed twice. Andyur never moved, and the engine never"
echo "exposed a way to write to it."
