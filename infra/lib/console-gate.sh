#!/usr/bin/env bash
# Shared by the console live gates (infra/verify-console.sh and
# infra/verify-console-modes.sh): assertion helpers and the one way to turn a
# console's launch URL into a session secret, exactly as the page does.
# Source this file; it defines functions and the FAILURES/PASSES counters.
FAILURES=0; PASSES=0
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASSES=$((PASSES+1)); }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES+1)); }
want(){ [ "$2" = "$1" ] && ok "$3 -> $2" || bad "$3: expected '$1' got '$2'"; }
code(){ curl -s -o /dev/null -w "%{http_code}" "$@"; }
# The `reason` name in a BFF refusal body; empty when there is none.
reason(){ curl -s "$@" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p'; }
# Response header value (lower-cased name), empty when absent.
header(){ local name="$1"; shift; curl -s -D - -o /dev/null "$@" | tr -d '\r' | awk -v n="$name" 'tolower($1)==n":" {sub(/^[^:]*:[ ]*/,""); print; exit}'; }

# The launch token printed in a console's log (`?launch=`), empty if none.
console_launch_token(){ sed -n 's#.*?launch=##p' "$1" | head -1 | tr -d '[:space:]'; }
# POST /session with a launch token; prints the secret, empty on refusal.
console_exchange(){ # $1=base url $2=launch token
  curl -s -X POST -H 'content-type: application/json' -d "{\"launch\":\"$2\"}" \
    "$1/session" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p'
}
# The whole page fetched from a running console must pass the same inline
# check the unit test applies (andyur/console/pagecheck.py).
console_page_is_clean(){ # $1=base url $2=path to the venv python
  curl -s "$1/" | "$2" -m andyur.console.pagecheck
}
SESSION_HEADER="andyur-console-session"

# Microseconds since the epoch, the unit Jaeger's query API speaks. Recorded at
# the top of a gate so the read-back can be bounded to THAT gate's run.
console_now_us(){ python3 -c 'import time; print(int(time.time()*1_000_000))'; }

# Spans read back from the collector's query API (Jaeger, the stack's default):
# prints "<console reason> <trace id> <span start, us>" for every console span
# carrying andyur.console.reason that was emitted AT OR AFTER $3. Empty when the
# collector is unreachable or nothing was exported yet.
#
# BOUNDED TWICE, ON PURPOSE. `lookback` is IGNORED by the HTTP query API:
# lookback=1h and lookback=1s return the same 500 traces, so the previous form
# was not looking back an hour, it was unbounded -- every one of the nine
# reasons "read back" green against spans 8 h old with no console traffic in the
# last minute. Explicit start/end IS honoured, so that is the server-side bound;
# the client-side startTime filter is the second, because `limit` is applied
# within the window and a busy window could still hand back only older spans.
# The instance id a running console reports at /healthz -- the one process the
# gate started. Empty if the console does not report one.
console_instance_id(){ # $1=console base url
  curl -s -m 5 "$1/healthz" | sed -n 's/.*"instance_id":"\([^"]*\)".*/\1/p'
}

console_span_reasons(){ # $1=jaeger url $2=venv python $3=since (us) $4=instance id
  local since="$3" now
  now=$(console_now_us)
  local limit=1000
  curl -s -m 5 "$1/api/traces?service=andyur-console&limit=$limit&start=$since&end=$now" \
    | "$2" -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
since, want, limit = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
traces = d.get("data", [])
# CROWD-OUT IS NOT ABSENCE. `limit` keeps the NEWEST traces inside the window,
# so a busy window can return a full page that excludes ours -- and a caller
# that reads "no rows" as "the console exported nothing" reports a FALSE RED
# for a reason that was emitted. A saturated page says so instead.
if len(traces) >= limit:
    print("!saturated", len(traces), limit)
seen = set()
for t in traces:
    procs = t.get("processes", {})
    for s in t.get("spans", []):
        if int(s.get("startTime", 0)) < since:
            continue                      # older than this gate run: not evidence
        if want:
            tags = procs.get(s.get("processID"), {}).get("tags", [])
            if not any(g.get("key") == "service.instance.id" and g.get("value") == want
                       for g in tags):
                continue                  # another console process on this box
        for tag in s.get("tags", []):
            if tag.get("key") == "andyur.console.reason":
                seen.add((tag.get("value"), t["traceID"], int(s["startTime"])))
for r, tid, start in sorted(seen):
    print(r, tid, start)' "$since" "${4:-}" "$limit"
}
