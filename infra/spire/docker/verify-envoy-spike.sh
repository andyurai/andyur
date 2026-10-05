#!/usr/bin/env bash
# LIVE Envoy data-plane spike (ADR-004). Proves on the wire, against REAL Envoy
# + REAL SPIRE, the security properties the sidecar hand-rolled. This is a REAL
# GATE: any failed assertion increments FAILURES and the script EXITS NONZERO,
# and every check asserts an EXACT status/outcome (not merely "not ok").
# Usage: ./verify-envoy-spike.sh   (down to tear down)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
NET="andyur-spire-net"; TD="andyur.local"
SOCK_VOL="andyur-spire-sockets"; SOCK="unix:/run/spire/sockets/api.sock"
AUTHZ_VOL="andyur-authz-sock"; AUTHZ_UDS="/authzsock/authz.sock"
RUN_SVID="spiffe://$TD/agent/scout/run/r1"
TOOL_SVID="spiffe://$TD/tool/calendar"
WRONG_SVID="spiffe://$TD/tool/evil"
ENVOY_IMG="envoyproxy/envoy:v1.31-latest"; ANDYUR_IMG="andyur-server"

FAILURES=0; PASSES=0
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASSES=$((PASSES+1)); }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES+1)); }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }
# assert exact status: $1 expected, $2 actual, $3 label
want(){ [ "$2" = "$1" ] && ok "$3 -> $2 (as required)" || bad "$3: expected $1, got $2"; }

# Client: the agent ALWAYS supplies its own credentials (known AND arbitrary,
# to test the ALLOWLIST) and a JSON-RPC body. Prints "<status> <body>".
# $1 path (default /mcp) $2 method (default POST) $3 mcp tool (default read_calendar).
call(){ local path="${1:-/mcp}" method="${2:-POST}" tool="${3:-read_calendar}"; \
  docker run --rm --network "$NET" --entrypoint python "$ANDYUR_IMG" -c "
import httpx, json
body=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'$tool'}})
try:
    r=httpx.request('$method','http://andyur-envoy:15000$path',timeout=10,content=body,
        headers={'content-type':'application/json',
                 'x-andyur-run-token':'AGENT-RUNTOKEN','authorization':'Bearer AGENT-OWN',
                 'x-api-key':'k','cookie':'s=secret','proxy-authorization':'Basic x',
                 'x-custom-secret':'HUNTER2','x-vendor-session':'sess',
                 'traceparent':'00-FORGEDTRACE0000000000000000000-0000000000000001-01',
                 'x-envoy-internal':'true','x-forwarded-for':'6.6.6.6'})
    print(r.status_code, r.text[:1200])
except Exception as e: print('000', 'ERR', type(e).__name__, str(e)[:120])" 2>/dev/null; }
callm(){ local method_name="$1"; \
  docker run --rm --network "$NET" --entrypoint python "$ANDYUR_IMG" -c "
import httpx, json
body=json.dumps({'jsonrpc':'2.0','id':1,'method':'$method_name'})
try:
    r=httpx.post('http://andyur-envoy:15000/mcp',timeout=10,content=body,
        headers={'content-type':'application/json','x-andyur-run-token':'t'})
    print(r.status_code, r.text[:200])
except Exception as e: print('000','ERR',type(e).__name__)" 2>/dev/null; }
status(){ call "$@" | awk '{print $1}'; }

entry(){ local sid="$1"; shift; docker exec andyur-spire-server /opt/spire/bin/spire-server \
  entry create -parentID "spiffe://$TD/agent/node" -spiffeID "$sid" -x509SVIDTTL 3600 "$@" >/dev/null 2>&1 || true; }

teardown(){ docker rm -f andyur-tool andyur-tool-wrong andyur-authz andyur-envoy >/dev/null 2>&1 || true
  docker volume rm "$AUTHZ_VOL" >/dev/null 2>&1 || true
  bash "$HERE/verify-slice3.sh" down >/dev/null 2>&1 || true; }
if [ "${1:-up}" = "down" ]; then say "tearing down"; teardown; echo done; exit 0; fi
trap 'echo; echo "(stack left up; tear down: $0 down)"' EXIT
teardown
docker volume create "$AUTHZ_VOL" >/dev/null

# Capture-then-match. NEVER `docker logs X | grep -q PAT`: grep -q exits at the
# FIRST match, which SIGPIPEs docker while it is still writing, and under this
# script's pipefail the PIPELINE reports failure even though the pattern WAS
# found -- a healthy server read as down. Root-caused in 644b63f.
# Every call site passes a literal pattern, so case matching is equivalent.
wait_for(){ local c="$1" pat="$2" lg; for _ in $(seq 1 30); do \
  lg="$(docker logs "$c" 2>&1 || true)"; \
  case "$lg" in *"$pat"*) return 0 ;; esac; \
  docker ps -a --filter name="$c" --format '{{.Status}}' | grep -q Exited && break; sleep 1; done; \
  bad "$c not ready"; docker logs "$c" 2>&1 | tail -6; return 1; }

start_authz(){ # $1 = ALLOW, $2 = LIVE. Runs on a UDS shared only with Envoy.
  # Per-tool POLICY comes from the REAL manifest via the REAL registry parser
  # (mounted current code, not the baked image); only the run's already-
  # narrowed actions and liveness are injected (unit-tested against the real
  # sources). No tool list exists in the stub or this environment.
  docker rm -f andyur-authz >/dev/null 2>&1
  docker run -d --name andyur-authz --network "$NET" --label andyur.role=authz -e PYTHONPATH=/app \
    -e ANDYUR_SPIKE_ALLOW="$1" -e ANDYUR_SPIKE_LIVE="$2" -e ANDYUR_SPIKE_UDS="$AUTHZ_UDS" \
    -e ANDYUR_SPIKE_MANIFEST=/spike_manifest.json \
    -e ANDYUR_SPIKE_ACTIONS="calendar:read" \
    -e ANDYUR_SPIKE_CNF="${CNF:-0}" -e ANDYUR_SPIKE_CNF_WRONG="${CNF_WRONG:-0}" \
    -e ANDYUR_SPIKE_CNF_THUMB="${CNF_THUMB:-}" \
    -v "$ROOT/infra/envoy/authz_stub.py:/authz.py:ro" \
    -v "$ROOT/infra/envoy/spike_manifest.json:/spike_manifest.json:ro" \
    -v "$ROOT/andyur/dataplane:/app/andyur/dataplane:ro" \
    -v "$ROOT/andyur/registry:/app/andyur/registry:ro" \
    -v "$AUTHZ_VOL:/authzsock" \
    --entrypoint python "$ANDYUR_IMG" /authz.py >/dev/null
  wait_for andyur-authz "Uvicorn running" || exit 1; }

BOOT_DIR="/tmp/andyur-envoy-spike"; mkdir -p "$BOOT_DIR"
gen_and_run_envoy(){ # $1 = tool host, $2 = extra python to mutate `boot` (optional)
  docker rm -f andyur-envoy >/dev/null 2>&1 || true
  "$ROOT/.venv/bin/python" -c "
import yaml
from andyur.dataplane import envoyconfig
boot=envoyconfig.build_bootstrap(run_spiffe_id='$RUN_SVID',trust_domain='$TD',
  tool={'name':'calendar','host':'$1','port':8443,'path':'/mcp','expected_spiffe_id':'$TOOL_SVID'},
  listen_port=15000,authz_cluster='andyur-authz:9000',authz_socket='$AUTHZ_UDS')
${2:-}
open('$BOOT_DIR/bootstrap.yaml','w').write(yaml.safe_dump(boot))" || { bad "bootstrap gen failed"; return 1; }
  docker run -d --name andyur-envoy --network "$NET" --label andyur.run_id=r1 \
    -v "$SOCK_VOL:/run/spire/sockets:ro" -v "$BOOT_DIR/bootstrap.yaml:/boot.yaml:ro" \
    -v "$AUTHZ_VOL:/authzsock" \
    "$ENVOY_IMG" envoy -c /boot.yaml --service-node "$RUN_SVID" --service-cluster andyur-tool-egress >/dev/null
  for _ in $(seq 1 25); do envoy_lg="$(docker logs andyur-envoy 2>&1 || true)"; \
    case "$envoy_lg" in *"starting main dispatch loop"*) return 0 ;; esac; \
    docker ps -a --filter name=andyur-envoy --format '{{.Status}}' | grep -q Exited && break; sleep 1; done
  bad "envoy did not start"; docker logs andyur-envoy 2>&1 | tail -4; }

say "1. SPIRE up + register the tool, wrong-tool and run identities"
bash "$HERE/verify-slice3.sh" up >/dev/null 2>&1 && info "SPIRE up" || { bad "SPIRE failed"; exit 1; }
entry "$TOOL_SVID"  -selector "docker:label:andyur.role:tool"
entry "$WRONG_SVID" -selector "docker:label:andyur.role:tool-wrong"
entry "$RUN_SVID"   -selector "docker:label:andyur.run_id:r1"
sleep 5

say "2. start the mTLS tool (presents $TOOL_SVID) and the ext_authz service (UDS-only)"
docker run -d --name andyur-tool --network "$NET" --label andyur.role=tool \
  -v "$SOCK_VOL:/run/spire/sockets:ro" -v "$ROOT/infra/envoy/tool_server.py:/tool.py:ro" -v "$ROOT/demos/authority-tool/pep.py:/pep.py:ro" \
  --entrypoint python "$ANDYUR_IMG" /tool.py "$SOCK" "$TD" 8443 >/dev/null
wait_for andyur-tool "mTLS listening" || exit 1
start_authz 1 1
info "tool + ext_authz up"

say "3. POSITIVE (POST/GET/DELETE) + CREDENTIAL BOUNDARY + HEADER ALLOWLIST"
gen_and_run_envoy andyur-tool
for m in POST GET DELETE; do
  out="$(call /mcp $m)"; s="$(echo "$out" | awk '{print $1}')"
  # allowlist: NONE of the agent's arbitrary credential headers reached the tool
  # The injected Authorization is a platform-minted Bearer JWT, and it OVERRODE
  # the agent's own 'Bearer AGENT-OWN'; no arbitrary agent credential survived.
  if [ "$s" = 200 ] && echo "$out" | grep -q "$RUN_SVID" \
     && echo "$out" | grep -q '"leaked_credentials": \[\]' \
     && echo "$out" | grep -qE '"authorization": "Bearer eyJ' \
     && ! echo "$out" | grep -q 'AGENT-OWN' \
     && ! echo "$out" | grep -qiE 'x-custom-secret|proxy-authorization|x-vendor-session|x-api-key|cookie'; then
    ok "$m: RUN cert + ONLY the injected token; arbitrary agent headers stripped by the allowlist"
  else bad "$m: credential boundary/allowlist/positive path failed: $out"; fi
done
# The agent's FORGED trace + x-envoy header must not reach the tool (audit /
# provenance integrity); Envoy overrides x-forwarded-for with the real peer, so
# the tool's echoed xff is NOT the agent's forged 6.6.6.6.
out="$(call /mcp POST)"
if ! echo "$out" | grep -qi 'traceparent' && ! echo "$out" | grep -qi 'x-envoy-internal' \
   && echo "$out" | grep -q '"xff":' && ! echo "$out" | grep -q '"xff": "6.6.6.6"'; then
  ok "forged trace/x-envoy stripped + XFF overridden by Envoy (not 6.6.6.6): $out"
else bad "a forged agent trace/forwarding header reached the tool: $out"; fi

say "3c. MCP-AWARE AUTHORIZATION from REGISTRY DATA: method + specific tool"
# The manifest grants read_calendar (requires calendar:read) and
# delete_calendar (requires calendar:delete); the run's narrowed actions are
# calendar:read only. The decision is REAL registry policy, not a stub list.
out="$(call /mcp POST read_calendar)"
echo "$out" | grep -q '"ok": true' && echo "$out" | grep -q '"mcp_method": "tools/call"' \
  && ok "tools/call read_calendar allowed and reached the tool as an MCP call: $out" \
  || bad "permitted MCP tool did not reach the tool: $out"
want 403 "$(call /mcp POST delete_calendar | awk '{print $1}')" "tools/call delete_calendar (granted tool, action NOT in run scope)"
want 403 "$(callm 'resources/read' | awk '{print $1}')"          "method outside the tool-enumerated MCP surface"

say "3d. TOOLS/LIST FILTERING: no ghost tools, both response shapes (negative #9)"
# $1 = Accept header; prints "<status> <body>"
list_call(){ docker run --rm --network "$NET" --entrypoint python "$ANDYUR_IMG" -c "
import httpx, json
body=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/list'})
try:
    r=httpx.post('http://andyur-envoy:15000/mcp',timeout=10,content=body,
        headers={'content-type':'application/json','accept':'${1:-application/json}'})
    print(r.status_code, r.text[:500].replace(chr(10),' '))
except Exception as e: print('000','ERR',type(e).__name__)" 2>/dev/null; }
out="$(list_call 'application/json')"
if echo "$out" | grep -q '^200' && echo "$out" | grep -q 'read_calendar' \
   && ! echo "$out" | grep -q 'delete_calendar'; then
  ok "JSON tools/list shows ONLY the granted tool: $out"
else bad "JSON tools/list not filtered to the grant: $out"; fi
out="$(list_call 'application/json, text/event-stream')"
if echo "$out" | grep -q '^200' && echo "$out" | grep -q 'data: ' \
   && echo "$out" | grep -q 'read_calendar' && ! echo "$out" | grep -q 'delete_calendar'; then
  ok "SSE tools/list filtered too, framing intact: $out"
else bad "SSE tools/list not filtered/framed: $out"; fi

say "3e. TOOLS/LIST MUTATION: remove the rewrite filter -> the ghost tool REAPPEARS"
gen_and_run_envoy andyur-tool "hf=boot['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']['http_filters']; boot['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']['http_filters']=[f for f in hf if 'toolfilter' not in str(f)]"
out="$(list_call 'application/json')"
echo "$out" | grep -q 'delete_calendar' \
  && ok "MUTATION CONFIRMED: without the rewrite filter the ungranted tool is LISTED: $out" \
  || bad "tools/list mutation inconclusive (expected the ghost tool to reappear): $out"
gen_and_run_envoy andyur-tool

say "3f. TOOLS/LIST FAIL-CLOSED: an unreadable (gzipped) list -> the agent gets an ERROR, not the raw menu"
docker rm -f andyur-tool >/dev/null 2>&1
docker run -d --name andyur-tool --network "$NET" --label andyur.role=tool -e TOOL_GZIP_LIST=1 \
  -v "$SOCK_VOL:/run/spire/sockets:ro" -v "$ROOT/infra/envoy/tool_server.py:/tool.py:ro" -v "$ROOT/demos/authority-tool/pep.py:/pep.py:ro" \
  --entrypoint python "$ANDYUR_IMG" /tool.py "$SOCK" "$TD" 8443 >/dev/null
wait_for andyur-tool "mTLS listening" || exit 1
gen_and_run_envoy andyur-tool
out="$(list_call 'application/json')"
if echo "$out" | grep -q '^200' && echo "$out" | grep -q '"code": -32000' \
   && ! echo "$out" | grep -q 'read_calendar' && ! echo "$out" | grep -q 'delete_calendar'; then
  ok "unreadable list FAILED CLOSED: the agent received a JSON-RPC error, never the raw menu: $out"
else bad "fail-closed path did not substitute the error (or leaked the list): $out"; fi
# restore the normal tool
docker rm -f andyur-tool >/dev/null 2>&1
docker run -d --name andyur-tool --network "$NET" --label andyur.role=tool \
  -v "$SOCK_VOL:/run/spire/sockets:ro" -v "$ROOT/infra/envoy/tool_server.py:/tool.py:ro" -v "$ROOT/demos/authority-tool/pep.py:/pep.py:ro" \
  --entrypoint python "$ANDYUR_IMG" /tool.py "$SOCK" "$TD" 8443 >/dev/null
wait_for andyur-tool "mTLS listening" || exit 1
gen_and_run_envoy andyur-tool

say "3b. CREDENTIAL-BOUNDARY MUTATION: remove the allowlist filter -> creds must LEAK"
gen_and_run_envoy andyur-tool "hf=boot['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']['http_filters']; boot['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']['http_filters']=[f for f in hf if f['name']!='envoy.filters.http.lua']"
out="$(call /mcp POST)"
echo "$out" | grep -q '"leaked_credentials": \["x-andyur-run-token"' \
  && ok "MUTATION CONFIRMED: without the allowlist filter the run token LEAKS: $out" \
  || bad "mutation inconclusive (expected a leak): $out"

say "4. PATH CONFINEMENT: every non-declared path/method is EXACTLY 404 (tool not reached)"
gen_and_run_envoy andyur-tool
want 404 "$(status /admin POST)"     "/admin"
want 404 "$(status /mcp/extra POST)" "/mcp/extra"
want 404 "$(status /mcpadmin POST)"  "/mcpadmin"
want 404 "$(status '/mcp?x=1' POST)" "/mcp?x=1"
want 404 "$(status /mcp PATCH)"      "PATCH /mcp"

say "5. N-02: wrong-SVID tool is REJECTED; and the SAN MUTATION (no matcher -> accepted)"
docker run -d --name andyur-tool-wrong --network "$NET" --label andyur.role=tool-wrong \
  -v "$SOCK_VOL:/run/spire/sockets:ro" -v "$ROOT/infra/envoy/tool_server.py:/tool.py:ro" -v "$ROOT/demos/authority-tool/pep.py:/pep.py:ro" \
  --entrypoint python "$ANDYUR_IMG" /tool.py "$SOCK" "$TD" 8443 >/dev/null
wait_for andyur-tool-wrong "mTLS listening" || exit 1
gen_and_run_envoy andyur-tool-wrong
out="$(call /mcp POST)"
if ! echo "$out" | grep -q '"ok": true' && echo "$out" | grep -qi "certificate_verify"; then
  ok "wrong-SVID tool failed the handshake (CERTIFICATE_VERIFY_FAIL): $out"
else bad "N-02 BREACH or wrong reason: $out"; fi
# inverse mutation: strip the SAN matcher and the SAME wrong tool must be ACCEPTED
gen_and_run_envoy andyur-tool-wrong "boot['static_resources']['clusters'][1]['transport_socket']['typed_config']['common_tls_context']['combined_validation_context']['default_validation_context'].pop('match_typed_subject_alt_names',None)"
out="$(call /mcp POST)"
echo "$out" | grep -q '"ok": true' \
  && ok "SAN MUTATION CONFIRMED: without the matcher the wrong tool is ACCEPTED -> the matcher is what enforces N-02: $out" \
  || bad "SAN mutation inconclusive (expected acceptance without matcher): $out"

say "6. AUTHORITY DENY -> 403 (decider's own body)"
start_authz 0 1; gen_and_run_envoy andyur-tool
out="$(call /mcp POST)"
if echo "$out" | grep -q "^403" && echo "$out" | grep -qi "not permitted"; then
  ok "ext_authz DENY blocked at Envoy: $out"; else bad "authority deny not enforced: $out"; fi

say "7. LIVENESS: a TERMINATED run is refused (403) even with a valid token/SVID"
start_authz 1 0; gen_and_run_envoy andyur-tool
out="$(call /mcp POST)"
if echo "$out" | grep -q "^403" && echo "$out" | grep -qi "not active"; then
  ok "terminated run refused: $out"; else bad "liveness not enforced: $out"; fi

say "8. AUTHZ IS NOT A NETWORK DISPENSER: a workload cannot reach the decision service directly"
start_authz 1 1
direct="$(docker run --rm --network "$NET" --entrypoint python "$ANDYUR_IMG" -c "
import httpx
try:
    r=httpx.post('http://andyur-authz:9000/authz',timeout=5); print(r.status_code, r.text[:80])
except Exception as e: print('REFUSED', type(e).__name__)" 2>/dev/null)"
echo "$direct" | grep -q "REFUSED" \
  && ok "a direct network call to the authz service is refused (UDS-only, no network port): $direct" \
  || bad "authz reachable over the network -- unauthenticated token dispenser: $direct"

say "9. F-02 SENDER BINDING: the delegated token is bound to the run certificate"
# The tool runs the REAL pep.verify_cnf against the LIVE presented client
# certificate. The positive and negative cases keep the same Envoy (stable
# presented cert): capture its thumbprint once (bearer call, cnf off), then
# swap only the authz config. The mutation case is thumbprint-independent (a
# mis-bound token accepted only because verify_cnf is neutralized), so its
# Envoy restart is immaterial. This stands in for the co-located SDS material a
# same-Pod AS shares with Envoy; a separate SPIRE fetch would mint a distinct
# key and never match.
# The tool runs in STRICT mode (TOOL_REQUIRE_CNF=1): a plain bearer is refused,
# so an AS that strips cnf cannot degrade to a bearer at the resource. Capture
# the presented thumbprint first with a NON-strict tool (a bearer read), then
# restart the tool strict (Envoy unchanged -> same presented cert).
gen_and_run_envoy andyur-tool
CNF=0 start_authz 1 1
cap="$(call /mcp POST read_calendar)"
THUMB="$(echo "$cap" | sed -n 's/.*"presented_x5t": "\([^"]*\)".*/\1/p')"
[ -n "$THUMB" ] && info "captured presented cert thumbprint: $THUMB" \
  || bad "could not capture the presented cert thumbprint: $cap"
start_tool_strict(){ docker rm -f andyur-tool >/dev/null 2>&1
  docker run -d --name andyur-tool --network "$NET" --label andyur.role=tool -e TOOL_REQUIRE_CNF=1 \
    -v "$SOCK_VOL:/run/spire/sockets:ro" -v "$ROOT/infra/envoy/tool_server.py:/tool.py:ro" -v "$1:/pep.py:ro" \
    --entrypoint python "$ANDYUR_IMG" /tool.py "$SOCK" "$TD" 8443 >/dev/null
  wait_for andyur-tool "mTLS listening" || exit 1; }
start_tool_strict "$ROOT/demos/authority-tool/pep.py"
# POSITIVE: strict tool accepts a token bound to that exact cert.
CNF=1 CNF_THUMB="$THUMB" start_authz 1 1
out="$(call /mcp POST read_calendar)"
if echo "$out" | grep -q '"ok": true' && echo "$out" | grep -q '"cnf": "bound"'; then
  ok "cnf-bound token ACCEPTED under require_cnf: verify_cnf matched the binding to the presented run cert: $out"
else bad "cnf positive control failed (expected a bound acceptance): $out"; fi
# NEGATIVE 1: a token bound to a DIFFERENT certificate (stolen-token replay).
CNF=1 CNF_WRONG=1 start_authz 1 1
out="$(call /mcp POST read_calendar)"
if echo "$out" | grep -q "^401" && echo "$out" | grep -qi "not bound to this channel"; then
  ok "stolen-token replay REFUSED: a token whose cnf is a different cert is rejected at the tool: $out"
else bad "F-02 negative failed (a mis-bound token was not refused): $out"; fi
# (The "AS strips cnf -> resource refuses under require_cnf" property is proven
# by a real unit test against pep.verify_cnf, not by simulating a misbehaving AS
# here. The real end-to-end AS binding is B's ADR-006 lane.)
# MUTATION: neutralize verify_cnf in the tool's copy of pep -> the same
# mis-bound token is ACCEPTED, proving verify_cnf is exactly what enforces it.
MUT_PEP="/tmp/andyur-envoy-spike/pep_nocnf.py"
"$ROOT/.venv/bin/python" -c "
import re
src=open('$ROOT/demos/authority-tool/pep.py').read()
mut=re.sub(r'def verify_cnf\(([^)]*)\) -> None:', r'def verify_cnf(\1) -> None:\n    return  # MUTATED: binding disabled', src, count=1)
assert 'MUTATED: binding disabled' in mut, 'mutation did not apply'
open('$MUT_PEP','w').write(mut)"
start_tool_strict "$MUT_PEP"
# a mis-bound token (CNF_WRONG); the neutralized verify_cnf must accept it.
CNF=1 CNF_WRONG=1 start_authz 1 1
out="$(call /mcp POST read_calendar)"
echo "$out" | grep -q '"ok": true' \
  && ok "MUTATION CONFIRMED: with verify_cnf neutralized the mis-bound token is ACCEPTED -> verify_cnf is what enforces F-02: $out" \
  || bad "cnf mutation inconclusive (expected acceptance with the check disabled): $out"

trap - EXIT
say "RESULT"
if [ "$FAILURES" -eq 0 ]; then ok "all $PASSES assertions passed; spike gate GREEN"; echo "(stack up; tear down: $0 down)"; exit 0
else bad "$FAILURES assertion(s) failed -- spike gate RED"; echo "(stack up; tear down: $0 down)"; exit 1; fi
