#!/usr/bin/env bash
# The FEDERATED enterprise demo, end to end.
#
# A human is paged. Two agents act FOR her. Neither holds a credential, and the
# resource server records HER, not them.
#
# Prerequisites: ./demos/enterprise/setup-federation.py has run green, and the
# control plane is up with ANDYUR_USER_AUTH=on.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$HERE"

KC="${ANDYUR_IDP_URL:-http://127.0.0.1:8480}"
CP="${ANDYUR_SERVER_URL:-http://127.0.0.1:8642}"
GF="${ANDYUR_GRAFANA_URL:-http://127.0.0.1:3000}"
SERVICE="${1:-checkout-service}"

bold() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

bold "1. the tool server (holds NO grafana credential)"
pkill -f 'demos/enterprise/grafana_server.py' 2>/dev/null || true
sleep 1
ANDYUR_SERVER_URL="$CP" ANDYUR_GRAFANA_URL="$GF" \
  nohup python3 demos/enterprise/grafana_server.py > /tmp/grafana-tool.log 2>&1 &
for _ in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8804/mcp" 2>/dev/null | grep -q 401 && break
  sleep 1
done
echo "  grafana tool server: $(grep -c . /tmp/grafana-tool.log) log lines"
grep -E 'holds NO|forwarding' /tmp/grafana-tool.log | sed 's/^/    /' || true

bold "2. two humans authenticate at the IdP -- nowhere else"
tok() {
  curl -s -X POST "$KC/realms/andyur/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=andyur-cli \
    -d "username=$1" -d "password=$2" -d scope=openid \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
DAVID_TOKEN="$(tok david.kumar david-password)"     # platform lead, provisions
SARAH_TOKEN="$(tok sarah.miller sarah-password)"    # on-call, gets paged
for pair in "David:$DAVID_TOKEN" "Sarah:$SARAH_TOKEN"; do
  python3 -c "
import base64,json
c='${pair#*:}'.split('.')[1]
cl=json.loads(base64.urlsafe_b64decode(c+'='*(-len(c)%4)))
print(f\"  ${pair%%:*}: {cl['preferred_username']} <{cl['email']}> roles={cl.get('realm_access',{}).get('roles',[])[-1:]}\")"
done

bold "3. DAVID clears old agents (admin lifecycle), SARAH owns the ones she runs"
echo "  the platform's model: an admin SEES every agent but CANNOT trigger one."
echo "  Only the owner triggers. So the on-call engineer owns her own agents."
export ANDYUR_USER_TOKEN="$DAVID_TOKEN"    # admin: may delete any owner's agent
for a in incident-responder platform-engineer; do
  ./andyur-cli agents delete "$a" --yes --force >/dev/null 2>&1 || true
done
export ANDYUR_USER_TOKEN="$SARAH_TOKEN"   # she owns what she runs
./andyur-cli agents create incident-responder \
  --description "on-call SRE; triages and delegates" \
  --instructions-file demos/enterprise/incident-responder-instructions.md \
  --mcp-file demos/enterprise/grafana-mcp.json | sed 's/^/  /'
./andyur-cli agents create platform-engineer \
  --description "receives delegated engineering work" \
  --instructions-file demos/enterprise/platform-engineer-instructions.md \
  --mcp-file demos/enterprise/grafana-mcp.json | sed 's/^/  /'

ANDYUR_PROFILE=dev ANDYUR_DB="$HERE/data/andyur.db" python3 - <<'PY'
import sys, os
sys.path.insert(0, os.getcwd())
from andyur.server import registry
for a in ("incident-responder", "platform-engineer"):
    registry.set_ceiling(a, actions=["telemetry:read","incidents:read","incidents:write",
                                  "tasks:write","messages:write"],
                         audiences=["http://127.0.0.1:8804/mcp"])
    print(f"  ceiling set: {a}")
PY

bold "4. the page: a run triggered with SARAH's token, not by an operator"
echo "  (the CLI presents its own workload SVID; her IdP token rides in"
echo "   X-Andyur-User-Token -- two credentials, and neither is a password)"
export ANDYUR_USER_TOKEN="$SARAH_TOKEN"
# NOT `agents trigger`: it pre-flights GET /workers, which is admin-only, so
# it crashes for an ordinary user. Filed as a CLI defect. `api` is the
# documented scripting surface and reaches the same endpoint.
./andyur-cli api POST "/agents/incident-responder/trigger" \
  --data "{\"reason\": \"PagerDuty: $SERVICE 5xx error rate breached SLO\", \"subject_context\": {\"service\": \"$SERVICE\"}}" \
  2>&1 | sed 's/^/  /'

bold "5. what the platform recorded about WHO acted"
python3 - <<'PYEOF'
import sqlite3
c = sqlite3.connect("data/andyur.db")
print(f"  {'AGENT':<20} {'ACTING_USER':<38} {'BY':<10} REASON")
for a, u, ab, r in c.execute("SELECT agent, acting_user, user_asserted_by, reason "
                             "FROM runs ORDER BY created_at DESC LIMIT 6"):
    print(f"  {a:<20} {str(u):<38} {str(ab):<10} {(r or '')[:40]}")
PYEOF

bold "6. what GRAFANA recorded -- the resource server's own view"
python3 - <<'PYEOF'
import requests, os, sys
sys.path.insert(0, os.getcwd())
os.environ.setdefault("ANDYUR_PROFILE", "dev")
os.environ.setdefault("ANDYUR_EXCHANGE_KEY",
                      os.path.join(os.getcwd(), "data/secrets/exchange-key.pem"))
from andyur.server import tokenexchange, runtoken
GF = os.environ.get("ANDYUR_GRAFANA_URL", "http://127.0.0.1:3000")
o = tokenexchange.mint(actor="incident-responder", audience="http://127.0.0.1:8804/mcp", ctx_sub="sarah.miller",
                       ctx_sub_src=runtoken.SUB_SRC_IDP, ctx_scope=["telemetry:read"],
                       requested_scope=["telemetry:read"])
tok = o[0] if isinstance(o, tuple) else o
r = requests.get(f"{GF}/api/annotations", headers={"X-Andyur-Auth": tok},
                 params={"limit": 8}, timeout=20)
if r.status_code != 200:
    print(f"  could not read annotations: {r.status_code} {r.text[:120]}")
else:
    rows = r.json()
    if not rows:
        print("  (no annotations yet)")
    for a in rows:
        who = a.get("login") or a.get("email") or "?"
        print(f"  [{a.get('id')}] {a.get('text','')[:58]!r}  ->  {who}")
PYEOF
