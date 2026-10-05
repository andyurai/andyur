#!/usr/bin/env bash
# LIVE proof of the console's ADMIN vs USER modes against a REAL Keycloak, in
# the configuration where every control is actually active: identity is
# mandatory, so the server and every caller here run as their SPIRE-attested
# role binaries on the host plane (./run.sh up first), and Keycloak is a real
# container publishing a loopback port.
#
# What it proves, live:
#   ADMIN   carol's Keycloak realm role (andyur-admin) makes /me say admin; she
#           sees every owner's agents (owner column), reads /workers,
#           halts/unhalts a workflow, and pauses another owner's agent
#   USER    alice is not admin; her list is owner-scoped; workers/halt are 403
#   ISOLATION  bob cannot pause/resume/read-or-write-ceiling alice's agent
#           (404); the refused pause provably did not happen and the refused
#           resume provably left it paused
#   NO IMPERSONATION  even admin carol cannot trigger alice's agent (404)
#   LOGIN   the console's own `andyur console` process completes a REAL
#           Auth Code + PKCE login against Keycloak's login form (scripted
#           browser), then proxies as that user: /api/me, mode-scoped lists,
#           and the session-secret fence, all through the real uvicorn BFF
#   REFRESH the exact refresh_token form UserSession sends is accepted by
#           Keycloak (mid-session refresh itself is unit/mutation-covered)
#
# The stack is torn down on exit either way (the console processes hold live IdP
# tokens in memory, so leaving them running would leak a credential). `down`
# removes a Keycloak container left by an interrupted run.
# Usage: ./verify-console-modes.sh   (add `down`)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$HERE/infra/lib/console-gate.sh"
KC_IMAGE="${ANDYUR_KC_IMAGE:-quay.io/keycloak/keycloak:26.2}"
KC_PORT="${ANDYUR_KC_PORT:-8087}"
ISS="http://127.0.0.1:$KC_PORT/realms/andyur"
# 8643 is the broker default (ANDYUR_BROKER_PORT); a gate server there would
# fight a main stack running with ANDYUR_BROKER=on and its teardown would kill
# that broker. 8644 has no other user in the repo.
SRV_PORT="${ANDYUR_MODES_SRV_PORT:-8644}"
SRV="http://127.0.0.1:$SRV_PORT"
CONSOLE_PORT="${CONSOLE_PORT:-8652}"   # this AND the next port (two consoles); override when another stack holds them
# Prior runs' dirs are swept here because teardown cannot know their random
# names: a red run deliberately keeps its dir for diagnosis, and this is the
# bounded end of that bargain -- kept logs live until a later invocation, not
# forever. TWO guards make the sweep safe: it runs only in `up` mode (so
# `down`, which cleans up after a red run, never destroys the logs that run
# kept), and it only removes dirs untouched for 60+ minutes (`-mmin +60`), so
# a CONCURRENT run's live dir -- written continuously -- is never in range.
if [ "${1:-up}" != "down" ]; then
  find /tmp -maxdepth 1 -name 'andyur-console-modes.*' -type d -mmin +60 \
    -exec rm -rf {} + 2>/dev/null || true
fi
DATA_DIR="$(mktemp -d /tmp/andyur-console-modes.XXXXXX)"
LOGDIR="$DATA_DIR/logs"; mkdir -p "$LOGDIR"

say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }

# JWKS is set explicitly (not derived): Keycloak publishes its keys at
# .../protocol/openid-connect/certs, not the generic /.well-known/jwks.json the
# server would otherwise construct from the issuer.
USER_ENV=(ANDYUR_USER_AUTH=on "ANDYUR_OIDC_ISSUER=$ISS"
          "ANDYUR_OIDC_JWKS=$ISS/protocol/openid-connect/certs"
          ANDYUR_OIDC_AUDIENCE=andyur
          ANDYUR_ADMIN_ROLE=andyur-admin "ANDYUR_SERVER_URL=$SRV")

teardown(){ docker rm -f andyur-console-kc >/dev/null 2>&1 || true
  # Kill by PORT, not just the recorded PID: `run.sh server` / `andyur-cli
  # console` fork a child that exec's uvicorn, so the recorded pid is the wrapper
  # and killing it orphans the listener -- a stale server then survives to answer
  # the NEXT run's health check with the wrong config (seen live: a server from a
  # prior run, started before OIDC_JWKS was set, kept 404ing on the JWKS URL).
  # Only ports THIS run started something on: a red precondition must not
  # kill a developer's console or another gate sitting on these numbers.
  [ -n "${SERVER_PID:-}" ]   && { lsof -ti ":$SRV_PORT" 2>/dev/null | xargs -r kill 2>/dev/null || true; }
  [ -n "${CONSOLE_PID:-}" ]  && { lsof -ti ":$CONSOLE_PORT" 2>/dev/null | xargs -r kill 2>/dev/null || true; }
  [ -n "${CONSOLE2_PID:-}" ] && { lsof -ti ":$((CONSOLE_PORT+1))" 2>/dev/null | xargs -r kill 2>/dev/null || true; }
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  [ -n "${CONSOLE_PID:-}" ] && kill "$CONSOLE_PID" 2>/dev/null
  [ -n "${CONSOLE2_PID:-}" ] && kill "$CONSOLE2_PID" 2>/dev/null
  # The dir holds server state and cookie jars, so a green run must not leave
  # it behind; a red run keeps it and says so, because the logs inside are the
  # diagnosis (the next invocation sweeps it, so the keep is bounded).
  if [ "${FAILURES:-0}" -eq 0 ]; then
    rm -rf "$DATA_DIR"
  else
    printf 'logs kept for diagnosis: %s\n' "$DATA_DIR"
  fi
  true; }
if [ "${1:-up}" = "down" ]; then say "tearing down"; teardown; echo done; exit 0; fi
# INT/TERM route through exit so the EXIT trap runs teardown: a Ctrl-C mid-run
# otherwise leaves Keycloak, the server, and the in-memory IdP tokens alive --
# exactly the credential-bearing state teardown exists to destroy.
trap teardown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

say "0. preconditions: SPIRE plane + role binaries (./run.sh up), docker, curl"
command -v curl >/dev/null || { echo "curl required"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker required"; exit 1; }
[ -S "$HERE/data/spire/agent/api.sock" ] \
  || { echo "SPIRE agent socket not found -- run ./run.sh up first"; exit 1; }
[ -x "$HERE/infra/roles/bin/andyur-operator" ] \
  || { echo "role binaries not built -- run ./run.sh up first"; exit 1; }
ok "host plane present"

# The operator role binary, with the venv on PYTHONPATH (same recipe as andyur-cli):
# SPIRE's unix attestor identifies it by path and issues the OPERATOR SVID.
oppy(){ PYTHONPATH="$HERE/.venv/lib/python3.12/site-packages" \
        env "${USER_ENV[@]}" "$HERE/infra/roles/bin/andyur-operator" - ; }

say "1. Keycloak (real OIDC provider) with the seeded 'andyur' realm on :$KC_PORT"
docker rm -f andyur-console-kc >/dev/null 2>&1 || true
docker run -d --name andyur-console-kc -p "127.0.0.1:$KC_PORT:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false \
  -v "$HERE/infra/keycloak/realm-andyur.json:/opt/keycloak/data/import/realm-andyur.json:ro" \
  "$KC_IMAGE" start-dev --import-realm >/dev/null
for _ in $(seq 1 120); do
  curl -sf "$ISS/.well-known/openid-configuration" >/dev/null 2>&1 && break; sleep 2
done
curl -sf "$ISS/.well-known/openid-configuration" >/dev/null \
  || { bad "Keycloak not ready"; docker logs andyur-console-kc 2>&1 | tail -15; exit 1; }
ok "Keycloak up; realm discoverable at $ISS"

say "2. a dedicated server (fresh data dir) with user-auth ON + admin role, on the SPIRE plane"
( cd "$HERE" && env "${USER_ENV[@]}" ANDYUR_PROFILE=dev "ANDYUR_DATA_DIR=$DATA_DIR" \
    ANDYUR_PORT=$SRV_PORT ./run.sh server >"$LOGDIR/server.log" 2>&1 ) &
SERVER_PID=$!
for _ in $(seq 1 60); do curl -sf "$SRV/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$SRV/health" >/dev/null \
  || { bad "server did not come up"; tail -20 "$LOGDIR/server.log"; exit 1; }
ok "server up on :$SRV_PORT (identity on, user-auth on, admin role wired)"

say "3. server enforcement with REAL Keycloak tokens + a REAL operator SVID"
oppy <<'PY' || FAILURES=$((FAILURES+1))
import sys, httpx
from andyur import identity
from andyur.config import SERVER_URL, OIDC_ISSUER

TOKEN = OIDC_ISSUER + "/protocol/openid-connect/token"
results = []
def check(name, cond, detail=""):
    results.append(cond)
    print(("  \033[32mPASS\033[0m  " if cond else "  \033[31mFAIL\033[0m  ")
          + name + ("  " + detail if detail else ""))

def login(user):
    r = httpx.post(TOKEN, data={"grant_type": "password", "client_id": "andyur-cli",
                                "username": user, "password": f"{user}-password"}, timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]

alice, bob, carol = login("alice"), login("bob"), login("carol")
cert, verify = identity.client_tls("operator")
c = httpx.Client(base_url=SERVER_URL, timeout=15, auth=identity.httpx_auth(),
                 cert=cert, verify=verify)
def H(t): return {"X-Andyur-User-Token": t}

me_a = c.get("/me", headers=H(alice)).json()
me_c = c.get("/me", headers=H(carol)).json()
check("/me: alice is not admin", me_a.get("admin") is False, str(me_a))
check("/me: carol IS admin (Keycloak realm role)", me_c.get("admin") is True, str(me_c))

r = c.post("/agents", json={"name": "scout-alice"}, headers=H(alice))
check("alice creates her agent", r.status_code == 201, str(r.status_code))
r = c.post("/agents", json={"name": "vault-bob"}, headers=H(bob))
check("bob creates his agent", r.status_code == 201, str(r.status_code))

rows = c.get("/agents", headers=H(carol)).json()
owners = {a["name"]: a.get("owner") for a in rows}
check("ADMIN carol sees BOTH owners' agents with the owner column",
      set(owners) == {"scout-alice", "vault-bob"} and all(owners.values()), str(owners))
names = [a["name"] for a in c.get("/agents", headers=H(alice)).json()]
check("USER alice sees only her own", names == ["scout-alice"], str(names))

r = c.post("/agents/scout-alice/pause", headers=H(bob))
check("bob cannot pause alice's agent (404, no oracle)", r.status_code == 404, str(r.status_code))
paused = c.get("/agents/scout-alice", headers=H(alice)).json()["paused"]
check("...and it provably did not pause", not paused, str(paused))
# positive control: the owner CAN pause, and it provably takes effect
check("(+) owner alice pauses her agent",
      c.post("/agents/scout-alice/pause", headers=H(alice)).status_code == 200)
check("...and it provably IS now paused",
      bool(c.get("/agents/scout-alice", headers=H(alice)).json()["paused"]))
# resume is a separate gate: bob cannot un-pause alice's now-paused agent
check("bob cannot resume alice's paused agent (404)",
      c.post("/agents/scout-alice/resume", headers=H(bob)).status_code == 404)
check("...and it provably stayed paused",
      bool(c.get("/agents/scout-alice", headers=H(alice)).json()["paused"]))
check("bob cannot read alice's ceiling (404)",
      c.get("/agents/scout-alice/ceiling", headers=H(bob)).status_code == 404)
check("bob cannot WRITE alice's ceiling (404)",
      c.put("/agents/scout-alice/ceiling", json={"actions": []}, headers=H(bob)).status_code == 404)
check("(+) alice reads her own ceiling",
      c.get("/agents/scout-alice/ceiling", headers=H(alice)).status_code == 200)
check("ADMIN carol resumes alice's agent",
      c.post("/agents/scout-alice/resume", headers=H(carol)).status_code == 200)
check("(+) owner alice resumes it (idempotent)",
      c.post("/agents/scout-alice/resume", headers=H(alice)).status_code == 200)

check("USER alice refused /workers (403)",
      c.get("/workers", headers=H(alice)).status_code == 403)
check("ADMIN carol reads /workers",
      c.get("/workers", headers=H(carol)).status_code == 200)
check("USER alice refused workflow halt (403)",
      c.post("/workflows/wfx/halt", headers=H(alice)).status_code == 403)
check("ADMIN carol halts + unhalts a workflow",
      c.post("/workflows/wfx/halt", headers=H(carol)).status_code == 200
      and c.post("/workflows/wfx/unhalt", headers=H(carol)).status_code == 200)

r = c.post("/agents/scout-alice/trigger", json={"reason": "x"}, headers=H(carol))
check("even ADMIN carol cannot trigger alice's agent (no impersonation)",
      r.status_code == 404, str(r.status_code))
r = c.post("/agents/scout-alice/trigger", json={"reason": "x"}, headers=H(alice))
check("(+) owner alice triggers it", r.status_code == 201, str(r.status_code))

check("forged user token refused (401)",
      c.get("/me", headers=H("not.a.token")).status_code == 401)

sys.exit(0 if all(results) else 1)
PY

say "4. the REAL console: PKCE login at Keycloak's form, then the BFF in each mode"
LAST_PID=""
start_console(){ # $1=username $2=port $3=logfile -> proves the real login + BFF
  local user="$1" port="$2" log="$3"
  ( cd "$HERE" && env "${USER_ENV[@]}" \
      ./andyur-cli console --no-browser --port "$port" >"$log" 2>&1 ) &
  LAST_PID=$!
  # the console prints the Keycloak authorization URL, blocks on its loopback
  # callback; script the login form exactly as a browser would
  local authz=""
  for _ in $(seq 1 40); do
    # the FULL authorization URL (with code_challenge), not the bare endpoint
    # the login also prints on the line before it
    authz=$(grep -o 'http://127.0.0.1:'"$KC_PORT"'/[^ ]*code_challenge[^ ]*' "$log" | head -1)
    [ -n "$authz" ] && break; sleep 0.5
  done
  [ -n "$authz" ] || { bad "console never printed the authorization URL ($log)"; return 1; }
  # Inside DATA_DIR so it rides the teardown lifecycle instead of leaking a
  # cookie jar into /tmp per login.
  local jar; jar=$(mktemp "$DATA_DIR/jar.XXXXXX")
  local form_action
  form_action=$(curl -s -c "$jar" "$authz" \
    | grep -o 'action="[^"]*"' | head -1 | sed 's/^action="//; s/"$//' \
    | sed 's/\&amp;/\&/g')
  [ -n "$form_action" ] || { bad "no login form from Keycloak"; return 1; }
  local loc
  loc=$(curl -s -b "$jar" -o /dev/null -w '%{redirect_url}' \
    --data-urlencode "username=$user" --data-urlencode "password=$user-password" \
    "$form_action")
  case "$loc" in http://127.0.0.1:87*) ;; *) bad "login did not redirect to the console callback: $loc"; return 1;; esac
  curl -s "$loc" >/dev/null    # deliver the code to the console's RFC 8252 listener
  for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -sf "http://127.0.0.1:$port/healthz" >/dev/null || { bad "console BFF not up"; return 1; }
  return 0
}

start_console carol "$CONSOLE_PORT" "$LOGDIR/console-carol.log" \
  && ok "carol completed a real PKCE login; her console BFF is up" || true
CONSOLE_PID=$LAST_PID
SECRET=$(console_exchange "http://127.0.0.1:$CONSOLE_PORT" "$(console_launch_token "$LOGDIR/console-carol.log")")
if [ -n "$SECRET" ]; then
  H1=(-H "$SESSION_HEADER: $SECRET")
  BASE="http://127.0.0.1:$CONSOLE_PORT"
  ME=$(curl -s "${H1[@]}" "$BASE/api/me")
  echo "$ME" | grep -q '"admin":true' && ok "BFF(carol): /api/me says admin  $ME" \
    || bad "BFF(carol): /api/me not admin: $ME"
  LIST=$(curl -s "${H1[@]}" "$BASE/api/agents")
  echo "$LIST" | grep -q 'scout-alice' && echo "$LIST" | grep -q 'vault-bob' \
    && ok "BFF(carol): admin list shows BOTH owners' agents" \
    || bad "BFF(carol): admin list incomplete: $LIST"
  [ "$(curl -s -o /dev/null -w '%{http_code}' "${H1[@]}" "$BASE/api/workers")" = 200 ] \
    && ok "BFF(carol): /api/workers proxied for the admin" || bad "BFF(carol): workers not 200"
  want 401 "$(code -H "$SESSION_HEADER: wrong" "$BASE/api/agents")" "BFF: wrong session secret still 401"
  want launch_spent "$(reason -X POST -H 'content-type: application/json' -d "{\"launch\":\"$(console_launch_token "$LOGDIR/console-carol.log")\"}" "$BASE/session")" "BFF: a second exchange of the launch token is refused by name"
else
  bad "carol's console printed no launch token, or the exchange failed"
fi

start_console alice $((CONSOLE_PORT+1)) "$LOGDIR/console-alice.log" \
  && ok "alice completed a real PKCE login; her console BFF is up" || true
CONSOLE2_PID=$LAST_PID
SECRET2=$(console_exchange "http://127.0.0.1:$((CONSOLE_PORT+1))" "$(console_launch_token "$LOGDIR/console-alice.log")")
if [ -n "$SECRET2" ]; then
  H2=(-H "$SESSION_HEADER: $SECRET2")
  BASE2="http://127.0.0.1:$((CONSOLE_PORT+1))"
  ME2=$(curl -s "${H2[@]}" "$BASE2/api/me")
  echo "$ME2" | grep -q '"admin":false' && ok "BFF(alice): /api/me says NOT admin  $ME2" \
    || bad "BFF(alice): unexpected /api/me: $ME2"
  LIST2=$(curl -s "${H2[@]}" "$BASE2/api/agents")
  echo "$LIST2" | grep -q 'scout-alice' && ! echo "$LIST2" | grep -q 'vault-bob' \
    && ok "BFF(alice): user list is owner-scoped (no vault-bob)" \
    || bad "BFF(alice): list not owner-scoped: $LIST2"
  [ "$(curl -s -o /dev/null -w '%{http_code}' "${H2[@]}" "$BASE2/api/workers")" = 403 ] \
    && ok "BFF(alice): /api/workers refused (403) for the plain user" \
    || bad "BFF(alice): workers not refused"
else
  bad "alice's console printed no launch token, or the exchange failed"
fi

say "5. the realm accepts a refresh_token grant (probed via the andyur-cli client's password grant)"
REFRESH=$(curl -s "$ISS/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=andyur-cli \
  -d username=carol -d password=carol-password | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
NEW=$(curl -s "$ISS/protocol/openid-connect/token" \
  -d grant_type=refresh_token -d client_id=andyur-cli -d "refresh_token=$REFRESH")
echo "$NEW" | grep -q '"access_token"' \
  && ok "refresh_token grant accepted by the realm (the console client's own refresh path is pinned by tests/test_console_bff.py)" \
  || bad "refresh grant refused: $(echo "$NEW" | head -c 200)"

echo
if [ "$FAILURES" -eq 0 ]; then
  say "console-modes gate GREEN ($PASSES shell assertions + the python block)"
  exit 0
else
  say "console-modes gate RED ($FAILURES failures)"; exit 1
fi
