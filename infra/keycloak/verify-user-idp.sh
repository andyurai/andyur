#!/usr/bin/env bash
# LIVE user-identity proof against a REAL OpenID Connect provider (Keycloak), in
# the configuration where every control is actually active: identity is
# mandatory, so the server and the caller here run as their SPIRE-attested role
# binaries on the host plane (./run.sh up first), and Keycloak is a real
# container publishing a loopback port.
#
# What it proves, live:
#   U1  a real user login seals the agent's owner and the run acts for that
#       user (the signed run grant carries her `sub`)
#   (-) a forged or absent user token is refused (401)
#   U3  a second real user (bob) cannot even see alice's agent (404, no oracle)
# Nothing is stubbed: the token is signed by Keycloak and validated by Andyur
# against Keycloak's published keys, and every API call carries a real
# operator JWT-SVID (identity is no longer optional on these endpoints).
# On success everything (containers, server, temp data dir) is torn down; on
# failure the stack stays up for inspection. `down` reaps a left-up stack.
# Usage: ./verify-user-idp.sh  (add `down`).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KC_IMAGE="${ANDYUR_KC_IMAGE:-quay.io/keycloak/keycloak:26.2}"
KC_PORT="${ANDYUR_KC_PORT:-8086}"
ISS="http://127.0.0.1:$KC_PORT/realms/andyur"
SRV_PORT=8644
SRV="http://127.0.0.1:$SRV_PORT"
DATA_DIR="$(mktemp -d /tmp/andyur-user-idp.XXXXXX)"
LOGDIR="$DATA_DIR/logs"; mkdir -p "$LOGDIR"

FAILURES=0
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES+1)); }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }

# JWKS is set explicitly (not derived): Keycloak publishes its keys at
# .../protocol/openid-connect/certs, not the generic /.well-known/jwks.json the
# server would otherwise construct from the issuer.
USER_ENV=(ANDYUR_USER_AUTH=on "ANDYUR_OIDC_ISSUER=$ISS"
          "ANDYUR_OIDC_JWKS=$ISS/protocol/openid-connect/certs"
          ANDYUR_OIDC_AUDIENCE=andyur "ANDYUR_SERVER_URL=$SRV")

teardown(){ docker rm -f andyur-user-idp-kc >/dev/null 2>&1 || true
  # Kill by PORT as well as PID -- belt and suspenders: the exec chain usually
  # makes $SERVER_PID the uvicorn process itself, but a stale listener from an
  # older interrupted run answers the next run's health check with the wrong
  # config, so the port sweep guarantees a clean slate either way.
  lsof -ti ":$SRV_PORT" 2>/dev/null | xargs -r kill 2>/dev/null || true
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null; true; }
if [ "${1:-up}" = "down" ]; then
  say "tearing down"; teardown
  rm -rf /tmp/andyur-user-idp.*   # reap data dirs kept by earlier failed runs
  echo done; exit 0
fi
teardown   # clear a lingering Keycloak/orphaned listener from an interrupted run
# On SUCCESS everything is torn down and the temp data dir removed. On FAILURE
# the stack is left up for live inspection (matching verify-idp-reference.sh);
# `down` reaps it. The trap covers interrupts/early exits.
trap teardown EXIT

say "0. preconditions: SPIRE plane + role binaries (./run.sh up), docker, curl"
command -v curl >/dev/null || { echo "curl required"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker required"; exit 1; }
[ -S "$HERE/data/spire/agent/api.sock" ] \
  || { echo "SPIRE agent socket not found -- run ./run.sh up first"; exit 1; }
[ -x "$HERE/infra/roles/bin/andyur-operator" ] \
  || { echo "role binaries not built -- run ./run.sh up first"; exit 1; }
ok "host plane present"

# The operator role binary with the venv on PYTHONPATH (same recipe as
# andyur-cli): SPIRE's unix attestor identifies it by path and issues the
# OPERATOR SVID, which every API call below presents.
oppy(){ PYTHONPATH="$HERE/.venv/lib/python3.12/site-packages" \
        env "${USER_ENV[@]}" "$HERE/infra/roles/bin/andyur-operator" - ; }

say "1. Keycloak (real OIDC provider) with the seeded 'andyur' realm on :$KC_PORT"
docker rm -f andyur-user-idp-kc >/dev/null 2>&1 || true
docker run -d --name andyur-user-idp-kc -p "127.0.0.1:$KC_PORT:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false \
  -v "$HERE/infra/keycloak/realm-andyur.json:/opt/keycloak/data/import/realm-andyur.json:ro" \
  "$KC_IMAGE" start-dev --import-realm >/dev/null
info "waiting for Keycloak to publish the realm (first boot pulls the image + imports)"
for _ in $(seq 1 120); do
  curl -sf "$ISS/.well-known/openid-configuration" >/dev/null 2>&1 && break; sleep 2
done
curl -sf "$ISS/.well-known/openid-configuration" >/dev/null \
  || { bad "Keycloak not ready"; docker logs andyur-user-idp-kc 2>&1 | tail -15; exit 1; }
ok "Keycloak up; realm 'andyur' discoverable at $ISS"

say "2. a dedicated server (fresh data dir) with user-auth ON, on the SPIRE plane"
( cd "$HERE" && env "${USER_ENV[@]}" ANDYUR_PROFILE=dev "ANDYUR_DATA_DIR=$DATA_DIR" \
    ANDYUR_PORT=$SRV_PORT ./run.sh server >"$LOGDIR/server.log" 2>&1 ) &
SERVER_PID=$!
for _ in $(seq 1 60); do curl -sf "$SRV/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$SRV/health" >/dev/null \
  || { bad "server did not come up"; tail -20 "$LOGDIR/server.log"; exit 1; }
ok "server up on :$SRV_PORT, validating user tokens against Keycloak"

say "3. the live proof: a REAL Keycloak login drives ownership + isolation"
oppy <<'PY' || FAILURES=$((FAILURES+1))
import base64, json, sys, httpx
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

alice, bob = login("alice"), login("bob")
seg = alice.split(".")[1]
alice_sub = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))["sub"]
print("  \033[36m·\033[0m alice signed in at Keycloak; her token sub = " + alice_sub)

cert, verify = identity.client_tls("operator")
c = httpx.Client(base_url=SERVER_URL, timeout=15, auth=identity.httpx_auth(),
                 cert=cert, verify=verify)
def H(t): return {"X-Andyur-User-Token": t}

# U1: a real user token seals the owner (Andyur validated the Keycloak signature)
r = c.post("/agents", json={"name": "scout-alice", "description": "alices agent"}, headers=H(alice))
check("U1  real Keycloak token accepted, agent created", r.status_code == 201, "-> " + str(r.status_code))
r = c.get("/agents/scout-alice", headers=H(alice))
check("U1  owner can read her own agent", r.status_code == 200, "-> " + str(r.status_code))

# negative: no user token, and a forged user token, are both refused -- while
# the operator SVID on the same calls stays valid, so what is being refused is
# the USER credential, not the transport
r = c.get("/agents/scout-alice")
check("(-) no user token refused", r.status_code == 401, "-> " + str(r.status_code))
r = c.get("/agents/scout-alice", headers=H("not.a.real.token"))
check("(-) forged token refused (fails Keycloak signature check)", r.status_code == 401, "-> " + str(r.status_code))

# U3: a DIFFERENT real user cannot even see alice's agent -> 404, no oracle
r = c.get("/agents/scout-alice", headers=H(bob))
check("U3  bob cannot see alice's agent (404, hidden)", r.status_code == 404, "-> " + str(r.status_code))

# U1: the run inherits the owner as its user, carried in the signed run grant
r = c.post("/agents/scout-alice/trigger", json={"reason": "say hello"}, headers=H(alice))
check("U1  owner can trigger; run created", r.status_code == 201, "-> " + str(r.status_code))
run_id = r.json().get("run_id", "")
rt = c.post(f"/runs/{run_id}/token").json().get("run_token", "")
seg = rt.split(".")[0]
payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
check("U1  run grant carries sub=alice", payload.get("s") == alice_sub, "grant sub=" + str(payload.get("s")))

sys.exit(0 if all(results) else 1)
PY

echo
if [ "$FAILURES" -eq 0 ]; then
  say "user-identity proof complete against a LIVE Keycloak issuer"
  rm -rf "$DATA_DIR"
  exit 0
else
  trap - EXIT   # keep the stack up for inspection; `down` reaps it
  say "user-idp gate RED ($FAILURES failures; stack left up, logs in $LOGDIR; tear down: $0 down)"
  exit 1
fi
