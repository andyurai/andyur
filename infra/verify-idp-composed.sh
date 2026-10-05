#!/usr/bin/env bash
# LIVE gate for the COMPOSED reference deployment: the dockerized control
# plane validating real logins from the reference IdP -- the exact wiring
# `./run.sh idp wire` installs, proven end to end rather than documented.
#
# What it proves, live and composed:
#   W1  `idp wire` reconfigures the RUNNING dockerized server against the
#       reference issuer (JWKS fetched in-network at keycloak:8080, iss
#       validated as the browser-facing loopback URL)
#   P1  the console's exact wire flow -- Authorization Code + PKCE (S256) as
#       the andyur-console client, scripted against Keycloak's real login
#       form -- yields a token with canonical iss, aud=andyur, and carol's
#       andyur-admin role. A paired NEGATIVE exchanges a fresh valid code with
#       the WRONG verifier and requires a refusal, so S256 is proven ENFORCED
#       rather than resting on a realm attribute nothing asserts. (The BFF
#       binary itself is proven by infra/verify-console-modes.sh; this proves
#       the CLIENT configuration and realm compose with the reference IdP.)
#   P2  with a real operator SVID (container-attested, the docker
#       deployment's own identity path), the server enforces the admin/user
#       split and cross-user isolation on REAL reference-IdP tokens: /me
#       admin true/false, admin list shows both owners, user list scoped,
#       bob cannot pause alice's agent (and it provably did not pause),
#       workers 403/200, owner triggers, and the signed run grant carries
#       alice's setup-created sub
#   (-) absent and forged user tokens are refused while the operator SVID on
#       the same calls stays valid
#   N1  while all of this is live, the run network still cannot reach the
#       IdP by name or IP (positive control: the same network provably
#       reaches the server, which is dual-homed on it by design)
#   W2  `idp unwire` under the compose's pinned ANDYUR_PROFILE=prod is
#       REFUSED at boot: the recreated server must come up unhealthy and the
#       refusal must name ANDYUR_USER_AUTH (the profile gate, live -- prod
#       has no user-auth-off posture to restore; that is f377727's ratified
#       user-auth leg). The gate then re-wires so the stack is left healthy.
#
# Mutations that must turn this gate red: wiring a wrong JWKS URL (server
# can no longer validate -> P2 logins 401), ANDYUR_ADMIN_ROLE=something-else
# (carol /me admin:false), granting andyur-admin broadly (covered by
# verify-idp-reference.sh's negative), dropping the USER_AUTH prod
# requirement from assert_profile (W2's unwired boot succeeds -> red).
#
# Usage: ./verify-idp-composed.sh   (leaves the stack up, WIRED; unwired
# prod refuses to boot, so wired is the only healthy end state)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$HERE/data/docker.env"
CURL_IMAGE="${ANDYUR_CURL_IMAGE:-curlimages/curl:8.10.1}"

FAILURES=0; PASSES=0
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASSES=$((PASSES+1)); }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES+1)); }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }

JAR="$(mktemp)"
UNWIRE_LOG=""
# Set for the W2 window ONLY: between `idp unwire` (which rewrites the env so
# the prod-pinned server crash-loops) and the step-6 re-wire. An abort in that
# window -- Ctrl-C, TERM, or any early exit -- otherwise leaves andyur-server
# and andyur-worker crash-looping forever (compose restart: unless-stopped)
# with nothing left to re-wire them. cleanup re-wires when the flag is set, so
# every exit path out of the danger window restores a bootable stack.
UNWIRED_DANGER=""
cleanup(){
  local rc=$?
  if [ -n "$UNWIRED_DANGER" ]; then
    printf '\n\033[1m== aborted inside the W2 unwired window: re-wiring so the stack can boot ==\033[0m\n'
    bash "$HERE/infra/docker-stack.sh" idp wire >/dev/null 2>&1 \
      && echo "  re-wired; control plane can boot again" \
      || echo "  RE-WIRE FAILED; run './run.sh idp wire' by hand to recover andyur-server"
  fi
  rm -f "$JAR" ${UNWIRE_LOG:+"$UNWIRE_LOG"}
  return $rc
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

opy(){ # run python in a container-attested OPERATOR container (script on stdin)
  docker compose --env-file "$ENV_FILE" -f "$HERE/infra/docker-compose.yml" \
    --profile operator run -T --rm --no-deps --entrypoint python andyur-cli -
}

netcurl(){ net="$1"; shift; docker run --rm -i --network "$net" "$CURL_IMAGE" "$@"; }

say "0. preconditions: reference IdP + dockerized control plane running"
command -v docker >/dev/null || { echo "docker required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon not reachable" >&2; exit 1; }
if [ "$(docker inspect -f '{{.State.Running}}' andyur-keycloak 2>/dev/null)" != "true" ]; then
  bash "$HERE/infra/docker-stack.sh" idp up < /dev/null \
    || { bad "reference IdP failed to come up"; exit 1; }
fi
if [ "$(docker inspect -f '{{.State.Running}}' andyur-server 2>/dev/null)" != "true" ]; then
  info "dockerized control plane absent; bringing it up (first run builds images)"
  bash "$HERE/infra/docker-stack.sh" up \
    || { bad "docker deployment failed to come up"; exit 1; }
fi
PUB="$(docker port andyur-keycloak 8080/tcp | head -1)"
[ -n "$PUB" ] || { bad "keycloak publishes no host port"; exit 1; }
ISSUER="http://$PUB/realms/andyur"
TOKEN_EP="$ISSUER/protocol/openid-connect/token"
ALICE_PW="$(grep '^ANDYUR_IDP_PASSWORD_ALICE=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
BOB_PW="$(grep '^ANDYUR_IDP_PASSWORD_BOB=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
CAROL_PW="$(grep '^ANDYUR_IDP_PASSWORD_CAROL=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
[ -n "$ALICE_PW" ] && [ -n "$BOB_PW" ] && [ -n "$CAROL_PW" ] \
  || { bad "demo user passwords missing from $ENV_FILE (run ./run.sh idp up)"; exit 1; }
ok "IdP + control plane present; issuer $ISSUER"

say "1. W1: wire the running control plane to the reference IdP"
bash "$HERE/infra/docker-stack.sh" idp wire \
  && ok "idp wire reconfigured the server (healthy after recreate)" \
  || { bad "idp wire failed"; exit 1; }

say "2. P1: the console's exact PKCE code flow against the reference IdP (carol)"
VERIFIER="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
CHALLENGE="$(printf '%s' "$VERIFIER" | python3 -c '
import base64, hashlib, sys
d = hashlib.sha256(sys.stdin.read().encode()).digest()
print(base64.urlsafe_b64encode(d).rstrip(b"=").decode())')"
STATE="$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')"
REDIRECT="http://127.0.0.1:8765/callback"
AUTHZ="$ISSUER/protocol/openid-connect/auth?client_id=andyur-console&response_type=code&scope=openid&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256"
FORM_ACTION="$(curl -s -c "$JAR" "$AUTHZ" \
  | grep -o 'action="[^"]*"' | head -1 | sed 's/^action="//; s/"$//' | sed 's/&amp;/\&/g')"
if [ -z "$FORM_ACTION" ]; then
  bad "no login form from Keycloak at the authorization endpoint"
else
  ok "authorization endpoint served the real login form"
fi
LOC="$(printf '%s' "$CAROL_PW" | curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=carol" --data-urlencode "password@-" "$FORM_ACTION")"
case "$LOC" in
  "$REDIRECT"*) ok "login redirected to the console's registered redirect URI" ;;
  *) bad "login did not redirect to the console callback: ${LOC:0:120}" ;;
esac
GOT_STATE="${LOC#*state=}"; GOT_STATE="${GOT_STATE%%&*}"
[ "$GOT_STATE" = "$STATE" ] \
  && ok "state round-tripped intact" || bad "state mismatch (got '$GOT_STATE')"
CODE="${LOC#*code=}"; CODE="${CODE%%&*}"
# exchange the single-use code: the whole form body rides stdin, so neither
# the code nor the verifier appears on argv
TOK_JSON="$(printf 'grant_type=authorization_code&client_id=andyur-console&redirect_uri=http%%3A%%2F%%2F127.0.0.1%%3A8765%%2Fcallback&code=%s&code_verifier=%s' \
  "$CODE" "$VERIFIER" | curl -s --data @- "$TOKEN_EP")"
CAROL_CLAIMS="$(printf '%s' "$TOK_JSON" | python3 -c '
import base64, json, sys
try:
    tok = json.load(sys.stdin)["access_token"]
    seg = tok.split(".")[1]
    p = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    aud = p.get("aud", [])
    aud = [aud] if isinstance(aud, str) else aud
    roles = (p.get("realm_access") or {}).get("roles") or []
    print(json.dumps({"iss": p.get("iss"), "aud_ok": "andyur" in aud,
                      "admin": "andyur-admin" in roles, "ok": True}))
except Exception as e:
    print(json.dumps({"error": str(e), "ok": False}))
')"
echo "$CAROL_CLAIMS" | grep -q '"ok": true' \
  && ok "PKCE code exchange issued a token (S256 verifier accepted)" \
  || bad "code exchange failed: $CAROL_CLAIMS ${TOK_JSON:0:120}"
echo "$CAROL_CLAIMS" | grep -qF "\"iss\": \"$ISSUER\"" \
  && ok "token iss is the canonical issuer" || bad "wrong iss: $CAROL_CLAIMS"
echo "$CAROL_CLAIMS" | grep -q '"aud_ok": true' \
  && ok "token aud includes andyur" || bad "aud missing: $CAROL_CLAIMS"
echo "$CAROL_CLAIMS" | grep -q '"admin": true' \
  && ok "carol's token carries andyur-admin" || bad "no admin role: $CAROL_CLAIMS"
CAROL_TOK="$(printf '%s' "$TOK_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))')"

# S256 NEGATIVE: the positive above proves the CORRECT verifier is ACCEPTED,
# which stays green even if PKCE is not enforced at all (a client with no
# challenge method set accepts any verifier). So prove the challenge is
# actually BOUND: a fresh code exchanged with a WRONG verifier must be refused.
# Without this, S256 rests entirely on the realm's pkce.code.challenge.method
# attribute, which nothing here asserts.
NEG_JAR="$(mktemp "${JAR%/*}/negjar.XXXXXX")"
NEG_V="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
NEG_C="$(printf '%s' "$NEG_V" | python3 -c '
import base64, hashlib, sys
print(base64.urlsafe_b64encode(hashlib.sha256(sys.stdin.read().encode()).digest()).rstrip(b"=").decode())')"
NEG_AUTHZ="$ISSUER/protocol/openid-connect/auth?client_id=andyur-console&response_type=code&scope=openid&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&state=neg&code_challenge=$NEG_C&code_challenge_method=S256"
NEG_ACTION="$(curl -s -c "$NEG_JAR" "$NEG_AUTHZ" \
  | grep -o 'action="[^"]*"' | head -1 | sed 's/^action="//; s/"$//' | sed 's/&amp;/\&/g')"
NEG_LOC="$(printf '%s' "$CAROL_PW" | curl -s -b "$NEG_JAR" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=carol" --data-urlencode "password@-" "$NEG_ACTION")"
NEG_CODE="${NEG_LOC#*code=}"; NEG_CODE="${NEG_CODE%%&*}"
# Exchange the fresh, valid code with a DIFFERENT verifier than its challenge.
NEG_RESP="$(printf 'grant_type=authorization_code&client_id=andyur-console&redirect_uri=http%%3A%%2F%%2F127.0.0.1%%3A8765%%2Fcallback&code=%s&code_verifier=%s' \
  "$NEG_CODE" "$VERIFIER" | curl -s -o /dev/null -w '%{http_code}' --data @- "$TOKEN_EP")"
rm -f "$NEG_JAR"
[ -n "$NEG_CODE" ] && [ "$NEG_CODE" != "$NEG_LOC" ] \
  && ok "negative setup: fresh authorization code obtained for the S256 check" \
  || bad "negative setup failed: no fresh code (loc: ${NEG_LOC:0:80})"
case "$NEG_RESP" in
  400|401) ok "wrong PKCE verifier is REFUSED ($NEG_RESP) -- S256 is enforced, not decorative" ;;
  200) bad "wrong PKCE verifier was ACCEPTED (200): the client is not enforcing S256" ;;
  *) bad "wrong-verifier exchange returned $NEG_RESP; expected a 400/401 refusal" ;;
esac

say "3. P2: the dockerized server enforces the split on real reference-IdP tokens"
# Fixture names are unique per invocation: a triggered run cannot be finalized
# by the operator under REQUIRE_RUN_SVID (only its runner can), so a fixed name
# would 409 on the next run. Terminal leftovers are swept best-effort below.
SUF="$(date +%s)"
# HONEST SCOPE: carol above went through the console's real Authorization Code
# + PKCE flow. alice and bob use ROPC (the password grant) purely as a test
# convenience to mint two more subjects cheaply -- ROPC is RFC 9700
# "MUST NOT" and is NOT the console's path; it stays enabled only on the
# andyur-cli TEST client in this demo realm. What P2 actually proves for alice
# and bob is the SERVER'S enforcement over valid reference-IdP tokens (the
# admin/user split, owner scoping, isolation), not the login flow -- only
# carol's leg certifies the flow. Do not read the ROPC convenience here as a
# blessing of the password grant in any real deployment.
ropc_token(){ # user pw -> access_token (password via stdin)
  printf '%s' "$2" | curl -sf -d grant_type=password -d client_id=andyur-cli \
    -d "username=$1" --data-urlencode "password@-" "$TOKEN_EP" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'
}
ALICE_TOK="$(ropc_token alice "$ALICE_PW")"
BOB_TOK="$(ropc_token bob "$BOB_PW")"
[ -n "$ALICE_TOK" ] && [ -n "$BOB_TOK" ] && [ -n "$CAROL_TOK" ] \
  || { bad "could not obtain all three user tokens"; exit 1; }
ALICE_SUB="$(printf '%s' "$ALICE_TOK" | python3 -c '
import base64, json, sys
seg = sys.stdin.read().split(".")[1]
print(json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))["sub"])')"
info "alice sub = $ALICE_SUB (setup-created)"
# The checks run INSIDE a container-attested operator container -- the docker
# deployment's own identity path -- so every call carries a real JWT-SVID
# alongside the user token. Tokens ride the heredoc on stdin, never argv.
opy <<PY
import sys, httpx
from andyur import identity

results = []
def check(name, cond, detail=""):
    results.append(cond)
    print(("  \033[32mPASS\033[0m  " if cond else "  \033[31mFAIL\033[0m  ")
          + name + ("  " + detail if detail else ""))

alice = "$ALICE_TOK"
bob = "$BOB_TOK"
carol = "$CAROL_TOK"
alice_sub = "$ALICE_SUB"
a_name = "composed-alice-$SUF"
b_name = "composed-bob-$SUF"
c = httpx.Client(base_url="http://andyur-server:8642", timeout=20,
                 auth=identity.httpx_auth())
def H(t): return {"X-Andyur-User-Token": t}

me_c = c.get("/me", headers=H(carol)).json()
me_a = c.get("/me", headers=H(alice)).json()
check("P2  /me: carol IS admin (reference-IdP realm role)", me_c.get("admin") is True, str(me_c))
check("P2  /me: alice is not admin", me_a.get("admin") is False, str(me_a))

# Best-effort sweep of earlier invocations' fixtures. Deletion is refused for
# an agent whose triggered run never reached a terminal state (only its runner
# may finalize it under REQUIRE_RUN_SVID), which is why the sweep is
# best-effort and this invocation's names are unique.
for tok in (alice, bob):
    for row in c.get("/agents", headers=H(tok)).json():
        if row["name"].startswith("composed-"):
            c.delete(f"/agents/{row['name']}", headers=H(tok))

r = c.post("/agents", json={"name": a_name}, headers=H(alice))
check("P2  alice creates her agent (server validated the reference-IdP token)",
      r.status_code == 201, "-> " + str(r.status_code))
r = c.post("/agents", json={"name": b_name}, headers=H(bob))
check("P2  bob creates his agent", r.status_code == 201, "-> " + str(r.status_code))

rows = c.get("/agents", headers=H(carol)).json()
owners = {a["name"]: a.get("owner") for a in rows
          if a["name"] in (a_name, b_name)}
check("P2  ADMIN carol sees BOTH owners' agents with owners set",
      set(owners) == {a_name, b_name} and all(owners.values()),
      str(owners))
names = [a["name"] for a in c.get("/agents", headers=H(alice)).json()]
check("P2  USER alice's list is owner-scoped (hers in, bob's out)",
      a_name in names and b_name not in names
      and all(n.startswith("composed-alice") for n in names), str(names))

r = c.post(f"/agents/{a_name}/pause", headers=H(bob))
check("P2  bob cannot pause alice's agent (404, no oracle)", r.status_code == 404,
      "-> " + str(r.status_code))
paused = c.get(f"/agents/{a_name}", headers=H(alice)).json()["paused"]
check("P2  ...and it provably did not pause", not paused, str(paused))
check("P2  USER alice refused /workers (403)",
      c.get("/workers", headers=H(alice)).status_code == 403)
check("P2  ADMIN carol reads /workers",
      c.get("/workers", headers=H(carol)).status_code == 200)

r = c.post(f"/agents/{a_name}/trigger", json={"reason": "composed"}, headers=H(alice))
check("P2  owner alice triggers; run created", r.status_code == 201, "-> " + str(r.status_code))
run_id = r.json().get("run_id", "")
import base64, json
rt = c.post(f"/runs/{run_id}/token").json().get("run_token", "")
seg = rt.split(".")[0]
payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
check("P2  signed run grant carries alice's setup-created sub",
      payload.get("s") == alice_sub, "grant sub=" + str(payload.get("s")))

r = c.get("/agents/composed-alice")
check("(-) no user token refused (401)", r.status_code == 401, "-> " + str(r.status_code))
r = c.get("/agents/composed-alice", headers=H("not.a.real.token"))
check("(-) forged token refused (401)", r.status_code == 401, "-> " + str(r.status_code))

sys.exit(0 if all(results) else 1)
PY
if [ $? -eq 0 ]; then
  ok "operator-attested composed enforcement block passed"
else
  bad "one or more composed enforcement checks failed (see above)"
fi

say "4. N1: with user-auth live, the run network STILL cannot reach the IdP"
netcurl andyur-runs -sf --max-time 5 "http://andyur-server:8642/health" >/dev/null \
  && ok "(+) run network reaches the dual-homed server (probe + net are live)" \
  || bad "(+) run-network positive control failed -- negatives would be vacuous"
for name in keycloak andyur-keycloak; do
  if netcurl andyur-runs -sf --max-time 5 "http://$name:8080/realms/andyur/.well-known/openid-configuration" >/dev/null 2>&1; then
    bad "run network reached the IdP as '$name' while user-auth is live"
  else
    ok "run network cannot reach the IdP as '$name'"
  fi
done
KC_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "andyur-control").IPAddress}}' andyur-keycloak 2>/dev/null)"
if [ -z "$KC_IP" ]; then
  bad "no keycloak control-net IP -- IP probe cannot run"
elif netcurl andyur-runs -sf --max-time 5 "http://$KC_IP:8080/realms/andyur/.well-known/openid-configuration" >/dev/null 2>&1; then
  bad "run network reached the IdP by IP $KC_IP"
else
  ok "run network cannot reach the IdP by IP $KC_IP"
fi

say "5. W2: unwired prod REFUSES to boot (the profile gate, live)"
# There is no user-auth-off posture in the prod-pinned compose to restore:
# assert_profile requires ANDYUR_USER_AUTH=on, so a successful unwired boot
# here would mean the requirement was silently dropped -- exactly the
# mutation this step exists to catch.
# Enter the danger window: from here until the re-wire below, an abort must
# re-wire (cleanup does, keyed on this flag). Assigned BEFORE unwire runs, so
# even a kill during unwire's own health poll is covered.
UNWIRED_DANGER=1
UNWIRE_LOG="$(mktemp)"
if bash "$HERE/infra/docker-stack.sh" idp unwire >"$UNWIRE_LOG" 2>&1; then
  bad "idp unwire left a prod control plane serving without user-auth"
else
  ok "unwired prod control plane refused to become healthy"
fi
# The refusal must be the profile gate by name, not an unrelated crash. The
# recreated container may still be starting or in restart backoff when we
# first look, so the log read is a bounded poll, not a single sample.
NAMED=""
for _ in $(seq 1 45); do
  # Capture-then-match; the piped form false-negatives under pipefail because
  # grep -q exits early and SIGPIPEs docker. Root-caused in 644b63f.
  srv_logs="$(docker logs andyur-server 2>&1 || true)"
  case "$srv_logs" in *ANDYUR_USER_AUTH*) NAMED=1; break ;; esac
  sleep 1
done
if [ -n "$NAMED" ]; then
  ok "the boot refusal names ANDYUR_USER_AUTH (InsecureProfile)"
else
  bad "the failed boot does not name ANDYUR_USER_AUTH; wrong failure"
  info "unwire tail: $(tail -3 "$UNWIRE_LOG" | tr '\n' ' | ')"
  info "server log tail: $(docker logs andyur-server 2>&1 | tail -5 | tr '\n' ' | ')"
fi
# UNWIRE_LOG is reaped by cleanup (it may hold the diagnosis if we abort here).

say "6. restore: re-wire so the stack is left healthy"
bash "$HERE/infra/docker-stack.sh" idp wire \
  && ok "re-wired; control plane healthy again" \
  || bad "re-wire after the unwire negative failed"
# Left the danger window: the stack is wired again, so an abort past this point
# needs no re-wire.
UNWIRED_DANGER=""

echo
if [ "$FAILURES" -eq 0 ]; then
  say "idp-composed gate GREEN ($PASSES shell checks + the operator block)"
  echo "(stack left up, WIRED; unwired prod refuses to boot by design)"
  exit 0
else
  say "idp-composed gate RED ($FAILURES failures)"
  exit 1
fi
