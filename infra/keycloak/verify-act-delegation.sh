#!/usr/bin/env bash
# Does Keycloak emit the RFC 8693 `act` claim on a token exchange?
#
# This matters because `docs/decisions.md` #5 says the delegated token carries
# `act` = the run. If the adopter's AS cannot emit `act`, the token arriving at a
# tool is indistinguishable from the user calling directly, and that decision is
# unachievable against that AS.
#
# ANSWER, verified 7 August 2026 against Keycloak 26.7.1: NO. Not even with the
# delegation feature fully configured. Keycloak's `token-exchange-delegation`
# produces `may_act` (who MAY act) in the SUBJECT token; emitting `act` in the
# EXCHANGED token is a separate, still-open enhancement:
#   https://github.com/keycloak/keycloak/issues/12076
#   https://github.com/keycloak/keycloak/issues/38279
#
# Three earlier attempts reported "act absent" for the WRONG reason, and each was
# a false green. Recorded so nobody repeats them:
#   1. a stale container held the port, so the test hit a different Keycloak
#   2. only the legacy umbrella flag `token-exchange` was enabled, not
#      `token-exchange-delegation:v1` + `parameterized-scopes`
#   3. the realm had no `delegation` client scope, so every delegation scope
#      spelling came back invalid_scope and Keycloak fell back to impersonation
# This script configures all of it and STILL gets `act` absent. That is the
# result worth trusting.
#
# Usage: ./verify-act-delegation.sh [down]
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="andyur-kc-act"
PORT="${ANDYUR_KC_ACT_PORT:-18087}"
IMAGE="${ANDYUR_KC_IMAGE:-quay.io/keycloak/keycloak:26.7}"
WANT_VERSION="${ANDYUR_KC_WANT_VERSION:-26.7}"
ISS="http://localhost:${PORT}/realms/andyur"
FEATURES="token-exchange-standard:v2,token-exchange-delegation:v1,parameterized-scopes,spiffe:v1,client-auth-federated:v1"

say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }

docker rm -f "$NAME" >/dev/null 2>&1 || true
[ "${1:-up}" = "down" ] && { echo "torn down"; exit 0; }

# GUARD 1: the port must be free. A stale container answering here is the exact
# false green that made the first three runs of this test worthless.
say "0. the port must be free"
if (echo >/dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then
  bad "port $PORT is held by: $(docker ps --filter publish=${PORT} --format '{{.Names}} ({{.Image}})')"
  echo "  set ANDYUR_KC_ACT_PORT to something else, or stop that container"; exit 1
fi
ok "port $PORT free"

say "1. Keycloak $IMAGE with the delegation features"
info "$FEATURES"
docker run -d --name "$NAME" -p ${PORT}:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false \
  -v "$HERE/realm-andyur.json:/opt/keycloak/data/import/realm-andyur.json:ro" \
  "$IMAGE" start-dev --import-realm --features="$FEATURES" || {
    bad "docker run failed"; exit 1; }

sleep 3
[ "$(docker inspect -f '{{.State.Status}}' $NAME 2>/dev/null)" = "running" ] || {
  bad "container did not start; feature flags likely rejected"
  docker logs "$NAME" 2>&1 | tail -20; exit 1; }
ok "container running (so the feature flags were ACCEPTED)"

for i in $(seq 1 90); do
  [ "$(docker inspect -f '{{.State.Status}}' $NAME 2>/dev/null)" != "running" ] && {
    bad "died during boot"; docker logs "$NAME" 2>&1 | tail -20; exit 1; }
  code=$(curl -s -o /dev/null -w '%{http_code}' "$ISS/.well-known/openid-configuration" 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 2
done
[ "$code" = "200" ] || { bad "realm never came up"; docker logs "$NAME" 2>&1 | tail -20; exit 1; }
ok "realm live"

# GUARD 2: prove the server answering is the one we started, at the version we think.
say "2. prove we are testing the server we started"
banner=$(docker logs "$NAME" 2>&1 | grep -o "Keycloak [0-9.]*" | head -1)
case "$banner" in
  *"Keycloak ${WANT_VERSION}"*) ok "banner: $banner" ;;
  *) bad "expected Keycloak $WANT_VERSION, got '${banner:-none}'"; exit 1 ;;
esac
mapped=$(docker port "$NAME" 8080 2>/dev/null | head -1)
case "$mapped" in
  *":${PORT}") ok "port $PORT maps to $NAME" ;;
  *) bad "port $PORT does not map to $NAME (got '${mapped:-none}')"; exit 1 ;;
esac

say "3. configure delegation properly (the step the first three runs missed)"
TOK=$(curl -s -d "grant_type=password&client_id=admin-cli&username=admin&password=admin" \
  "http://localhost:${PORT}/realms/master/protocol/openid-connect/token" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])' 2>/dev/null)
[ -n "$TOK" ] || { bad "no admin token"; exit 1; }
adm(){ curl -s -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" "$@"; }
KC="http://localhost:${PORT}/admin/realms/andyur"

# Keycloak auto-creates this scope in NEW realms when the feature is on; the
# hand-built realm-andyur.json predates it, so create it explicitly.
adm -X POST "$KC/client-scopes" -d '{
  "name":"delegation","description":"token exchange delegation","protocol":"openid-connect",
  "attributes":{"include.in.token.scope":"true","parameterized.scope.type":"delegation",
    "is.parameterized.scope":"true","display.on.consent.screen":"false"},
  "protocolMappers":[{"name":"may_act sub","protocol":"openid-connect",
    "protocolMapper":"oidc-parameterized-scope-user-property-mapper","consentRequired":false,
    "config":{"introspection.token.claim":"true","multivalued":"false","user.attribute":"id",
      "id.token.claim":"true","access.token.claim":"true","claim.name":"may_act.sub",
      "jsonType.label":"String"}}]}' -o /dev/null -w '   delegation scope -> HTTP %{http_code}\n'

SID=$(adm "$KC/client-scopes" | python3 -c 'import sys,json;print(next((s["id"] for s in json.load(sys.stdin) if s["name"]=="delegation"),""))')
[ -n "$SID" ] || { bad "delegation scope not created"; exit 1; }
for CID in andyur-cli andyur-agent; do
  UUID=$(adm "$KC/clients?clientId=$CID" | python3 -c 'import sys,json;a=json.load(sys.stdin);print(a[0]["id"] if a else "")')
  [ -n "$UUID" ] && adm -X PUT "$KC/clients/$UUID/optional-client-scopes/$SID" -o /dev/null -w "   attach to $CID -> HTTP %{http_code}\n"
done

# Without the impersonation role the delegation scope is SILENTLY dropped and
# may_act never appears -- which reads exactly like "the feature does not work".
SA=$(adm "$KC/users?username=service-account-andyur-agent&exact=true" | python3 -c 'import sys,json;a=json.load(sys.stdin);print(a[0]["id"] if a else "")')
RM=$(adm "$KC/clients?clientId=realm-management" | python3 -c 'import sys,json;a=json.load(sys.stdin);print(a[0]["id"] if a else "")')
ROLE=$(adm "$KC/clients/$RM/roles/impersonation")
adm -X POST "$KC/users/$SA/role-mappings/clients/$RM" -d "[$ROLE]" -o /dev/null -w '   impersonation role -> HTTP %{http_code}\n'

say "4. the test"
python3 - "$ISS" <<'PY'
import json,sys,base64,urllib.parse,urllib.request
T=sys.argv[1]+"/protocol/openid-connect/token"
def post(d):
    r=urllib.request.Request(T,data=urllib.parse.urlencode(d).encode(),
        headers={"Content-Type":"application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(r,timeout=20) as x: return x.status,json.loads(x.read())
    except urllib.error.HTTPError as e:
        try: return e.code,json.loads(e.read() or b'{}')
        except Exception: return e.code,{}
def peek(t):
    p=t.split(".")[1]; return json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))
fails = []
def r(c,m,d=""):
    print(("  \033[32mPASS\033[0m  " if c else "  \033[31mFAIL\033[0m  ")+m+("  "+d if d else ""))
    # Without an accumulator a FAIL printed red and the script still exited 0,
    # headline result and all. A harness that cannot report failure is not one.
    if not c: fails.append(m)
    return c

st,j=post({"grant_type":"password","client_id":"andyur-cli","username":"alice",
    "password":"alice-password","scope":"openid files:read delegation:service-account-andyur-agent"})
if st!=200: print("  alice login failed:",st,j); sys.exit(1)
alice=j["access_token"]; ma=peek(alice).get("may_act")

# POSITIVE CONTROL: if may_act is absent the delegation feature is not active and
# an "act absent" result below would prove nothing.
if not r(bool(ma), "positive control: delegation feature IS active (may_act present)", repr(ma)):
    print("\n  Without this the result below is meaningless. Aborting."); sys.exit(1)

st,j=post({"grant_type":"client_credentials","client_id":"andyur-agent","client_secret":"agent-secret"})
actor=j.get("access_token")
r(bool(actor), "actor token obtained")

st,j=post({"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange",
    "client_id":"andyur-agent","client_secret":"agent-secret","subject_token":alice,
    "subject_token_type":"urn:ietf:params:oauth:token-type:access_token",
    "actor_token":actor,"actor_token_type":"urn:ietf:params:oauth:token-type:access_token",
    "audience":"tool-files","scope":"files:read"})
if st!=200: print("  exchange failed:",st,j); sys.exit(1)
c=peek(j["access_token"])
# was r(True, ...), which cannot fail. The status is the property.
r(st==200,"exchange performed","-> %d"%st)
r(c.get("sub")==peek(alice)["sub"], "sub preserved (the user does not drift)")
print("  \033[36m·\033[0m claims: %s" % sorted(c.keys()))
print("  \033[36m·\033[0m act = %r    azp = %r" % (c.get("act"), c.get("azp")))
print()
if c.get("act"):
    print("  \033[33mRESULT CHANGED:\033[0m Keycloak now emits `act`. Update")
    print("  docs/decisions.md #5 and docs/replaceable-components.md.")
    sys.exit(0)
print("  \033[1mRESULT (expected): Keycloak does NOT emit `act`.\033[0m")
print("  The only trace of the acting party is azp, which names the CLIENT,")
print("  not the run. See docs/decisions.md #5.")
if fails:
    print("\n  \033[31m%d check(s) failed\033[0m" % len(fails)); sys.exit(1)
PY

say "done — '$NAME' left up for inspection (tear down: $0 down)"
