#!/usr/bin/env bash
# LIVE gate for the reference IdP (compose `idp` profile): proves the runnable
# Keycloak is REAL (a genuine login issues a validated token with the canonical
# issuer) and that its reachability contract holds at the network layer:
#
#   P1  OIDC discovery works from the control network (http://keycloak:8080)
#       and from the host loopback publish, and both report the SAME issuer
#   P2  a real password login as a SETUP-CREATED demo user (passwords are
#       asked/generated at idp up, never committed) issues a token with the
#       canonical iss and aud=andyur; the committed bootstrap password is
#       dead, alice's sub is not the committed fixture id, and recreated
#       carol still carries andyur-admin
#   P3  the console client (andyur-console) REFUSES the password grant: it is
#       Auth Code + PKCE only
#   P4  the bootstrap admin took the GENERATED password (login succeeds with
#       it) and the default "admin" password is refused
#   N1  keycloak is on exactly {andyur-control, andyur-idp} -- never the run
#       network
#   N2  andyur-idp is Internal (no host/internet route for the IdP database)
#   N3  keycloak-db is on andyur-idp ONLY and publishes no host port
#   N4  keycloak's only host publish is bound to 127.0.0.1
#   N5  from the RUN network, the IdP is unreachable by name AND by the same
#       IP:port that the control network provably CAN reach (paired positive
#       control, so this probe can never pass vacuously)
#
# Mutations that must turn this gate red: `docker network connect andyur-runs
# andyur-keycloak` (N1 membership + the N5 container-NAME probe; the N5 IP
# probe reads the control-net IP, unroutable cross-bridge, so it stays green
# under this one), `docker network connect andyur-control andyur-keycloak-db`
# (N3), recreating andyur-idp without --internal (N2), publishing on 0.0.0.0
# (N4), enabling directAccessGrants on andyur-console (P3), a realm import
# that silently failed (P2), resetting andyur-agent's secret back to the
# committed value (4b), resetting alice's password to the committed bootstrap
# value or skipping user recreation so the fixture id survives (P2), or
# dropping carol's role re-attachment (P2).
#
# Usage: ./verify-idp-reference.sh   (stack is brought up if needed and left
# up; tear down with ./run.sh idp down)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$HERE/data/docker.env"
CURL_IMAGE="${ANDYUR_CURL_IMAGE:-curlimages/curl:8.10.1}"
RUN_NETWORK="andyur-runs"

FAILURES=0; PASSES=0
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASSES=$((PASSES+1)); }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES+1)); }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }

say "0. preconditions: docker + the idp profile up (via the supported wrapper)"
command -v docker >/dev/null || { echo "docker required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon not reachable" >&2; exit 1; }
# RUNNING, not merely existing: a created-but-crashed container (e.g. secrets
# missing) must route through idp up, whose readiness wait diagnoses it.
if [ "$(docker inspect -f '{{.State.Running}}' andyur-keycloak 2>/dev/null)" != "true" ]; then
  bash "$HERE/infra/docker-stack.sh" idp up \
    || { bad "idp stack failed to come up (./run.sh idp up for details)"; exit 1; }
fi
ok "idp stack running"

# Everything below derives from the LIVE containers, not from re-parsed config,
# so the gate cannot drift from what actually runs.
PUB="$(docker port andyur-keycloak 8080/tcp | head -1)"
[ -n "$PUB" ] || { bad "keycloak publishes no host port"; exit 1; }
ISSUER="http://$PUB/realms/andyur"
info "published at $PUB; canonical issuer $ISSUER"

# in-network probe helper (curl on a named docker network); -i so callers can
# feed secrets via stdin (curl name@- forms) instead of argv, which host ps
# can read for the life of the container
netcurl(){ net="$1"; shift; docker run --rm -i --network "$net" "$CURL_IMAGE" "$@"; }

say "1. P1: discovery from the control network and the host agree on one issuer"
for _ in $(seq 1 120); do
  curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1 && break
  sleep 2
done
HOST_ISS="$(curl -sf "$ISSUER/.well-known/openid-configuration" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' 2>/dev/null)"
[ "$HOST_ISS" = "$ISSUER" ] \
  && ok "host discovery reports the canonical issuer" \
  || bad "host discovery issuer: '$HOST_ISS' (wanted $ISSUER)"
NET_ISS="$(netcurl andyur-control -sf http://keycloak:8080/realms/andyur/.well-known/openid-configuration \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' 2>/dev/null)"
[ "$NET_ISS" = "$ISSUER" ] \
  && ok "control-network discovery reports the SAME issuer (split-horizon safe)" \
  || bad "control-network issuer: '$NET_ISS' (wanted $ISSUER)"

say "2. P2: a real login (setup-created user) issues a token with canonical iss/aud"
ALICE_PW="$(grep '^ANDYUR_IDP_PASSWORD_ALICE=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)"
if [ -z "$ALICE_PW" ]; then
  bad "no ANDYUR_IDP_PASSWORD_ALICE in $ENV_FILE (demo-user setup never ran)"
  CLAIMS='{}'
else
  TOKEN_JSON="$(printf '%s' "$ALICE_PW" | netcurl andyur-control -sf \
    -d grant_type=password -d client_id=andyur-cli \
    -d username=alice --data-urlencode "password@-" \
    http://keycloak:8080/realms/andyur/protocol/openid-connect/token || true)"
  CLAIMS="$(printf '%s' "$TOKEN_JSON" | python3 -c '
import base64, json, sys
try:
    tok = json.load(sys.stdin)["access_token"]
    seg = tok.split(".")[1]
    p = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    aud = p.get("aud", [])
    aud = [aud] if isinstance(aud, str) else aud
    roles = (p.get("realm_access") or {}).get("roles") or []
    print(json.dumps({"iss": p.get("iss"), "aud_ok": "andyur" in aud,
                      "sub": p.get("sub") or "", "admin": "andyur-admin" in roles}))
except Exception as e:
    print(json.dumps({"error": str(e)}))
')"
fi
echo "$CLAIMS" | grep -qF "\"iss\": \"$ISSUER\"" \
  && ok "alice's real token (setup-set password) carries iss=$ISSUER" \
  || bad "login/iss failed: $CLAIMS ${TOKEN_JSON:0:120}"
echo "$CLAIMS" | grep -q '"aud_ok": true' \
  && ok "token audience includes 'andyur'" \
  || bad "audience missing: $CLAIMS"
# on-the-fly creation held: the committed fixture's fixed id must be gone.
# Self-sufficient: an absent/empty sub is its own FAIL, so this check cannot
# pass vacuously if the login checks above are ever reordered away.
SUB="$(echo "$CLAIMS" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("sub",""))' 2>/dev/null)"
if [ -z "$SUB" ]; then
  bad "no sub claim obtained for alice -- fixture-id check cannot run"
elif [ "$SUB" = "11111111-1111-1111-1111-111111111111" ]; then
  bad "alice still carries the COMMITTED fixture id (users were not created at setup)"
else
  ok "alice is a setup-created user (sub $SUB, not the committed fixture id)"
fi
# paired negative for the admin role: a plain user must NOT carry andyur-admin
# (a grant-to-everyone misconfig would pass the carol positive alone)
echo "$CLAIMS" | grep -q '"admin": false' \
  && ok "(-) alice does NOT carry andyur-admin" \
  || bad "alice CARRIES andyur-admin (role granted too broadly) or claims unreadable"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -d grant_type=password \
  -d client_id=andyur-cli -d username=alice -d password=alice-password \
  "$ISSUER/protocol/openid-connect/token")"
case "$CODE" in
  400|401) ok "committed bootstrap password refused for alice ($CODE)" ;;
  *) bad "committed bootstrap password still ACCEPTED ($CODE)" ;;
esac
# carol's admin role survived recreation (the role is attached at creation)
CAROL_PW="$(grep '^ANDYUR_IDP_PASSWORD_CAROL=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)"
if [ -z "$CAROL_PW" ]; then
  bad "no ANDYUR_IDP_PASSWORD_CAROL in $ENV_FILE (demo-user setup never ran)"
else
  ROLES_OK="$(printf '%s' "$CAROL_PW" | curl -s -d grant_type=password \
    -d client_id=andyur-cli -d username=carol --data-urlencode "password@-" \
    "$ISSUER/protocol/openid-connect/token" | python3 -c '
import base64, json, sys
try:
    tok = json.load(sys.stdin)["access_token"]
    seg = tok.split(".")[1]
    p = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    roles = (p.get("realm_access") or {}).get("roles") or []
    print("yes" if "andyur-admin" in roles else "no")
except Exception:
    print("no")
')"
  [ "$ROLES_OK" = "yes" ] \
    && ok "setup-created carol carries the andyur-admin realm role" \
    || bad "recreated carol LOST the andyur-admin role"
fi

say "3. P3: the console client refuses the password grant (PKCE-only client)"
CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  -d grant_type=password -d client_id=andyur-console \
  -d username=alice -d password=alice-password \
  "$ISSUER/protocol/openid-connect/token")"
case "$CODE" in
  400|401) ok "andyur-console ROPC refused ($CODE)" ;;
  *) bad "andyur-console ROPC not refused (got $CODE)" ;;
esac

say "4. P4: bootstrap admin uses the GENERATED secret, not a default"
ADMIN_USER="$(grep '^ANDYUR_IDP_ADMIN_USER=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2)"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PW="$(grep '^ANDYUR_IDP_ADMIN_PASSWORD=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)"
[ -n "$ADMIN_PW" ] || bad "no ANDYUR_IDP_ADMIN_PASSWORD in $ENV_FILE"
MASTER="http://$PUB/realms/master/protocol/openid-connect/token"
CODE="$(printf '%s' "$ADMIN_PW" | curl -s -o /dev/null -w '%{http_code}' \
  -d grant_type=password -d client_id=admin-cli -d "username=$ADMIN_USER" \
  --data-urlencode "password@-" "$MASTER")"
[ "$CODE" = 200 ] \
  && ok "admin login with the generated password (positive control)" \
  || bad "admin login with the generated password failed ($CODE)"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -d grant_type=password \
  -d client_id=admin-cli -d "username=$ADMIN_USER" -d password=admin "$MASTER")"
[ "$CODE" = 401 ] \
  && ok "default password 'admin' refused" \
  || bad "default password 'admin' was ACCEPTED ($CODE)"

say "4b. the andyur-agent demo secret was rotated off the committed value"
# The realm ships a public secret for this CONFIDENTIAL, token-exchange-enabled
# client; idp_up rotates it live. The committed value must be dead here, and
# the generated one must work (the positive control proving rotation, not
# client breakage, is what the refusal shows).
TOKEN_EP="$ISSUER/protocol/openid-connect/token"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -d grant_type=client_credentials \
  -d client_id=andyur-agent -d client_secret=agent-secret "$TOKEN_EP")"
case "$CODE" in
  400|401) ok "committed 'agent-secret' refused for the confidential andyur-agent client ($CODE)" ;;
  *) bad "committed 'agent-secret' still ACCEPTED ($CODE) -- rotation did not hold" ;;
esac
AGENT_SECRET="$(grep '^ANDYUR_IDP_AGENT_CLIENT_SECRET=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)"
if [ -z "$AGENT_SECRET" ]; then
  bad "no ANDYUR_IDP_AGENT_CLIENT_SECRET in $ENV_FILE (rotation never ran?)"
else
  CODE="$(printf '%s' "$AGENT_SECRET" | curl -s -o /dev/null -w '%{http_code}' \
    -d grant_type=client_credentials -d client_id=andyur-agent \
    --data-urlencode "client_secret@-" "$TOKEN_EP")"
  [ "$CODE" = 200 ] \
    && ok "(+) rotated secret authenticates andyur-agent (client alive; refusal above is the rotation)" \
    || bad "(+) rotated secret refused ($CODE) -- refusal above proves nothing"
fi

say "5. N1-N4: network membership, internality, and loopback-only publish"
# Every lookup is guarded so a missing container/network becomes a FAIL entry,
# never a crash: an exception here once aborted the block before its print, the
# shell read the empty output as "zero problems", and this section printed a
# blanket PASS for topology it had not verified (found by review, reproduced
# live with the db container renamed away).
TOPO="$(python3 - <<'PY'
import json, subprocess

def inspect(*args):
    try:
        return json.loads(subprocess.check_output(
            ["docker", "inspect", *args], stderr=subprocess.DEVNULL))[0]
    except Exception:
        return None

fails = []
kc = inspect("andyur-keycloak")
ip = ""
if kc is None:
    fails.append("N1 andyur-keycloak container not inspectable")
else:
    networks = kc["NetworkSettings"]["Networks"]
    nets = set(networks)
    if nets != {"andyur-control", "andyur-idp"}:
        fails.append(f"N1 keycloak networks {sorted(nets)} != [andyur-control, andyur-idp]")
    if "andyur-runs" in nets:
        fails.append("N1 keycloak is ON the run network")
    ip = networks.get("andyur-control", {}).get("IPAddress") or ""
    if not ip:
        fails.append("N1 keycloak has no address on andyur-control")
    ports = kc["NetworkSettings"].get("Ports") or {}
    bindings = [b for v in ports.values() if v for b in v]
    if not bindings:
        fails.append("N4 keycloak publishes nothing (expected one loopback bind)")
    for b in bindings:
        if b.get("HostIp") not in ("127.0.0.1", "::1"):
            fails.append(f"N4 non-loopback publish: {b}")

net = inspect("--type=network", "andyur-idp")
if net is None:
    fails.append("N2 andyur-idp network not inspectable")
else:
    if net.get("Internal") is not True:
        fails.append("N2 andyur-idp is not Internal")
    # exact membership: the internal db segment admits ONLY the IdP pair, so a
    # third service quietly joining it (a route into the IdP database) fails
    # (NOTE: no apostrophes in this heredoc -- macOS bash 3.2 scans quotes
    # inside a heredoc nested in $(...) and reports a bogus unmatched quote)
    members = {c.get("Name") for c in (net.get("Containers") or {}).values()}
    if members != {"andyur-keycloak", "andyur-keycloak-db"}:
        fails.append(f"N2 andyur-idp members {sorted(members)} != [andyur-keycloak, andyur-keycloak-db]")

db = inspect("andyur-keycloak-db")
if db is None:
    fails.append("N3 andyur-keycloak-db container not inspectable")
else:
    db_nets = set(db["NetworkSettings"]["Networks"])
    if db_nets != {"andyur-idp"}:
        fails.append(f"N3 keycloak-db networks {sorted(db_nets)} != [andyur-idp]")
    if any(v for v in (db["NetworkSettings"].get("Ports") or {}).values()):
        fails.append("N3 keycloak-db publishes a host port")

print(json.dumps({"fails": fails, "kc_ip": ip}))
PY
)"
if ! KC_IP="$(echo "$TOPO" | python3 -c 'import json,sys; print(json.load(sys.stdin)["kc_ip"])' 2>/dev/null)"; then
  bad "topology inspection produced no result -- treating N1-N4 as FAILED, not passed"
  KC_IP=""
fi
TOPO_FAILS="$(echo "$TOPO" | python3 -c 'import json,sys; [print(f) for f in json.load(sys.stdin)["fails"]]' 2>/dev/null)"
if [ -n "$TOPO_FAILS" ]; then
  while IFS= read -r line; do bad "$line"; done <<< "$TOPO_FAILS"
elif [ -n "$KC_IP" ]; then
  ok "keycloak on exactly {andyur-control, andyur-idp}; andyur-idp Internal with exactly the IdP pair; db unpublished; publish loopback-only"
fi

say "6. N5: the run network cannot reach the IdP (with its own positive controls)"
# NEVER create or remove the real run network: docker-stack.sh owns its
# lifecycle, and a create/remove here can race an in-flight docker-up (found by
# review: an empty andyur-runs can be rm'd out from under a bring-up that has
# not attached containers yet). If the deployment's network exists, probe from
# it; otherwise probe from a gate-owned, uniquely named internal network --
# same bridge-isolation class, no shared state.
if docker network inspect "$RUN_NETWORK" >/dev/null 2>&1; then
  PROBE_NET="$RUN_NETWORK"; GATE_NET=""
else
  PROBE_NET="andyur-idp-gate-$$"; GATE_NET="$PROBE_NET"
  docker network create --internal "$PROBE_NET" >/dev/null \
    || { bad "could not create probe network $PROBE_NET"; exit 1; }
  info "FALLBACK MODE: $RUN_NETWORK absent, probing from gate-owned internal net $PROBE_NET -- the negatives below prove generic bridge-class isolation, NOT the deployment's actual run-network boundary; run docker-up first for the real-boundary form"
fi
# Same-network positive control: the probe must be able to reach SOMETHING on
# the run-class net, or a net that dropped all traffic for an unrelated reason
# would pass every negative below vacuously.
PEER="andyur-idp-gate-peer-$$"
# clean up the probe scaffolding on ANY exit, not just the linear path
gate_cleanup(){ docker rm -f "$PEER" >/dev/null 2>&1 || true
  [ -n "$GATE_NET" ] && docker network rm "$GATE_NET" >/dev/null 2>&1 || true; }
trap gate_cleanup EXIT
docker run -d --name "$PEER" --network "$PROBE_NET" --entrypoint sh \
  "${ANDYUR_ISO_IMAGE:-busybox:1.36}" \
  -c 'mkdir -p /www; echo ok>/www/i; httpd -f -p 80 -h /www' >/dev/null
PEER_UP=""
for _ in $(seq 1 10); do
  if netcurl "$PROBE_NET" -sf --max-time 5 "http://$PEER:80/i" >/dev/null 2>&1; then
    PEER_UP=1; break
  fi
  sleep 0.5
done
[ -n "$PEER_UP" ] \
  && ok "(+) probe reaches a peer ON the run-class net (the net passes intended traffic)" \
  || bad "(+) probe cannot reach a same-net peer -- the negatives below would be vacuous"
# positive controls FIRST, from the control network: by raw IP and by BOTH
# names -- proving each probe form detects reachability when it exists
if [ -z "$KC_IP" ]; then
  bad "no keycloak control-net IP (topology already failed) -- IP probes cannot run"
elif netcurl andyur-control -sf --max-time 5 "http://$KC_IP:8080/realms/andyur/.well-known/openid-configuration" >/dev/null; then
  ok "(+) control network reaches the IdP by IP $KC_IP (IP probe is live)"
else
  bad "(+) IP positive-control probe failed -- the negatives below would be vacuous"
fi
for name in keycloak andyur-keycloak; do
  netcurl andyur-control -sf --max-time 5 "http://$name:8080/realms/andyur/.well-known/openid-configuration" >/dev/null \
    && ok "(+) control network resolves+reaches the IdP as '$name' (name probe is live)" \
    || bad "(+) name positive-control '$name' failed -- its negative below would be vacuous"
done
if [ -n "$KC_IP" ] && netcurl "$PROBE_NET" -sf --max-time 5 "http://$KC_IP:8080/realms/andyur/.well-known/openid-configuration" >/dev/null 2>&1; then
  bad "run-class network reached the IdP by IP -- agent-to-IdP route exists"
elif [ -n "$KC_IP" ]; then
  ok "run-class network cannot reach the IdP by IP"
fi
# probe BOTH names: the compose service alias and the container name (a manual
# `docker network connect` attaches under the container name only, so probing
# just the alias would stay green under exactly that mutation)
for name in keycloak andyur-keycloak; do
  if netcurl "$PROBE_NET" -sf --max-time 5 "http://$name:8080/realms/andyur/.well-known/openid-configuration" >/dev/null 2>&1; then
    bad "run-class network resolved+reached the IdP as '$name'"
  else
    ok "run-class network cannot reach the IdP as '$name'"
  fi
done
gate_cleanup
trap - EXIT

echo
if [ "$FAILURES" -eq 0 ]; then
  say "idp-reference gate GREEN ($PASSES checks)"
  echo "(stack left up; tear down with ./run.sh idp down)"
  exit 0
else
  say "idp-reference gate RED ($FAILURES failures)"
  exit 1
fi
