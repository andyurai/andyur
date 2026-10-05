#!/usr/bin/env bash
# LIVE U4 downstream delegation against a REAL authorization server's native
# RFC 8693 token exchange (Keycloak 26.2, Standard Token Exchange = GA). This is
# the "compose OSS in production" model: instead of Andyur's own minimal exchange,
# the enterprise AS mints the downstream token. We prove Keycloak keeps the user
# (sub), rebinds the audience to the target tool, carries the granted scope, and
# REFUSES to widen to a scope the user is not entitled to. Usage: ./verify-u4-keycloak.sh (add `down`).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET="andyur-keycloak-net"
KC_IMAGE="${ANDYUR_KC_IMAGE:-quay.io/keycloak/keycloak:26.2}"
ISS="http://keycloak:8080/realms/andyur"
CERT_DIR="$(cd "$HERE/../../data" && pwd)"
CERT_NAME="as-certification-keycloak.json"
CERT_PUB_NAME="as-certification-keycloak.pub"

say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }
netpy(){ docker run --rm --network "$NET" -e ANDYUR_PROFILE=dev \
  -v "$CERT_DIR:/evidence" \
  --entrypoint python andyur-server -c "$1"; }

teardown(){ docker rm -f andyur-keycloak >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true; }

if [ "${1:-up}" = "down" ]; then say "tearing down"; teardown; echo done; exit 0; fi
trap 'echo; echo "(stack left up for inspection; tear down: $0 down)"' EXIT
teardown

say "building the current Andyur server image (stale images are invalid evidence)"
docker build -f "$HERE/../../Dockerfile.server" -t andyur-server "$HERE/../.." >/tmp/kc-build.log 2>&1 \
  || { bad "image build failed"; tail -25 /tmp/kc-build.log; exit 1; }

say "1. Keycloak with the seeded 'andyur' realm (files:read/files:write scopes, agent + tool clients)"
docker network create "$NET" >/dev/null 2>&1 || true
docker run -d --name andyur-keycloak --network "$NET" --network-alias keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false \
  -v "$HERE/realm-andyur.json:/opt/keycloak/data/import/realm-andyur.json:ro" \
  "$KC_IMAGE" start-dev --import-realm >/dev/null
info "waiting for Keycloak to publish the realm"
netpy '
import time, httpx, sys
url = "'"$ISS"'/.well-known/openid-configuration"
for _ in range(120):
    try:
        if httpx.get(url, timeout=3).status_code == 200:
            print("keycloak ready"); sys.exit(0)
    except Exception: pass
    time.sleep(2)
print("not ready"); sys.exit(1)
' || { bad "Keycloak not ready"; docker logs andyur-keycloak 2>&1 | tail -20; exit 1; }
ok "Keycloak up; RFC 8693 standard token exchange enabled on client 'andyur-agent'"

say "2. Andyur's real Keycloak adapter performs and verifies the exchange"
netpy '
import hashlib, httpx, json, jwt, sys, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from andyur import config
from andyur.server import asclient, ascertification, asproviders

TOKEN = "'"$ISS"'/protocol/openid-connect/token"
JWKS  = "'"$ISS"'/protocol/openid-connect/certs"
DISCOVERY = "'"$ISS"'/.well-known/openid-configuration"
results = []
def check(name, cond, detail=""):
    results.append(cond)
    print(("  \033[32mPASS\033[0m  " if cond else "  \033[31mFAIL\033[0m  ") + name + ("  " + detail if detail else ""))
def verified(tok, audience):
    key = jwt.PyJWKClient(JWKS).get_signing_key_from_jwt(tok).key
    return jwt.decode(tok, key, algorithms=["RS256"], audience=audience,
                      issuer="'"$ISS"'")

# alice logs in, entitled to files:read only
r = httpx.post(TOKEN, data={"grant_type":"password","client_id":"andyur-cli",
                            "username":"alice","password":"alice-password","scope":"openid files:read"}, timeout=15)
r.raise_for_status()
alice = r.json()["access_token"]
a = verified(alice, "andyur-agent")
alice_sub = a["sub"]
print("  \033[36m·\033[0m alice token: sub=%s  scope=%s" % (alice_sub, a.get("scope")))
check("alice is entitled to files:read", "files:read" in (a.get("scope") or "").split())

config.AS_TOKEN_ENDPOINT = TOKEN
config.AS_ISSUER = "'"$ISS"'"
config.AS_JWKS_URL = JWKS
config.AS_CLIENT_ID = "andyur-agent"
config.AS_CLIENT_SECRET = "agent-secret"
config.AS_PROVIDER = "keycloak"
config.AS_CAPABILITY = "core"
config.AS_RESOURCE_SCOPE = ""
config.EXCHANGE_TTL = 300
asclient._jwks = None

# The actor is required by Andyur before any exchange. Keycloak V2 is core-only
# and its exact adapter deliberately does not transmit this unsupported field.
actor = jwt.encode({"sub":"spiffe://andyur.local/agent/a/run/r"}, "x" * 32,
                   algorithm="HS256")
response = asclient.exchange(
    subject_token=alice, expected_subject=alice_sub, actor_token=actor,
    resource="tool-files", audience="tool-files", scope=["files:read"])
down = response["access_token"]
d = verified(down, "tool-files")
check("U4 exchange traversed Andyur asclient + Keycloak V2 profile", True)
check("core exchange keeps the user (sub=alice)", d.get("sub") == alice_sub, "sub=%s" % d.get("sub"))
aud = d.get("aud"); aud = aud if isinstance(aud, list) else [aud]
check("U4 audience rebound to the target tool", "tool-files" in aud, "aud=%s" % aud)
check("U4 granted scope carried (files:read)", "files:read" in (d.get("scope") or "").split(), "scope=%s" % d.get("scope"))
print("  \033[36m·\033[0m acting party: azp=%s  act=%s" % (d.get("azp"), d.get("act")))
check("core ceiling is explicit: no resource-visible act claim", d.get("act") is None)

check("U4 target validates signature, issuer and audience from Keycloak JWKS", True)

# --- never widening: ask for files:write, which alice is NOT entitled to ---
form, headers = asproviders.build_request(
    provider_name="keycloak", client_id="andyur-agent",
    client_secret="agent-secret", subject_token=alice, actor_token=actor,
    resource="tool-files", audience="tool-files",
    scope="files:read files:write", authorization_details=None)
r = httpx.post(TOKEN, data=form, headers=headers, timeout=15)
if r.status_code != 200:
    check("U4 never widening: files:write refused", True, "refused -> %d %s" % (r.status_code, r.json().get("error","")))
else:
    sc = (verified(r.json()["access_token"], "tool-files").get("scope") or "").split()
    check("U4 never widening: files:write dropped", "files:write" not in sc, "scope=%s" % " ".join(sc))

# Emit evidence only after every property above passed. The local issuer is HTTP,
# so production still refuses this artifact; a production tenant gate must bind
# its own HTTPS endpoints.
if all(results):
    discovery = httpx.get(DISCOVERY, timeout=15).json()
    digest = hashlib.sha256(json.dumps(
        discovery, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    now = int(time.time())
    artifact = {
        "schema": ascertification.SCHEMA, "suite": ascertification.SUITE,
        "result": "pass", "provider": "keycloak", "capability": "core",
        "issuer": "'"$ISS"'", "token_endpoint": TOKEN, "jwks_url": JWKS,
        "client_id": "andyur-agent", "discovery_sha256": digest,
        "product_version": "26.2",
        "scope_config_sha256": hashlib.sha256(b"").hexdigest(),
        "issued_at": now, "expires_at": now + 7 * 24 * 60 * 60,
    }
    evidence_key = Ed25519PrivateKey.generate()
    artifact = ascertification.sign(artifact, evidence_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    with open("/evidence/'"$CERT_NAME"'", "w", encoding="utf-8") as handle:
        json.dump(artifact, handle, sort_keys=True, separators=(",", ":"))
    with open("/evidence/'"$CERT_PUB_NAME"'", "wb") as handle:
        handle.write(evidence_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    check("signed evidence passes the production artifact validator", not ascertification.problems(
        "/evidence/'"$CERT_NAME"'", provider="keycloak", capability="core",
        issuer="'"$ISS"'", token_endpoint=TOKEN, jwks_url=JWKS,
        client_id="andyur-agent", product_version="26.2",
        public_key_file="/evidence/'"$CERT_PUB_NAME"'", scope_config="", now=now))

sys.exit(0 if all(results) else 1)
' && ok "Keycloak core exchange proven: keeps user, narrows scope, cannot widen" \
  || { bad "one or more U4 checks failed (see above)"; exit 1; }

trap - EXIT
say "Keycloak core user-preserving RFC 8693 exchange proof complete"
echo "Certification evidence: $CERT_DIR/$CERT_NAME (local HTTP topology; not production-usable)"
echo "Pinned certification public key: $CERT_DIR/$CERT_PUB_NAME"
echo "(stack left up for inspection; tear down: $0 down)"
