#!/usr/bin/env bash
# THE ACTOR LEG, LIVE: a real per-run SVID exchanged at the reference AS.
#
# This is the wire proof for what the config layer asserts in unit tests
# (tests/test_asclient.py): that the RFC 8693 exchange carries the run's
# identity as the ACTOR, so the issued token asserts delegation rather than the
# user acting directly. Unit tests prove the config SHAPE; only this proves the
# real per-run sidecar and the real AS agree on it.
#
# Three assertions, each proving what the ones before it cannot:
#   3. a container LABELED with the run id fetches a per-run JWT-SVID whose
#      subject IS the run's SPIFFE id (docker attestation, not a hand-made JWT)
#   4. a DIRECT exchange (subject = dana's real login token, actor = that SVID)
#      returns a token carrying sub=dana AND act.sub=<the run> -- delegation
#   5. the SAME exchange driven by the per-run SIDECAR (andyur/proxy, the sole
#      tool egress) yields a token a resource server's PEP ACCEPTS end to end
#      (MCP initialize -> 200), with the agent's forged bearer stripped
#
# PREREQUISITES: the containerized SPIRE stack (./run.sh spire-docker up), which
# gives the docker WorkloadAttestor and the shared socket volume this uses; and
# go, for the reference AS. Everything else it stands up itself, on scratch
# ports. No agentgateway binary: the sidecar is Andyur code.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$HERE/infra/ports.sh"
VENV="$HERE/.venv"
WORK="$(mktemp -d)"
AS_PORT="${ANDYUR_AS_PORT:-8683}"
OBS_PORT="${ANDYUR_OBS_PORT:-8781}"
AS="http://localhost:$AS_PORT"

command -v go >/dev/null || { echo "go is required to build the reference AS"; exit 1; }
docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^andyur-spire-server$' || {
  echo "the containerized SPIRE stack is not up. Start it with:"
  echo "    ./run.sh spire-docker up"; exit 1; }
for p in "$AS_PORT" "$OBS_PORT"; do
  port_held "$p" && { echo "port $p is already held; refusing to verify"; exit 1; }
done
# The tool's real MCP path is /mcp, but the AUDIENCE identifier is a separate
# field: PinOf() reads the last path segment as the resource name, so the
# identifier must end in the team the user is entitled to. (The shipped AS demo
# sets audience=.../mcp, which PinOf reduces to "mcp" and no user holds -- a
# real ADR-002 mismatch, recorded, not this probe's subject.)
OBS_PATH="/mcp"
OBS_AUD="http://127.0.0.1:$OBS_PORT/teams/checkout"
# The tool PEP enforces aud == its own MCP URL; PinOf reduces that to
# "mcp". Step 5 uses this shape so the tool ACCEPTS end to end; the
# team-vs-mcp divergence is ADR-002, recorded, not this probe's subject.
OBS_MCP="http://127.0.0.1:$OBS_PORT/mcp"
RUN_ID="run-probe-$$"
RUN_SVID_ID="spiffe://andyur.local/agent/oncall/run/$RUN_ID"
FAILED=0
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILED=$((FAILED+1)); }
cleanup(){ for p in ${AS_PID:-} ${OBS_PID:-} ${LOGIN_PID:-}; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "== 1. reference AS up (NOT Andyur)"
[ -d "$HERE/infra/reference-as/patches/go-oidc" ] || bash "$HERE/infra/reference-as/patches/apply.sh" >/dev/null
( cd "$HERE/infra/reference-as" && go build -o "$WORK/refas" . ) || { bad "refas build"; exit 1; }
mkdir -p "$WORK/asdata"
cat > "$WORK/asdata/users.json" <<EOF
{"dana": {"entitlements": ["telemetry:read","tickets:read","tickets:write"],
          "resources": ["checkout","mcp"]}}
EOF
cat > "$WORK/asdata/ceilings.json" <<EOF
{"oncall": {"actions": ["telemetry:read","tickets:read","tickets:write"],
            "audiences": ["$OBS_AUD","$OBS_MCP"]}}
EOF
ANDYUR_REFAS_ADDR=":$AS_PORT" ANDYUR_REFAS_DATA="$WORK/asdata" \
ANDYUR_REFAS_ANDYUR_URL="http://127.0.0.1:8642" \
ANDYUR_REFAS_RESOURCES="$OBS_AUD,$OBS_MCP" ANDYUR_REFAS_USERS="dana:dana-password" \
  "$WORK/refas" >"$WORK/as.log" 2>&1 &
AS_PID=$!
for _ in $(seq 1 60); do curl -sf "$AS/.well-known/openid-configuration" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "$AS/.well-known/openid-configuration" >/dev/null && ok "AS on :$AS_PORT" || { bad "AS never came up"; cat "$WORK/as.log"; exit 1; }

echo "== 2. dana signs in AT the AS (real Authorization Code + PKCE, headless)"
export ANDYUR_HOME="$WORK/home"; mkdir -p "$ANDYUR_HOME"
export VENV HERE
"$VENV/bin/python" - "$AS" <<'PY' >"$WORK/login.log" 2>&1
import re, subprocess, sys, os, urllib.request, urllib.parse, http.cookiejar
issuer = sys.argv[1]
p = subprocess.Popen([os.environ["VENV"] + "/bin/python", "-u", "-m", "andyur.cli",
                      "auth", "login", "--issuer", issuer, "--no-browser",
                      "--scope", "openid telemetry:read tickets:write"],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                     cwd=os.environ["HERE"],
                     env={**os.environ, "PYTHONUNBUFFERED": "1"})
url = None
for line in p.stdout:
    m = re.search(r'(http\S*/authorize\?\S+)', line)
    if m and not url:
        url = m.group(1)
        cj = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        page = op.open(url, timeout=20).read().decode()
        action = re.search(r'<form action="([^"]+)"', page).group(1)
        op.open(urllib.request.Request(action, data=urllib.parse.urlencode(
            {"username": "dana", "password": "dana-password"}).encode()), timeout=20).read()
    print(line, end="")
sys.exit(p.wait(timeout=90))
PY
T0=$("$VENV/bin/python" -c "import json,os;print(json.load(open(os.path.join(os.environ['ANDYUR_HOME'],'credentials.json')))['access_token'])" 2>/dev/null || true)
[ -n "$T0" ] && ok "dana's token in hand (real login)" || { bad "login failed"; cat "$WORK/login.log"; exit 1; }

echo "== 3. the RUN's SVID: docker-attested, per-run, audience = the AS"
docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
  -parentID "spiffe://andyur.local/agent/node" \
  -spiffeID "$RUN_SVID_ID" \
  -selector "docker:label:andyur.run_id:$RUN_ID" \
  -selector "docker:label:andyur.agent:oncall" \
  -jwtSVIDTTL 300 >/dev/null 2>&1 || { bad "entry create (is spire-docker up?)"; exit 1; }
ACTOR=""
for _ in $(seq 1 15); do   # the agent syncs entries on an interval (~5s)
  OUT=$(docker run --rm --network andyur-spire-net --user 0 \
    --label "andyur.run_id=$RUN_ID" --label "andyur.agent=oncall" \
    -v andyur-spire-sockets:/run/spire/sockets:ro \
    --entrypoint /opt/spire/bin/spire-agent \
    ghcr.io/spiffe/spire-agent:1.11.2 api fetch jwt -audience "$AS" \
    -socketPath /run/spire/sockets/api.sock 2>&1 || true)
  ACTOR=$(printf '%s' "$OUT" | grep -oE '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1)
  [ -n "$ACTOR" ] && break; sleep 2
done
[ -n "$ACTOR" ] && ok "per-run JWT-SVID fetched by a container labeled $RUN_ID" \
  || { bad "no SVID: $OUT"; exit 1; }
"$VENV/bin/python" - "$ACTOR" "$RUN_SVID_ID" <<'PY'
import base64, json, sys
p = sys.argv[1].split(".")[1]
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
print("      svid sub=%s aud=%s" % (c.get("sub"), c.get("aud")))
sys.exit(0 if c.get("sub") == sys.argv[2] else 1)
PY
[ $? -eq 0 ] && ok "...and it IS the run's identity" || bad "SVID sub mismatch"

echo "== 4. DIRECT exchange at the AS: subject + actor -> act.sub is the RUN"
PIN='[{"type":"andyur_pin","identifier":"checkout","datatypes":["team"]}]'
RESP=$(curl -s -X POST "$AS/token" \
  -d client_id=client_one -d client_secret=gateway-secret \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$T0" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d actor_token="$ACTOR" \
  -d actor_token_type=urn:ietf:params:oauth:token-type:jwt \
  -d resource="$OBS_AUD" -d audience="$OBS_AUD" -d scope="telemetry:read" \
  --data-urlencode "authorization_details=$PIN")
echo "$RESP" > "$WORK/exchange.json"
"$VENV/bin/python" - "$WORK/exchange.json" "$RUN_SVID_ID" <<'PY'
import base64, json, sys
d = json.load(open(sys.argv[1]))
tok = d.get("access_token")
if not tok:
    print("      AS refused:", json.dumps(d)); sys.exit(1)
p = tok.split(".")[1]
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
print("      sub=%s  act=%s  aud=%s  scope=%s" % (
    c.get("sub"), json.dumps(c.get("act")), c.get("aud"), c.get("scope")))
ok = c.get("sub") == "dana" and (c.get("act") or {}).get("sub") == sys.argv[2]
sys.exit(0 if ok else 1)
PY
[ $? -eq 0 ] && ok "issued token: sub=dana, act.sub=$RUN_SVID_ID" \
  || bad "the exchange did not produce delegation (see $WORK/exchange.json)"

echo "== 5. the SAME exchange, driven by the per-run SIDECAR (ADR-003 tool egress)"
# The registry path made the tool's default audience the LOGICAL id
# (resource:telemetry, 4d68d2a); this harness proves the URL-audience AS
# chain, so the expected audience is pinned back to the MCP URL.
ANDYUR_OBS_PORT="$OBS_PORT" ANDYUR_AS_ISSUER="$AS" \
ANDYUR_OBS_AUDIENCE="$OBS_MCP" \
  "$VENV/bin/python" "$HERE/demos/sre-triage/observability.py" >"$WORK/obs.log" 2>&1 &
OBS_PID=$!
sleep 3
export T0 ACTOR OBS_MCP WORK
# The sidecar is the sole tool egress (the per-run agentgateway was deleted,
# ADR-003). Its external-AS leg -- the REAL proxy app, its REAL default
# exchange (asclient.exchange at the adopter's AS, subject=dana's login,
# actor=the docker-attested run SVID) -- accepted end to end by the tool's PEP.
# The agent-side request carries a FORGED bearer, so a 200 also proves the
# sidecar
# stripped it and presented the minted token instead. The tool client is a
# plain httpx client injected through build_app's factory seam: this host has
# no SPIRE Workload API for an X509-SVID, and the mTLS leg is already proven
# live by the registry gate; the subject of THIS probe is the exchange.
# Dev profile: the reference AS is a test fixture (plaintext users, published
# example key), which production correctly refuses -- and the default profile is
# prod. Without this the sidecar's as_problems() certification check withholds
# the call ("ANDYUR_AS_PROVIDER=reference is refused in production"), which is
# right for prod but wrong for this reference-chain proof.
ANDYUR_PROFILE=dev \
ANDYUR_EXCHANGE_TTL=3600 \
ANDYUR_AS_TOKEN_ENDPOINT="$AS/token" ANDYUR_AS_ISSUER="$AS" \
ANDYUR_AS_JWKS="$AS/jwks" \
ANDYUR_AS_CLIENT_ID="client_one" ANDYUR_AS_CLIENT_SECRET="gateway-secret" \
ANDYUR_SERVER_URL="http://127.0.0.1:8642" \
  "$VENV/bin/python" - <<PY3
import json, os, sys, threading, time, urllib.request
sys.path.insert(0, "$HERE")
import httpx, uvicorn
from andyur.proxy import app as proxy_app
from andyur.proxy import sidecar as sc

route = sc.ToolRoute.from_managed("telemetry", {
    "url": os.environ["OBS_MCP"], "audience": os.environ["OBS_MCP"],
    "scheme": "http", "host": "127.0.0.1", "port": $OBS_PORT, "path": "/mcp"})
ident = sc.RunIdentity(subject_token=os.environ["T0"],
                       actor_token=lambda: os.environ["ACTOR"],
                       mtls_material=lambda: {},
                       expected_subject="dana",
                       expected_actor="$RUN_SVID_ID")
app = proxy_app.build_app(
    router=sc.Router({"telemetry": route}), identity=ident,
    scope=["telemetry:read"],
    pin=json.dumps([{"type": "andyur_pin", "identifier": "mcp",
                     "datatypes": ["team"]}]),
    gateway_url="",
    tool_client_factory=lambda: httpx.AsyncClient(timeout=30.0))
server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0,
                                       log_level="warning"))
thread = threading.Thread(target=server.run, daemon=True)
thread.start()
deadline = time.monotonic() + 15
while not server.started:
    if not thread.is_alive() or time.monotonic() > deadline:
        print("      FAILED: sidecar app never came up"); sys.exit(1)
    time.sleep(0.02)
port = server.servers[0].sockets[0].getsockname()[1]
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "probe", "version": "1"}}}).encode()
req = urllib.request.Request(
    f"http://127.0.0.1:{port}/tools/telemetry/mcp", data=body,
    headers={"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream",
             "Authorization": "Bearer FORGED-BY-THE-AGENT"})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print("      MCP initialize through the SIDECAR -> HTTP", r.status)
        code = 0
except Exception as exc:
    print("      FAILED: %s: %s" % (type(exc).__name__, exc))
    code = 1
server.should_exit = True
thread.join(timeout=5)
sys.exit(code)
PY3
[ $? -eq 0 ] && ok "the sidecar exchanged BOTH legs at the AS and the tool's PEP accepted" \
  || { bad "sidecar-driven exchange failed"; tail -5 "$WORK/as.log"; tail -5 "$WORK/obs.log"; }

echo "== 6. a REGISTRY-vocabulary run exchanges via the ADR-010 scope map"
# Checks 4-5 spoke the AS's vocabulary directly. A registry-driven run instead
# names LOGICAL actions (obs:read) the reference AS does not know. With a scope
# map configured, asclient must translate obs:read -> telemetry:read at exchange
# time so the SAME AS accepts it -- the fix that unblocks the SRE --full path.
ANDYUR_PROFILE=dev ANDYUR_EXCHANGE_TTL=3600 \
ANDYUR_AS_TOKEN_ENDPOINT="$AS/token" ANDYUR_AS_ISSUER="$AS" ANDYUR_AS_JWKS="$AS/jwks" \
ANDYUR_AS_CLIENT_ID="client_one" ANDYUR_AS_CLIENT_SECRET="gateway-secret" \
ANDYUR_AS_PROVIDER=reference \
ANDYUR_AS_RESOURCE_SCOPE='{"schema":"andyur-reference-scope-map/v1","actions":{"obs:read":{"request":"telemetry:read","claim":"telemetry:read"}}}' \
ANDYUR_SERVER_URL="http://127.0.0.1:8642" \
  "$VENV/bin/python" - "$T0" "$ACTOR" "$RUN_SVID_ID" "$OBS_AUD" <<'PY6'
import base64, json, sys
sys.path.insert(0, ".")
from andyur.server import asclient
t0, actor, run_svid, aud = sys.argv[1:5]
try:
    # scope is the LOGICAL registry action, NOT the AS's vocabulary.
    resp = asclient.exchange(subject_token=t0, expected_subject="dana",
                             actor_token=actor, expected_actor=run_svid,
                             audience=aud, resource=aud, scope=["obs:read"])
except Exception as exc:                       # noqa: BLE001
    print("      FAILED: %s: %s" % (type(exc).__name__, exc)); sys.exit(1)
tok = resp.get("access_token")
seg = tok.split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
print("      asked obs:read (logical) -> issued scope=%s sub=%s" % (
    claims.get("scope"), claims.get("sub")))
sys.exit(0 if "telemetry:read" in (claims.get("scope") or "") else 1)
PY6
[ $? -eq 0 ] && ok "obs:read translated to telemetry:read; the reference AS accepted it" \
  || bad "the scope map did not let a logical action exchange through the AS"

echo; echo "artifacts: $WORK"
[ "$FAILED" = "0" ] && echo "ALL CHECKS PASSED" || echo "$FAILED check(s) FAILED"
exit "$FAILED"
