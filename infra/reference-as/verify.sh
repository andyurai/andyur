#!/usr/bin/env bash
# What a standards-complete authorization server carries for Andyur, proven by
# running one. Companion to `infra/keycloak/verify-act-delegation.sh`, which
# proves Keycloak carries almost none of it.
#
# Covers, in one exchange each:
#   RFC 7523  jwt-bearer login (the demo's stand-in for an interactive login)
#   RFC 8693  token exchange, `act` nested, actor = the run's SPIFFE id
#   RFC 8707  resource indicator -> `aud`
#   RFC 9396  the pin as `authorization_details`
#   RFC 9449  DPoP -> `cnf.jkt`
#
# Every refusal is asserted NEXT TO a success, because a broken server refuses
# everything and a refusal alone proves nothing.
#
# Two results are asserted as REQUIREMENTS rather than bugs, and they are the
# reason `docs/decisions.md` O1 enforces the pin at the gateway and the PDP:
#   - the AS carries a WIDER pin than asked for if the client asks for one
#   - it allow-lists the RAR type, never the content
#
# Usage: ./verify.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${ANDYUR_REFAS_PORT:-8099}"
PY="${ANDYUR_PY:-python3}"

say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }

command -v go >/dev/null || { bad "go is required"; exit 1; }
$PY -c "import jwt, cryptography" 2>/dev/null || {
  bad "PyJWT and cryptography are required (DPoP proofs are signed)"; exit 1; }

# A stale listener here would test something other than what we just built. That
# exact false green wasted three runs of the Keycloak harness.
if (echo >/dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then
  bad "port $PORT already in use; set ANDYUR_REFAS_PORT"; exit 1
fi
info "port $PORT free"

say "1. build and start the reference AS"
BIN="$(mktemp -d)/refas"
( cd "$HERE" && go build -o "$BIN" . ) || { bad "build failed"; exit 1; }
ANDYUR_REFAS_ADDR=":$PORT" ANDYUR_REFAS_DATA="$HERE/data" \
  "$BIN" > /tmp/andyur-refas.log 2>&1 &
AS_PID=$!
trap 'kill $AS_PID 2>/dev/null' EXIT
for i in $(seq 1 30); do
  kill -0 $AS_PID 2>/dev/null || { bad "server exited"; cat /tmp/andyur-refas.log; exit 1; }
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/.well-known/openid-configuration" 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 1
done
[ "$code" = "200" ] || { bad "never became ready"; cat /tmp/andyur-refas.log; exit 1; }
info "ready on :$PORT"

say "2. the matrix"
$PY - "http://localhost:$PORT" <<'PY'
import base64, hashlib, json, sys, time, urllib.parse, urllib.request, uuid
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

BASE = sys.argv[1]; T = BASE + "/token"
fails = []
def r(cond, msg, detail=""):
    print(("  \033[32mPASS\033[0m  " if cond else "  \033[31mFAIL\033[0m  ") + msg
          + ("  " + detail if detail else ""))
    if not cond: fails.append(msg)
    return cond

def post(d, headers=None):
    q = urllib.request.Request(T, data=urllib.parse.urlencode(d, doseq=True).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
    try:
        with urllib.request.urlopen(q, timeout=20) as x: return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b'{}')
        except Exception: return e.code, {}

def peek(t):
    p = t.split(".")[1]; return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
def head(t):
    p = t.split(".")[0]; return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))

def unsigned(claims):
    """A presented token for the fixture. The reference AS reads `sub` without
    verifying, which its own comment calls out as a fixture limitation."""
    h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return h + "." + p + "."

# ---------- DPoP ----------
dpop_key = ec.generate_private_key(ec.SECP256R1())
nums = dpop_key.public_key().public_numbers()
def b64u(i): return base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()
dpop_jwk = {"kty": "EC", "crv": "P-256", "x": b64u(nums.x), "y": b64u(nums.y)}
def jkt(jwk):
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                       separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canon).digest()).rstrip(b"=").decode()
def dpop_proof(htm, htu):
    return pyjwt.encode({"jti": str(uuid.uuid4()), "htm": htm, "htu": htu,
                         "iat": int(time.time())}, dpop_key, algorithm="ES256",
                        headers={"typ": "dpop+jwt", "jwk": dpop_jwk})

# The prior chain lives in the SUBJECT token -- it is the output of the previous
# exchange. The ACTOR token is a JWT-SVID and carries no `act` at all. The old
# fixture had these the wrong way round, which is the only reason the chain test
# used to pass.
ALICE = unsigned({"sub": "alice", "iss": "chat-app", "act": {"sub": "chat-app"}})
RUN   = unsigned({"sub": "spiffe://andyur.example/agent/sre/run/r-7"})
TELEM = "https://telemetry.internal/teams/checkout"
PIN = json.dumps([{"type": "andyur_pin", "identifier": "checkout",
                   "actions": ["telemetry:read"], "locations": [TELEM]}])

def ex(headers=None, **extra):
    d = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
         "client_id": "client_one", "client_secret": "gateway-secret",
         "resource": TELEM,
         "subject_token": ALICE,
         "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
         "actor_token": RUN, "actor_token_type": "urn:ietf:params:oauth:token-type:jwt"}
    d.update(extra)
    st, j = post(d, headers)
    return st, (j if st != 200 else peek(j["access_token"])), j

# ---------- the interactive login (auth code + PKCE, RFC 8252 shape) ----------
import http.cookiejar, urllib.error
cj = http.cookiejar.CookieJar()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, hdrs, fp)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect)

verifier = base64.urlsafe_b64encode(b"andyur-verifier-fixture-0123456789ab").rstrip(b"=").decode()
challenge = base64.urlsafe_b64encode(
    hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
REDIRECT = "http://127.0.0.1:8765/callback"
authz = BASE + "/authorize?" + urllib.parse.urlencode({
    "response_type": "code", "client_id": "andyur-cli", "redirect_uri": REDIRECT,
    "scope": "openid", "state": "st-fixture",
    "code_challenge": challenge, "code_challenge_method": "S256"})

import re
page = ""; action = None
try:
    with opener.open(authz, timeout=20) as x:
        page = x.read().decode("utf-8", "replace")
    m = re.search(r'<form action="([^"]+)"', page)
    action = m.group(1) if m else None
    r(x.status == 200 and "password" in page.lower() and bool(action),
      "authorize serves a login form", action or "no action found")
except urllib.error.HTTPError as e:
    r(False, "authorize serves a login form", "-> %d" % e.code)
if not action:
    action = authz

# wrong password must NOT issue a code, and must not say which field was wrong
try:
    with opener.open(urllib.request.Request(action, data=urllib.parse.urlencode(
            {"username": "alice", "password": "wrong"}).encode()), timeout=20) as x:
        body = x.read().decode("utf-8", "replace")
    r(x.status == 200 and "Incorrect username or password" in body,
      "wrong password is refused, without naming which field")
except urllib.error.HTTPError as e:
    r(False, "wrong password refused", "-> %d" % e.code)

code = None
try:
    with opener.open(urllib.request.Request(action, data=urllib.parse.urlencode(
            {"username": "alice", "password": "alice-password"}).encode()), timeout=20) as x:
        r(False, "login redirects with a code", "-> %d, expected a redirect" % x.status)
except urllib.error.HTTPError as e:
    loc = e.headers.get("Location", "")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    code = (q.get("code") or [None])[0]
    r(e.code in (302, 303) and bool(code), "correct login redirects with a code",
      "-> %d" % e.code)
    r(q.get("state") == ["st-fixture"], "state is echoed back (CSRF)")

if code:
    st, j = post({"grant_type": "authorization_code", "client_id": "andyur-cli",
                  "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier})
    r(st == 200, "code + verifier exchanges for a token", "-> %d" % st)
    if st == 200:
        r(peek(j["access_token"]).get("sub") == "alice", "the token is FOR the user",
          repr(peek(j["access_token"]).get("sub")))
        ALICE_REAL = j["access_token"]
# PKCE, tested on a FRESH code. The previous version replayed the code spent two
# lines above, so what it observed was single-use refusal -- identical whether the
# verifier was right, wrong or absent. Deleting WithPKCERequired() left it green.
fresh = None
try:
    with opener.open(urllib.request.Request(action, data=urllib.parse.urlencode(
            {"username": "alice", "password": "alice-password"}).encode()), timeout=20) as x:
        pass
except urllib.error.HTTPError as e:
    q2 = urllib.parse.parse_qs(urllib.parse.urlparse(e.headers.get("Location", "")).query)
    fresh = (q2.get("code") or [None])[0]
if fresh:
    st2, j2 = post({"grant_type": "authorization_code", "client_id": "andyur-cli",
                    "code": fresh, "redirect_uri": REDIRECT})
    r(st2 == 400 and "verifier" in json.dumps(j2).lower(),
      "a FRESH code without the verifier is refused BY PKCE",
      "-> %d %s" % (st2, json.dumps(j2)[:80]))
else:
    r(False, "a FRESH code without the verifier is refused BY PKCE",
      "could not obtain a second code")

# ---------- RFC 8693: the chain ----------
st, c, _ = ex()
r(st == 200, "RFC 8693 exchange performed", "-> %d" % st)
r(c.get("sub") == "alice", "sub is the USER and does not drift", repr(c.get("sub")))
act = c.get("act") or {}
r(act.get("sub", "").startswith("spiffe://"), "act names the RUN by SPIFFE id", act.get("sub", ""))
r(bool((act.get("act") or {}).get("sub")), "act CHAINS to the prior hop", json.dumps(act.get("act")))

# ---------- the token must be usable by the PEP ----------
st, _, j = ex()
if st != 200 or "access_token" not in j:
    r(False, "token available for the PEP-compatibility checks",
      "-> %d %s" % (st, json.dumps(j)[:200]))
    tok = None
else:
    tok = j["access_token"]
if tok:
    r(head(tok).get("typ") == "at+jwt", "RFC 9068 typ is at+jwt (the PEP requires it)", repr(head(tok).get("typ")))
    r(head(tok).get("alg") == "RS256", "signed RS256 (the PEP pins it)", repr(head(tok).get("alg")))
    r(all(k in peek(tok) for k in ("client_id", "jti", "exp", "iat", "iss", "sub")),
      "RFC 9068 required claims present (the PEP requires them)")

# ---------- actor_token is mandatory ----------
st, c, _ = ex(actor_token="", actor_token_type="")
# 400 SPECIFICALLY, not merely "not 200". This assertion was written as != 200
# and passed against a 500, which is how the bug it now guards shipped: a client
# error surfacing as an internal server error. A refusal with the wrong status
# is a defect, not a pass.
r(st == 400, "NO actor_token REFUSED with 400 (else it is impersonation)", "-> %d" % st)
r(c.get("error") == "invalid_request", "and the error code names the cause", repr(c.get("error")))

# ---------- RFC 8707 ----------
st, c, _ = ex(resource=TELEM)
r(st == 200 and c.get("aud") == TELEM, "RFC 8707 resource becomes aud", repr(c.get("aud")))
st, c, _ = ex(resource="https://evil.example")
r(st == 400, "unregistered resource REFUSED", "-> %d" % st)

# ---------- RFC 9396 ----------
st, c, _ = ex(authorization_details=PIN)
ad = c.get("authorization_details") if st == 200 else None
r(bool(ad) and ad[0].get("identifier") == "checkout",
  "RFC 9396 pin carried into the token", json.dumps(ad))
st, c, _ = ex(authorization_details=json.dumps([{"type": "nope", "actions": ["read"]}]))
r(st == 400, "unregistered RAR type REFUSED", "-> %d" % st)

# ---------- RFC 9449 DPoP ----------
st, c, _ = ex(headers={"DPoP": dpop_proof("POST", T)}, resource=TELEM,
              authorization_details=PIN)
cnf = c.get("cnf") if st == 200 else None
r(bool(cnf and cnf.get("jkt")), "RFC 9449 DPoP puts cnf.jkt in the token", json.dumps(cnf))
r(bool(cnf) and cnf.get("jkt") == jkt(dpop_jwk),
  "cnf.jkt is the thumbprint of the PRESENTING key", "%s" % (cnf or {}).get("jkt"))
# positive control: without a proof there is no cnf, so the claim above means something
st, c2, _ = ex(resource=TELEM)
r(st == 200 and not c2.get("cnf"), "no proof -> no cnf (control)")

# ---------- everything at once ----------
st, c, _ = ex(headers={"DPoP": dpop_proof("POST", T)}, resource=TELEM,
              authorization_details=PIN, scope="openid")
r(st == 200 and c.get("act") and c.get("aud") and c.get("authorization_details") and c.get("cnf"),
  "act + aud + authorization_details + cnf in ONE token")
if st == 200:
    print("      %s" % json.dumps({k: c.get(k) for k in ("sub","act","aud","authorization_details","cnf")}))

# ---------- the RAR claim is not self-validating; the HOOK is the control ------
# Two different facts, and conflating them cost a round of confusion:
#
#   the CLAIM   RFC 9396 authorization_details is a CARRIER. An AS with no policy
#               carries whatever the client asks for, including identifier "*",
#               because a token exchange has no prior granted set to narrow
#               against. Measured before this policy existed.
#   the HOOK    an AS that HAS a policy hook can refuse. That is the control, and
#               it is the only place that can decline to ISSUE.
#
# So a wildcard pin must now be REFUSED, and the refusal proves the hook runs.
st, c, _ = ex(authorization_details=json.dumps(
    [{"type": "andyur_pin", "identifier": "*", "actions": ["*"]}]))
r(st != 200, "a WILDCARD pin is refused by the detail validator", "-> %d" % st)

st, c, _ = ex(authorization_details=json.dumps(
    [{"type": "andyur_pin", "actions": ["read"]}]))
r(st != 200, "a pin with NO identifier is refused (it constrains nothing)",
  "-> %d" % st)

# POSITIVE CONTROL: an honest pin still travels, so the two above are not just
# a server that refuses everything.
st, c, _ = ex(authorization_details=PIN)
r(st == 200 and (c.get("authorization_details") or [{}])[0].get("identifier") == "checkout",
  "POSITIVE CONTROL: an honest pin is still carried", "-> %d" % st)

# ---------- THE POLICY: the AS is the only place that can say DENY ----------
# Andyur narrowing before it asks is necessary and not sufficient: a compromised
# Andyur simply asks for more. Only the issuer can decline to issue.
BOB = unsigned({"sub": "bob", "iss": "chat-app"})
READER = unsigned({"sub": "spiffe://andyur.example/agent/reader/run/r-9",
                   "act": {"sub": "chat-app"}})
GHOST = unsigned({"sub": "spiffe://andyur.example/agent/ghost/run/r-1"})
NOBODY = unsigned({"sub": "mallory", "iss": "chat-app"})
PAY = "https://telemetry.internal/teams/payments"
TICKETS = "https://tickets.internal/incidents"

st, _, _ = ex(resource=TELEM)
r(st == 200, "POSITIVE CONTROL: alice + sre + checkout is ALLOWED", "-> %d" % st)
st, _, _ = ex(resource=TICKETS)
r(st == 200, "POSITIVE CONTROL: alice + sre + incidents is ALLOWED", "-> %d" % st)

st, j, _ = ex(resource=PAY)
r(st == 403 and j.get("error") == "access_denied",
  "PIN: alice has no claim to payments -> DENIED", "-> %d %s" % (st, j.get("error")))

st, j, _ = ex(subject_token=BOB, resource=TELEM)
r(st == 403 and j.get("error") == "access_denied",
  "PIN: bob has no claim to checkout -> DENIED", "-> %d %s" % (st, j.get("error")))

st, j, _ = ex(actor_token=READER, resource=TICKETS)
r(st == 403 and j.get("error") == "access_denied",
  "CEILING: agent 'reader' may not hold a tickets token -> DENIED",
  "-> %d %s" % (st, j.get("error")))

st, j, _ = ex(actor_token=READER, resource=TELEM)
r(st == 200, "POSITIVE CONTROL: 'reader' MAY hold a telemetry token", "-> %d" % st)

st, j, _ = ex(actor_token=GHOST, resource=TELEM)
r(st == 403 and j.get("error") == "access_denied",
  "an agent with NO configured ceiling is DENIED, not unrestricted",
  "-> %d %s" % (st, j.get("error")))

st, j, _ = ex(subject_token=NOBODY, resource=TELEM)
r(st == 403 and j.get("error") == "access_denied",
  "an unknown SUBJECT is DENIED, not defaulted", "-> %d %s" % (st, j.get("error")))

# ---------- REGRESSIONS: every one of these was a live defect ----------

# CRITICAL: an unauthenticated exchange minted a full delegated token, because
# go-oidc substitutes a mock client holding every scope when the caller is merely
# unidentified. A WRONG secret always 401'd; the hole was omitting credentials.
st, j = post({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
              "subject_token": ALICE,
              "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
              "actor_token": RUN, "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
              "resource": TELEM})
r(st == 401, "NO client credentials at all is REFUSED", "-> %d" % st)
st, _, _ = ex(client_secret="wrong-secret")
r(st == 401, "a WRONG client secret is refused (control)", "-> %d" % st)

# CRITICAL: the policy computed a narrowed scope and the AS had nowhere to put
# it, so a request mixing a permitted and an unpermitted action was ALLOWED and
# both were issued. It must refuse what it cannot narrow.
st, j, _ = ex(scope="telemetry:read tickets:delete")
r(st == 403, "a request it would have to NARROW is REFUSED, not widened",
  "-> %d %s" % (st, (j or {}).get("error")))

# POSITIVE CONTROL for the test above: the scope term is LIVE, not merely
# rejected by vocabulary. Until the action scopes were registered, go-oidc
# refused every resource action with invalid_scope before policy ran, so term 4
# could not fire and no test could tell.
st, c, _ = ex(scope="telemetry:read")
r(st == 200, "an action alice IS entitled to passes the scope term", "-> %d" % st)
r(st == 200 and "telemetry:read" in (c.get("scope") or ""),
  "and it is carried in the issued token", repr((c or {}).get("scope")))

st, j, _ = ex(scope="tickets:delete")
r(st == 403, "an action alice is NOT entitled to is refused by POLICY, not by "
  "vocabulary", "-> %d %s" % (st, (j or {}).get("error")))

# MEDIUM: the same DPoP proof was accepted three times, each issuing a token.
proof = dpop_proof("POST", T)
st1, _, _ = ex(headers={"DPoP": proof}, resource=TELEM)
st2, _, _ = ex(headers={"DPoP": proof}, resource=TELEM)
r(st1 == 200 and st2 != 200, "a DPoP proof is SINGLE-USE (replay refused)",
  "first -> %d, replay -> %d" % (st1, st2))

# LOW->MED: a malformed authorization_details was silently dropped and the token
# issued UNPINNED. A constraint that fails to parse is not the absence of one.
st, j, _ = ex(authorization_details='{"type":"andyur_pin"}')      # object, not array
r(st == 400, "a malformed authorization_details is REFUSED, not dropped",
  "-> %d %s" % (st, (j or {}).get("error")))
st, j, _ = ex(authorization_details='not json at all')
r(st == 400, "unparseable authorization_details is REFUSED", "-> %d" % st)

# LOW: `audience` was checked against the ceiling but never pin-checked, so the
# same value refused as `resource` was permitted as `audience`.
st, j, _ = ex(audience="https://telemetry.internal/teams/payments")
r(st == 403, "a pin violation via `audience` is refused, as via `resource`",
  "-> %d %s" % (st, (j or {}).get("error")))

# HIGH: an exchange naming NO target at all was GRANTED. Terms 3 and 5 both
# iterate the requested targets, so with neither `resource` nor `audience` the
# loops ran zero times and the ceiling and the pin were never consulted --
# `bob + sre` with no target returned 200, and so did `alice + reader` whose
# ceiling is telemetry-only. An empty loop is not a satisfied conjunct.
st, j = post({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
              "client_id": "client_one", "client_secret": "gateway-secret",
              "subject_token": ALICE,
              "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
              "actor_token": RUN, "actor_token_type": "urn:ietf:params:oauth:token-type:jwt"})
r(st == 403, "an exchange naming NO target is REFUSED",
  "-> %d %s" % (st, (j or {}).get("error")))

st, j = post({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
              "client_id": "client_one", "client_secret": "gateway-secret",
              "subject_token": BOB,
              "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
              "actor_token": RUN, "actor_token_type": "urn:ietf:params:oauth:token-type:jwt"})
r(st == 403, "...and so is bob, whose ceiling would never have been consulted",
  "-> %d" % st)

# LOW: the ceiling's trailing-* matched a path that climbs out of the prefix.
st, j, _ = ex(audience="https://telemetry.internal/teams/../../admin")
r(st == 403, "a traversal path does not satisfy a trailing-* ceiling",
  "-> %d %s" % (st, (j or {}).get("error")))

print()
if fails:
    print("  \033[31m%d check(s) failed\033[0m" % len(fails)); sys.exit(1)
print("  \033[32mall checks passed\033[0m")
PY
rc=$?
say "done"
exit $rc
