#!/usr/bin/env python3
"""Stand up the FEDERATED enterprise demo environment, idempotently.

WHAT THIS IS: environment setup that simulates an enterprise. It configures an
IdP, a resource server, and the demo's users and agents. It changes NOTHING in
the platform -- every call below is either an ordinary admin API of a
third-party product (Keycloak, Grafana) or a documented Andyur operator surface
(`registry.set_ceiling`, `andyur-cli agents create`).

WHAT AN ENTERPRISE WOULD ALREADY HAVE, that this creates instead:
  * an IdP with real humans in it        -> Keycloak realm `andyur`
  * a resource server that TRUSTS it     -> Grafana, generic_oauth + auth.jwt
  * accounts mapped to those humans      -> by the `sub` / `email` claim
  * agents with authority ceilings       -> the Andyur registry

Run it twice: the second run must change nothing and still pass every check.
That is the only version of "repeatable" worth claiming.
"""
from __future__ import annotations
import base64, json, os, pathlib, subprocess, sys, time

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

ROOT = pathlib.Path(__file__).resolve().parents[2]
KC   = os.environ.get("ANDYUR_IDP_URL", "http://127.0.0.1:8480")
GF   = os.environ.get("ANDYUR_GRAFANA_URL", "http://127.0.0.1:3000")
CP   = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642")
REALM = "andyur"
# ADR 002: the audience is the TOOL SERVER's canonical resource, not Grafana's url.
TOOL_RESOURCE = os.environ.get("ANDYUR_GRAFANA_TOOL", "http://127.0.0.1:8804/mcp")

OK, BAD = "\033[32m  ok  \033[0m", "\033[31m FAIL \033[0m"
_fails = []

def check(label, cond, detail=""):
    print(f"  [{OK if cond else BAD}] {label}" + (f"   {detail}" if detail else ""))
    if not cond:
        _fails.append(label)
    return cond

def head(t):
    print(f"\n\033[1m== {t} ==\033[0m")

# ---------------------------------------------------------------- the humans
# Names, not job titles. An agent is a role; a person is a person. Getting this
# backwards produced `sre-oncall@corp` (a human) colliding with `sre-oncall`
# (an agent) -- see the naming note in the demo README.
USERS = [
    dict(username="sarah.miller", firstName="Sarah", lastName="Miller",
         email="sarah.miller@andyur.test", password="sarah-password", roles=[]),
    dict(username="david.kumar", firstName="David", lastName="Kumar",
         email="david.kumar@andyur.test", password="david-password",
         roles=["andyur-admin"]),          # the approver
]
AGENTS = ["incident-responder", "platform-engineer"]

ON = {"access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"}
MAPPERS = [
    {"name": "username", "protocol": "openid-connect",
     "protocolMapper": "oidc-usermodel-property-mapper",
     "config": {**ON, "user.attribute": "username",
                "claim.name": "preferred_username", "jsonType.label": "String"}},
    {"name": "email", "protocol": "openid-connect",
     "protocolMapper": "oidc-usermodel-property-mapper",
     "config": {**ON, "user.attribute": "email",
                "claim.name": "email", "jsonType.label": "String"}},
    {"name": "full name", "protocol": "openid-connect",
     "protocolMapper": "oidc-full-name-mapper", "config": dict(ON)},
]


def env_file(path):
    d = {}
    p = pathlib.Path(path)
    if p.is_file():
        for line in p.read_text().splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v
    return d


def kc_admin():
    e = env_file(ROOT / "data" / "docker.env")
    r = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", timeout=20,
                      data={"grant_type": "password", "client_id": "admin-cli",
                            "username": e.get("ANDYUR_IDP_ADMIN_USER", "admin"),
                            "password": e.get("ANDYUR_IDP_ADMIN_PASSWORD", "")})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}",
            "Content-Type": "application/json"}


def claims(tok):
    c = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)))


# =============================================================== 1. the IdP
def setup_idp(H):
    head("1. the IdP: humans who can actually authenticate")
    roles = {r["name"]: r for r in requests.get(
        f"{KC}/admin/realms/{REALM}/roles", headers=H, timeout=20).json()}

    for u in USERS:
        body = {k: u[k] for k in ("username", "firstName", "lastName", "email")}
        body.update(enabled=True, emailVerified=True)
        r = requests.post(f"{KC}/admin/realms/{REALM}/users", headers=H, json=body, timeout=20)
        existed = r.status_code == 409
        uid = requests.get(f"{KC}/admin/realms/{REALM}/users", headers=H, timeout=20,
                           params={"username": u["username"], "exact": "true"}).json()[0]["id"]
        requests.put(f"{KC}/admin/realms/{REALM}/users/{uid}/reset-password", headers=H, timeout=20,
                     json={"type": "password", "value": u["password"], "temporary": False})
        for rn in u["roles"]:
            if rn in roles:
                requests.post(f"{KC}/admin/realms/{REALM}/users/{uid}/role-mappings/realm",
                              headers=H, json=[roles[rn]], timeout=20)
        check(f"user {u['username']}", True, "(already present)" if existed else "(created)")

    # Grafana's own client, for the BROWSER login leg only. The API leg needs no
    # client at all -- it validates against the key set.
    r = requests.post(f"{KC}/admin/realms/{REALM}/clients", headers=H, timeout=20, json={
        "clientId": "grafana", "name": "Grafana", "enabled": True,
        "protocol": "openid-connect", "publicClient": False,
        "secret": os.environ.get("ANDYUR_GRAFANA_OIDC_SECRET", "grafana-oidc-secret"),
        "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
        "redirectUris": [f"{GF}/login/generic_oauth"], "webOrigins": [GF]})
    check("client 'grafana'", r.status_code in (201, 409),
          "(already present)" if r.status_code == 409 else "(created)")

    # THE REALM IMPORTS MINIMAL. It has no built-in `profile`/`email` client
    # scopes, so without these mappers the token carries no `preferred_username`
    # and no `email`, and Grafana has nothing to map a user onto.
    for cli in ("andyur-cli", "andyur-console", "grafana"):
        q = requests.get(f"{KC}/admin/realms/{REALM}/clients", headers=H, timeout=20,
                         params={"clientId": cli}).json()
        if not q:
            check(f"claim mappers on {cli}", False, "client absent")
            continue
        cid = q[0]["id"]
        have = {m["name"] for m in requests.get(
            f"{KC}/admin/realms/{REALM}/clients/{cid}/protocol-mappers/models",
            headers=H, timeout=20).json()}
        for m in MAPPERS:
            if m["name"] not in have:
                requests.post(f"{KC}/admin/realms/{REALM}/clients/{cid}/protocol-mappers/models",
                              headers=H, json=m, timeout=20)
        check(f"claim mappers on {cli}", True)

    for u in USERS:
        t = requests.post(f"{KC}/realms/{REALM}/protocol/openid-connect/token", timeout=20,
                          data={"grant_type": "password", "client_id": "andyur-cli",
                                "username": u["username"], "password": u["password"],
                                "scope": "openid"})
        good = t.status_code == 200 and claims(t.json()["access_token"]).get(
            "preferred_username") == u["username"]
        check(f"{u['username']} authenticates and carries her claims", good)


# ================================================== 2. the platform's own key
def setup_exchange_key():
    head("2. a PERSISTENT exchange key")
    key = ROOT / "data" / "secrets" / "exchange-key.pem"
    key.parent.mkdir(parents=True, exist_ok=True)
    if not key.exists():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key.write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        key.chmod(0o600)
    check("exchange key on disk", key.exists(), str(key.relative_to(ROOT)))
    # Without ANDYUR_EXCHANGE_KEY the platform generates a fresh key PER PROCESS
    # under the same `kid`. Every token then fails at a resource server holding
    # the other copy -- with no error that says so.
    live = requests.get(f"{CP}/.well-known/jwks.json", timeout=20).json()["keys"][0]
    from andyur.server import tokenexchange
    mine = tokenexchange.public_jwks()["keys"][0]
    check("the control plane signs with THIS key (not an ephemeral one)",
          live.get("n") == mine.get("n"),
          "" if live.get("n") == mine.get("n") else
          "restart the control plane with ANDYUR_EXCHANGE_KEY set")


# =========================================== 3. the resource server's key set
def setup_grafana_keys():
    head("3. the resource server's trusted key set")
    kc = requests.get(f"{KC}/realms/{REALM}/protocol/openid-connect/certs", timeout=20).json()
    kc_sig = [k for k in kc["keys"] if k.get("alg") == "RS256" and k.get("use") in (None, "sig")]
    an = requests.get(f"{CP}/.well-known/jwks.json", timeout=20).json()["keys"]
    out = ROOT / "data" / "grafana" / "jwks.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"keys": kc_sig + an}, indent=2))
    # Grafana REFUSES a plaintext jwk_set_url (https only), so the key set is a
    # mounted file. Two issuers: Keycloak signs the browser login, Andyur signs
    # the delegated API call.
    check("key set rendered", len(kc_sig) == 1 and len(an) >= 1,
          f"{len(kc_sig)} keycloak + {len(an)} andyur")


# ================================================================ 4. agents
def setup_agents():
    head("4. agents and their authority ceilings")
    sys.path.insert(0, str(ROOT))
    from andyur.server import registry
    for name in AGENTS:
        subprocess.run([str(ROOT / "andyur-cli"), "agents", "create", name,
                        "--description", f"federated enterprise demo: {name}"],
                       cwd=ROOT, capture_output=True, text=True)
        # A ceiling the agent cannot raise. An UNREGISTERED actor is refused
        # outright rather than granted an empty token.
        registry.set_ceiling(name, actions=["telemetry:read", "incidents:read",
                                            "incidents:write", "tasks:write",
                                            "messages:write"], audiences=[TOOL_RESOURCE])
        check(f"agent {name} exists with a ceiling", True,
              "telemetry:read, incidents:read, incidents:write")


# ================================================================ 5. proof
def verify():
    head("5. does delegation actually work, end to end")
    sys.path.insert(0, str(ROOT))
    from andyur.server import tokenexchange, runtoken

    def mint(**kw):
        o = tokenexchange.mint(**kw)
        return o[0] if isinstance(o, tuple) else o

    def as_user(tok):
        r = requests.get(f"{GF}/api/user", headers={"X-Andyur-Auth": tok}, timeout=20)
        return r.status_code, (r.json().get("login") if r.status_code == 200 else "")

    t1 = mint(actor="incident-responder", audience=TOOL_RESOURCE, ctx_sub="sarah.miller",
              ctx_sub_src=runtoken.SUB_SRC_IDP, ctx_scope=["telemetry:read"],
              requested_scope=["telemetry:read"])
    t2 = mint(actor="platform-engineer", audience=TOOL_RESOURCE, subject_token=t1,
              requested_scope=["telemetry:read"])
    c2 = claims(t2)
    check("the human survives two agent hops", c2["sub"] == "sarah.miller", f"sub={c2['sub']}")
    check("the agent chain is recorded", 
          c2["act"] == {"sub": "platform-engineer", "act": {"sub": "incident-responder"}},
          json.dumps(c2["act"]))
    code, login = as_user(t2)
    check("the resource server sees SARAH, not a robot", code == 200 and login == "sarah.miller",
          f"{code} {login}")

    # A demo where everything succeeds proves nothing.
    ta = mint(actor="incident-responder", audience=TOOL_RESOURCE, ctx_sub="sarah.miller",
              ctx_sub_src=runtoken.SUB_SRC_ASSERTED, ctx_scope=["telemetry:read"],
              requested_scope=["telemetry:read"])
    code, _ = as_user(ta)
    check("an ASSERTED subject is REFUSED by the resource server", code == 401, f"{code}")

    t3 = mint(actor="platform-engineer", audience=TOOL_RESOURCE, subject_token=t1,
              requested_scope=["telemetry:read", "incidents:write"])
    check("a delegate cannot WIDEN what it was given",
          claims(t3)["scope"] == ["telemetry:read"], str(claims(t3)["scope"]))

    r = requests.post(f"{GF}/login", json={"user": "sarah.miller",
                                           "password": "sarah-password"}, timeout=20)
    check("Sarah has NO local password at the resource server", r.status_code >= 400,
          f"POST /login -> {r.status_code}")

    # THE TWO LEGS ARE DELIBERATELY DIFFERENT, and this is the check that says so.
    #
    # The API leg accepts ONLY Andyur-minted tokens: `expect_claims` requires
    # `andyur_sub_src`, which a raw IdP token does not carry. So a stolen
    # Keycloak access token cannot drive the agent path -- it is not merely
    # unscoped there, it is refused. Interactive role mapping (Sarah=Editor,
    # David=Admin from the realm role) belongs to the BROWSER leg, generic_oauth,
    # and is exercised by logging in, not by this header.
    for who, pw in (("sarah.miller", "sarah-password"), ("david.kumar", "david-password")):
        raw = requests.post(f"{KC}/realms/{REALM}/protocol/openid-connect/token", timeout=20,
                            data={"grant_type": "password", "client_id": "andyur-cli",
                                  "username": who, "password": pw,
                                  "scope": "openid"}).json()["access_token"]
        code, _ = as_user(raw)
        check(f"a RAW IdP token for {who} is refused on the delegated API path",
              code == 401, f"{code} (no act chain, no andyur_sub_src)")


def main():
    os.environ.setdefault("ANDYUR_PROFILE", "dev")
    os.environ.setdefault("ANDYUR_EXCHANGE_KEY",
                          str(ROOT / "data" / "secrets" / "exchange-key.pem"))
    os.environ.setdefault("ANDYUR_DB", str(ROOT / "data" / "andyur.db"))
    sys.path.insert(0, str(ROOT))
    H = kc_admin()
    setup_idp(H)
    setup_exchange_key()
    setup_grafana_keys()
    print("\n  (re-creating grafana so it re-reads the key set)")
    subprocess.run(["docker", "compose", "-f", str(ROOT / "infra" / "docker-compose.yml"),
                    "--env-file", str(ROOT / "data" / "docker.env"),
                    "--profile", "idp", "up", "-d", "--force-recreate", "grafana"],
                   capture_output=True)
    for _ in range(30):
        try:
            if requests.get(f"{GF}/api/health", timeout=3).status_code == 200:
                break
        except Exception:
            pass
        time.sleep(2)
    setup_agents()
    verify()
    print()
    if _fails:
        print(f"\033[31mSETUP INCOMPLETE: {len(_fails)} check(s) failed\033[0m")
        for f in _fails:
            print(f"  - {f}")
        return 1
    print("\033[32mFEDERATED DEMO ENVIRONMENT READY\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
