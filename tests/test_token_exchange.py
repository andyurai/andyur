"""U4 Part A: RFC 8693 downstream delegation, never widening.

The exchange mints a downstream grant that keeps the same user, appends the delegatee
to a nested `act` chain, and narrows scope to a subset of the parent's -- widening is
impossible by construction. For external targets it issues an RS256 JWT verifiable
against Andyur's JWKS with no callback. Covers the primitive, the never-widening
property, external verification, and the /oauth/token + JWKS endpoints.
"""

import json

import jwt
import pytest
from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module, runtoken, tokenexchange

client = TestClient(app_module.app)


@pytest.fixture(autouse=True)
def _actors(env):
    """Every actor these tests delegate TO is a registered agent with no ceiling
    set, i.e. unrestricted. The mint reads the ceiling from the registry by actor
    name, so an unregistered actor is refused outright (see
    test_an_unregistered_actor_is_refused_rather_than_granted_nothing) -- which
    would make every test below fail for a reason it is not about."""
    for name in ("reviewer", "scout", "b", "nouser"):
        _register(name)
    return env


def _register(name: str) -> str:
    """OR IGNORE because the autouse fixture and `_run` both want the actor to
    exist and neither should care which of them got there first."""
    with db.connect() as c:
        c.execute(
            "INSERT OR IGNORE INTO agents (name, description, paused, created_at) "
            "VALUES (?, '', 0, ?)",
            (name, db.utcnow()),
        )
    return name


# -- the primitive: sub preserved, act chain nests -----------------------------

def test_the_user_travels_and_is_never_chosen_by_the_caller():
    tok = tokenexchange.exchange("reviewer", "tool:calendar", ctx_sub="alice",
                                 ctx_scope=["files:read"])
    claims = tokenexchange.verify_delegated(tok, audience="tool:calendar")
    assert claims["sub"] == "alice"          # the user came from the parent
    assert claims["act"]["sub"] == "reviewer"   # the delegatee is the actor


def test_the_act_chain_nests_across_hops():
    first = tokenexchange.exchange("scout", "andyur", ctx_sub="alice",
                                   ctx_scope=["files:read", "files:write"])
    # scout now re-delegates to reviewer, presenting the first token as the subject
    second = tokenexchange.exchange("reviewer", "tool:x", subject_token=first,
                                    requested_scope=["files:read"])
    claims = tokenexchange.verify_delegated(second, audience="tool:x")
    assert claims["sub"] == "alice"
    assert claims["act"]["sub"] == "reviewer"        # newest actor on top
    assert claims["act"]["act"]["sub"] == "scout"    # prior actor nested beneath


# -- the property: a downstream grant can never be wider than its parent -------

def test_scope_narrows_and_widening_is_dropped():
    tok = tokenexchange.exchange("b", "andyur", ctx_sub="alice",
                                 ctx_scope=["files:read"],
                                 requested_scope=["files:read", "files:write"])
    # asked for write too, but the parent only had read -> write is dropped
    assert tokenexchange.verify_delegated(tok)["scope"] == ["files:read"]


def test_no_request_inherits_the_parent_scope():
    tok = tokenexchange.exchange("b", "andyur", ctx_sub="alice", ctx_scope=["files:read"])
    assert tokenexchange.verify_delegated(tok)["scope"] == ["files:read"]


def test_unrestricted_parent_yields_exactly_what_is_requested():
    tok = tokenexchange.exchange("b", "andyur", ctx_sub="alice", ctx_scope=None,
                                 requested_scope=["files:read"])
    assert tokenexchange.verify_delegated(tok)["scope"] == ["files:read"]
    star = tokenexchange.exchange("b", "andyur", ctx_sub="alice", ctx_scope=["*"],
                                  requested_scope=["files:write"])
    assert tokenexchange.verify_delegated(star)["scope"] == ["files:write"]


def test_cannot_delegate_without_a_user():
    with pytest.raises(tokenexchange.ExchangeError):
        tokenexchange.exchange("b", "andyur", ctx_sub=None, ctx_scope=["files:read"])


def test_a_chained_token_cannot_relabel_its_user():
    first = tokenexchange.exchange("scout", "andyur", ctx_sub="alice", ctx_scope=["*"])
    # a caller authenticated as bob presents alice's token -> refused, no user swap
    with pytest.raises(tokenexchange.ExchangeError):
        tokenexchange.exchange("b", "tool:x", subject_token=first, ctx_sub="bob")


# -- external verification: audience binding + tamper resistance ---------------

def test_wrong_audience_is_refused():
    tok = tokenexchange.exchange("b", "tool:calendar", ctx_sub="alice", ctx_scope=["*"])
    with pytest.raises(tokenexchange.InvalidDelegatedToken):
        tokenexchange.verify_delegated(tok, audience="tool:email")


def test_a_tampered_token_is_refused():
    tok = tokenexchange.exchange("b", "tool:x", ctx_sub="alice", ctx_scope=["*"])
    head, payload, sig = tok.split(".")
    with pytest.raises(tokenexchange.InvalidDelegatedToken):
        tokenexchange.verify_delegated(head + "." + payload + "." + sig[:-4] + "AAAA")


def test_an_external_target_validates_against_the_jwks_alone():
    tok = tokenexchange.exchange("b", "tool:x", ctx_sub="alice", ctx_scope=["files:read"])
    # the target has ONLY the published JWKS, never the private key or a server call
    jwks = tokenexchange.public_jwks()
    pub = jwt.PyJWK(jwks["keys"][0]).key
    claims = jwt.decode(tok, pub, algorithms=["RS256"], audience="tool:x")
    assert claims["sub"] == "alice" and claims["scope"] == ["files:read"]


# -- the endpoints -------------------------------------------------------------

def _run(env, agent, run_id, user, scope):
    _register(agent)
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at, acting_user, scope) "
            "VALUES (?, ?, 'running', ?, ?, ?)",
            (run_id, agent, db.utcnow(), user, json.dumps(scope) if scope else None),
        )
    return {"X-Andyur-Run-Token": runtoken.mint(agent, run_id, "wf", sub=user, scope=scope)}


def test_jwks_endpoint_serves_a_verifying_key(env):
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    assert keys and keys[0]["kty"] == "RSA" and keys[0]["alg"] == "RS256"


def test_exchange_endpoint_mints_a_narrowed_delegated_token(env):
    hdr = _run(env, "scout", "run-x", "alice", ["files:read"])
    r = client.post("/oauth/token",
                    json={"audience": "tool:cal", "actor": "reviewer",
                          "scope": ["files:read", "files:write"]},
                    headers=hdr)
    assert r.status_code == 200
    claims = tokenexchange.verify_delegated(r.json()["access_token"], audience="tool:cal")
    assert claims["sub"] == "alice"               # the run's user, sealed in
    assert claims["act"]["sub"] == "reviewer"
    assert claims["scope"] == ["files:read"]      # write dropped: capped to the run's scope


def test_token_responses_forbid_caching(env):
    """RFC 6749 sec 5.1 (MUST): a token endpoint response is not cacheable, or an
    intermediary/client cache may replay a 200 token response to a later request.
    Both the token-bearing 200 and the OAuth-coded error carry no-store."""
    hdr = _run(env, "scout", "run-x", "alice", ["files:read"])
    ok = client.post("/oauth/token",
                     json={"audience": "tool:cal", "actor": "reviewer",
                           "scope": ["files:read"]},
                     headers=hdr)
    assert ok.status_code == 200 and "access_token" in ok.json()
    assert ok.headers["cache-control"] == "no-store"
    assert ok.headers["pragma"] == "no-cache"
    # An error from this endpoint (unregistered actor -> invalid_target) is
    # equally uncacheable: the header, not the body shape, is the property here.
    err = client.post("/oauth/token",
                      json={"audience": "tool:cal", "actor": "ghost-not-registered",
                            "scope": ["files:read"]},
                      headers=hdr)
    assert err.status_code >= 400
    assert err.headers["cache-control"] == "no-store"


def test_the_mint_itself_refuses_production_not_only_the_endpoint(monkeypatch):
    """Defense in depth for 17876bb: the prod invariant lives at the mint, not
    only at the /oauth/token door in front of it. A future second caller added
    without repeating the endpoint's PROD check would otherwise silently
    reintroduce prod self-signing; here we call mint directly under PROD and
    require it to refuse. The refusal is a RuntimeError, NOT an ExchangeError,
    so the endpoint's handlers cannot catch it and downgrade it to a 400."""
    monkeypatch.setattr(config, "PROD", True)
    with pytest.raises(RuntimeError, match="must not sign its own tool authority"):
        tokenexchange.mint("reviewer", "tool:cal", caller="scout",
                           ctx_sub="alice", ctx_scope=["files:read"])
    # And it is not in the family the endpoint turns into a refusal.
    assert not issubclass(RuntimeError, tokenexchange.ExchangeError)


def test_prod_with_no_external_as_withholds_the_delegated_tool_end_to_end(
        env, monkeypatch):
    """L's residual on 17876bb: the whole point of moving the AS requirement
    from boot to point-of-use is that a prod deployment with NO external AS
    still never mints local tool authority -- it fails closed at the mint. The
    two halves are tested separately (the endpoint 403s in prod; a failed
    exchange withholds); this proves the JOIN end to end. It drives the runner's
    real local-mint exchange_fn (gateway.local_exchange, the exact fn the
    sidecar uses) against the REAL app under PROD with AS_TOKEN_ENDPOINT unset,
    routing its HTTP to the live TestClient, and requires it to RAISE -- which
    is how the sidecar/runner withholds the tool rather than forwarding a
    locally-signed token."""
    from andyur.runner import gateway

    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "")   # no external AS
    hdr = _run(env, "scout", "run-noas", "alice", ["files:read"])
    run_token = hdr["X-Andyur-Run-Token"]

    last = {}

    def route_to_app(host, port, method, path, headers, payload, timeout):
        r = client.request(method, path, headers=headers, content=payload)
        last.update(status=r.status_code, body=r.json())
        return (r.status_code, dict(r.headers), r.content)

    monkeypatch.setattr(gateway, "_http", route_to_app)

    exchange = gateway.local_exchange(run_token, "testserver:80")
    with pytest.raises(gateway.GatewayUnavailable):
        exchange(audience="tool:cal", scope=["files:read"])
    # ...and it failed closed for the RIGHT reason: the prod signer refusal,
    # not an unrelated error that would mask a real regression.
    assert last["status"] == 403
    assert last["body"]["detail"]["error"] == "access_denied"


def test_exchange_endpoint_is_disabled_in_production(env, monkeypatch):
    """A missed startup check must not expose Andyur as production authority."""
    hdr = _run(env, "scout", "run-prod", "alice", ["files:read"])
    monkeypatch.setattr(config, "PROD", True)

    r = client.post("/oauth/token",
                    json={"audience": "tool:cal", "actor": "reviewer",
                          "scope": ["files:read"]},
                    headers=hdr)

    assert r.status_code == 403
    assert r.json() == {
        "detail": {
            "error": "access_denied",
            "error_description": (
                "Andyur's local token signer is disabled in production; use the "
                "configured enterprise authorization server"),
        },
    }


def test_exchange_endpoint_refuses_a_run_with_no_user(env):
    hdr = _run(env, "nouser", "run-n", None, ["files:read"])
    r = client.post("/oauth/token",
                    json={"audience": "tool:x", "actor": "b"}, headers=hdr)
    assert r.status_code == 400
