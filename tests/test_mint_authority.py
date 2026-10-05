"""The mint intersects all four authority terms, not two.

`registry.narrow()` is tested on its own in test_ceiling.py. What is tested HERE
is that the mint actually calls it -- that the ceiling and the pin reach the token
that gets issued, rather than sitting in a module nothing on the issuing path
imports. That gap is the specific bug these tests exist to catch: an intersection
that is correct and unreachable grants exactly as much as no intersection at all.

So every test below asserts on a MINTED TOKEN's claims, never on a return value
from registry, and each isolates one term by leaving the other three unrestricted.
Each also asserts the positive half -- what survives -- because "the write is
gone" passes just as happily when the whole grant came back empty for an unrelated
reason.
"""

import json

import pytest
from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module, registry, runtoken, tokenexchange
from andyur.server.app import ACCESS_TOKEN_TYPE

client = TestClient(app_module.app)


def _agent(name: str, actions=None, audiences=None) -> str:
    with db.connect() as c:
        c.execute(
            "INSERT OR IGNORE INTO agents (name, description, paused, created_at) "
            "VALUES (?, '', 0, ?)",
            (name, db.utcnow()),
        )
    if actions is not None or audiences is not None:
        registry.set_ceiling(name, actions=actions, audiences=audiences)
    return name


def _scope_of(token: str, audience: str) -> list:
    return tokenexchange.verify_delegated(token, audience=audience)["scope"]


# --- the ceiling reaches the token -------------------------------------------

def test_the_ceiling_narrows_the_mint_even_when_the_user_is_fully_entitled(env):
    """The entitlement and the request both say write; only the actor's ceiling
    says otherwise. If the mint ignored the registry this would return write."""
    _agent("classifier", actions=["files:read"])
    tok = tokenexchange.exchange(
        "classifier", "tool:x", ctx_sub="alice",
        ctx_scope=["files:read", "files:write"],
        requested_scope=["files:read", "files:write"])
    assert _scope_of(tok, "tool:x") == ["files:read"]


def test_two_actors_asking_identically_get_different_grants(env):
    """The same user, the same request, the same audience -- the ONLY difference
    is which agent the token is minted for. A mint that derives scope from the
    request cannot tell these two apart; one that re-derives per actor must."""
    _agent("reader", actions=["files:read"])
    _agent("writer", actions=["files:read", "files:write"])
    ask = dict(ctx_sub="alice", ctx_scope=["files:read", "files:write"],
               requested_scope=["files:read", "files:write"])
    assert _scope_of(tokenexchange.exchange("reader", "tool:x", **ask), "tool:x") \
        == ["files:read"]
    assert _scope_of(tokenexchange.exchange("writer", "tool:x", **ask), "tool:x") \
        == ["files:read", "files:write"]


def test_an_unset_ceiling_still_mints_rather_than_bricking_the_agent(env):
    """A registered agent with no ceiling configured is UNRESTRICTED. Upgrading a
    live database adds the columns as NULL, so reading that as "deny" would brick
    every agent that existed before the ceiling did."""
    _agent("fresh")
    assert _scope_of(
        tokenexchange.exchange("fresh", "tool:x", ctx_sub="alice",
                               ctx_scope=["files:read"]), "tool:x") == ["files:read"]


def test_an_unregistered_actor_is_refused_rather_than_granted_nothing(env):
    """An unknown actor has no readable ceiling. The failure must be an ERROR and
    not a successfully minted token that happens to permit nothing: a credential
    that silently does nothing is debugged as an outage, days later, by someone
    who does not know a security control produced it."""
    with pytest.raises(tokenexchange.ExchangeError, match="no registry entry"):
        tokenexchange.exchange("ghost", "tool:x", ctx_sub="alice",
                               ctx_scope=["files:read"])


def test_existence_and_ceiling_come_from_a_single_read(env):
    """A structural test, because the bug it guards is a RACE and cannot be
    provoked deterministically: if the mint asks "does this agent exist?" and then
    separately "what is its ceiling?", the agent can be deleted in between, and
    the legible "unknown actor" refusal silently becomes a token that grants
    nothing. One read cannot disagree with itself."""
    _agent("worker")
    # Counted at the DATABASE, not at one helper: a check that issues its own SQL
    # -- which is exactly what the removed registry.known() did -- sails straight
    # past a counter wrapped around a single function.
    reads = []
    real_connect = db.connect

    class _Counting:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *a, **kw):
            if "FROM agents" in sql:
                reads.append(sql)
            return self._conn.execute(sql, *a, **kw)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    class _Ctx:
        def __enter__(self):
            self._cm = real_connect()
            return _Counting(self._cm.__enter__())

        def __exit__(self, *exc):
            return self._cm.__exit__(*exc)

    registry.db.connect = lambda: _Ctx()
    try:
        tokenexchange.exchange("worker", "tool:x", ctx_sub="alice",
                               ctx_scope=["files:read"])
    finally:
        registry.db.connect = real_connect
    assert len(reads) == 1, f"the agents table was read {len(reads)} times"


# --- the audience is a conjunct, and a refusal is not a redirect --------------

def test_an_audience_above_the_ceiling_is_refused_not_quietly_rewritten(env):
    _agent("narrow", audiences=["tool:calendar"])
    with pytest.raises(tokenexchange.AudienceRefused, match="narrow"):
        tokenexchange.exchange("narrow", "tool:payments", ctx_sub="alice",
                               ctx_scope=["*"])
    # the positive control: the permitted audience still mints, so the refusal
    # above is attributable to the audience and not to a broken actor
    tok = tokenexchange.exchange("narrow", "tool:calendar", ctx_sub="alice",
                                 ctx_scope=["files:read"])
    assert tokenexchange.verify_delegated(tok, audience="tool:calendar")["sub"] == "alice"


def test_a_malformed_pin_is_not_reported_as_an_audience_refusal(env):
    """`narrow()` empties the WHOLE authority for an unreadable pin, audience
    included, so using "audience is None" as the proxy for "audience refused"
    reported a malformed pin to the operator as "this audience is above your
    ceiling" -- a wrong diagnosis pointing at the wrong control, which is worse
    than none. The two causes must raise distinguishable errors."""
    _agent("worker")
    with pytest.raises(tokenexchange.MalformedPin, match="str"):
        tokenexchange.exchange("worker", "tool:x", ctx_sub="alice",
                               ctx_scope=["files:read"], pin="447")
    # and the genuine audience refusal is still its own type, not swallowed by it
    _agent("narrowed", audiences=["tool:calendar"])
    with pytest.raises(tokenexchange.AudienceRefused, match="tool:payments"):
        tokenexchange.exchange("narrowed", "tool:payments", ctx_sub="alice",
                               ctx_scope=["files:read"])


def test_a_deny_all_ceiling_refuses_rather_than_minting_an_empty_credential(env):
    """A ceiling of [] is a deliberate deny, but a token whose scope is [] is a
    credential that validates everywhere and permits nothing: every call made with
    it fails elsewhere, for reasons that never mention the ceiling. Same argument
    as the unregistered actor -- refuse, loudly."""
    _agent("muzzled", actions=[])
    with pytest.raises(tokenexchange.AuthorityEmpty, match="muzzled"):
        tokenexchange.exchange("muzzled", "tool:x", ctx_sub="alice",
                               ctx_scope=["files:read"])
    # the positive control: the same agent with a non-empty ceiling still mints
    registry.set_ceiling("muzzled", actions=["files:read"])
    assert _scope_of(tokenexchange.exchange("muzzled", "tool:x", ctx_sub="alice",
                                            ctx_scope=["files:read"]),
                     "tool:x") == ["files:read"]


def test_a_pin_that_drops_every_action_refuses_too(env):
    """The empty grant can come from the PIN rather than the ceiling: every action
    qualified for another account leaves nothing. Same refusal, so the empty-token
    hole cannot be reopened through a different term."""
    _agent("worker")
    with pytest.raises(tokenexchange.AuthorityEmpty):
        tokenexchange.exchange("worker", "tool:x", ctx_sub="alice",
                               ctx_scope=["files:read@account=999"],
                               pin={"account": "447"})


def test_delegation_needs_an_audience(env):
    """A token with no audience is replayable at every target, which is the whole
    reason the audience is a term."""
    _agent("worker")
    for empty in (None, "", "   ", "*"):
        with pytest.raises(tokenexchange.ExchangeError):
            tokenexchange.exchange("worker", empty, ctx_sub="alice",
                                   ctx_scope=["files:read"])
    # the positive control: a real audience still mints, so the loop above is
    # rejecting these VALUES and not simply refusing this agent
    assert _scope_of(tokenexchange.exchange("worker", "tool:x", ctx_sub="alice",
                                            ctx_scope=["files:read"]),
                     "tool:x") == ["files:read"]


def test_the_request_cannot_exceed_the_entitlement_when_nothing_else_restricts(env):
    """Entitlement isolated: the ceiling is unset, the run is unpinned, and the
    delegatee asks for something the USER never had. Every other test in this file
    sets the request equal to the entitlement, which cannot tell the two apart."""
    _agent("worker")
    with pytest.raises(tokenexchange.AuthorityEmpty):
        tokenexchange.exchange("worker", "tool:x", ctx_sub="alice",
                               ctx_scope=["files:read"],
                               requested_scope=["files:write"])


# --- the CALLER is a term, not a bystander -----------------------------------

def test_naming_a_more_capable_delegatee_does_not_widen_the_callers_grant(env):
    """The minted token is returned to the CALLER in the response body, so "it
    was minted for someone else" is not a control over who holds it. A read-only
    agent that nominates a write-capable delegatee must still not come away
    holding write."""
    _agent("classifier", actions=["files:read"])
    _agent("specialist", actions=["files:read", "files:write"])
    tok = tokenexchange.exchange(
        "specialist", "tool:fs", caller="classifier", ctx_sub="alice",
        ctx_scope=["files:read", "files:write"])
    assert _scope_of(tok, "tool:fs") == ["files:read"]
    # the positive control: with the SAME request from a caller whose ceiling
    # permits write, write survives -- so the drop above is the caller's ceiling
    # and not something refusing the whole exchange
    tok2 = tokenexchange.exchange(
        "specialist", "tool:fs", caller="specialist", ctx_sub="alice",
        ctx_scope=["files:read", "files:write"])
    assert _scope_of(tok2, "tool:fs") == ["files:read", "files:write"]


def test_a_caller_cannot_reach_a_forbidden_audience_through_a_permitted_actor(env):
    """The audience half of the same hole: nominating an agent that IS allowed
    tool:payments must not get a tool:payments token into hands confined to
    tool:calendar."""
    _agent("classifier", audiences=["tool:calendar"])
    _agent("banker", audiences=["tool:payments"])
    with pytest.raises(tokenexchange.AudienceRefused, match="classifier"):
        tokenexchange.exchange("banker", "tool:payments", caller="classifier",
                               ctx_sub="alice", ctx_scope=["*"])
    # the positive control uses an actor whose OWN ceiling permits tool:calendar,
    # so the refusal above is attributable to the caller's ceiling rather than to
    # the actor's (banker is confined to tool:payments and would refuse either way)
    _agent("assistant")
    ok = tokenexchange.exchange("assistant", "tool:calendar", caller="classifier",
                                ctx_sub="alice", ctx_scope=["files:read"])
    assert _scope_of(ok, "tool:calendar") == ["files:read"]


# --- a chain hop carries the pin, and only its rightful holder may extend it --

def _grant(pin=None, scope=("payments:transfer",)) -> str:
    _agent("runnerA")
    _agent("runnerB")
    return tokenexchange.exchange("runnerB", "tool:bank", caller="runnerA",
                                  ctx_sub="alice", ctx_scope=list(scope), pin=pin)


def test_the_pin_survives_a_chain_hop_from_an_unpinned_run(env):
    """Presented from an UNPINNED run, the re-minted token used to carry no
    resource claim at all -- a laundering step that turned "may transfer, for
    account 447" into "may transfer". The bound must be inherited, not dropped."""
    t1 = _grant(pin={"account": "447"})
    t2 = tokenexchange.exchange("runnerB", "tool:bank", caller="runnerB",
                                subject_token=t1, ctx_sub="alice", pin=None)
    detail = tokenexchange.verify_delegated(t2, audience="tool:bank")[
        "authorization_details"][0]
    assert detail["resources"] == {"account": "447"}


def test_a_chain_hop_cannot_re_pin_a_grant_to_another_resource(env):
    """The inverse direction: presented from a run pinned to 999, the 447 grant's
    actions must not be restamped onto 999 -- no authenticated party ever paired
    that action with that account."""
    t1 = _grant(pin={"account": "447"})
    with pytest.raises(tokenexchange.ExchangeError, match="447"):
        tokenexchange.exchange("runnerB", "tool:bank", caller="runnerB",
                               subject_token=t1, ctx_sub="alice",
                               pin={"account": "999"})


def test_only_the_agent_a_grant_was_minted_for_may_extend_it(env):
    """Matching on the user alone made ANY same-user grant a re-mint key: an
    agent holding a narrow token could present a wider one it merely observed and
    continue THAT chain. RFC 8693 puts the delegatee in act.sub, and the delegatee
    is the party entitled to spend it and so to extend it."""
    _agent("bystander")
    t1 = _grant(pin={"account": "447"})
    with pytest.raises(tokenexchange.ExchangeError, match="runnerB"):
        tokenexchange.exchange("bystander", "tool:bank", caller="bystander",
                               subject_token=t1, ctx_sub="alice")
    # the positive control: the rightful holder extends its own grant
    t2 = tokenexchange.exchange("runnerB", "tool:bank", caller="runnerB",
                                subject_token=t1, ctx_sub="alice",
                                pin={"account": "447"})
    assert _scope_of(t2, "tool:bank") == ["payments:transfer"]


def test_hop_two_of_a_chain_still_meets_the_ceiling(env):
    """The chain path is the route this whole control exists to close: a
    read-only classifier reaching a write-capable specialist. Hop 1 was covered
    and hop 2 was not, so re-delegation could have skipped the registry entirely
    with nothing going red."""
    _agent("runnerA")
    _agent("runnerB")
    _agent("specialist", actions=["files:read"])
    t1 = tokenexchange.exchange("runnerB", "tool:fs", caller="runnerA",
                                ctx_sub="alice",
                                ctx_scope=["files:read", "files:write"])
    t2 = tokenexchange.exchange("specialist", "tool:fs", caller="runnerB",
                                subject_token=t1, ctx_sub="alice",
                                requested_scope=["files:read", "files:write"])
    assert _scope_of(t2, "tool:fs") == ["files:read"]


def test_hop_two_refuses_an_unregistered_actor_and_a_forbidden_audience(env):
    """The other two registry terms on the same untested hop."""
    _agent("runnerA")
    _agent("runnerB")
    _agent("confined", audiences=["tool:calendar"])
    t1 = tokenexchange.exchange("runnerB", "tool:fs", caller="runnerA",
                                ctx_sub="alice", ctx_scope=["files:read"])
    with pytest.raises(tokenexchange.UnknownActor):
        tokenexchange.exchange("ghost", "tool:fs", caller="runnerB",
                               subject_token=t1, ctx_sub="alice")
    with pytest.raises(tokenexchange.AudienceRefused):
        tokenexchange.exchange("confined", "tool:payments", caller="runnerB",
                               subject_token=t1, ctx_sub="alice")


def test_the_endpoint_applies_the_delegation_allowlist(env, monkeypatch):
    """Handing an agent a TOKEN for a delegatee is delegation exactly as much as
    handing it a task is; the operator's allow-list meant nothing on the one path
    that mints credentials."""
    from andyur.server import delegation
    _agent("scout")
    _agent("reviewer")
    monkeypatch.setattr(delegation, "_ALLOW", {"scout": {"nobody"}})
    hdr = _run("scout", "run-d", "alice", ["files:read"])
    r = client.post("/oauth/token",
                    json={"audience": "tool:cal", "actor": "reviewer"}, headers=hdr)
    assert r.status_code == 403
    monkeypatch.setattr(delegation, "_ALLOW", {"scout": {"reviewer"}})
    ok = client.post("/oauth/token",
                     json={"audience": "tool:cal", "actor": "reviewer"}, headers=hdr)
    assert ok.status_code == 200


# --- the pin reaches the token ------------------------------------------------

def test_the_pin_travels_in_the_minted_token(env):
    """The resource server must be able to ask "was this token minted for the
    account I am being asked to touch?" without a callback, so the pin has to be
    IN the token."""
    _agent("worker")
    tok = tokenexchange.exchange("worker", "tool:x", ctx_sub="alice",
                                 ctx_scope=["files:read"], pin={"account": "447"})
    claims = tokenexchange.verify_delegated(tok, audience="tool:x")
    detail = claims["authorization_details"][0]
    assert detail["resources"] == {"account": "447"}
    assert detail["actions"] == ["files:read"]


def test_an_action_qualified_for_another_resource_is_dropped_by_the_mint(env):
    """An entitlement may name the resource it applies to. One that names a
    DIFFERENT account than the run is pinned to must not survive into the token,
    or the pin is decoration."""
    _agent("worker")
    tok = tokenexchange.exchange(
        "worker", "tool:x", ctx_sub="alice",
        ctx_scope=["files:read", "files:write@account=999"],
        pin={"account": "447"})
    assert _scope_of(tok, "tool:x") == ["files:read"]


def test_an_unrestricted_pinned_grant_omits_actions_rather_than_nulling_it(env):
    """"No action model restricts this run" is not a statement a RAR object can
    make with `"actions": null` -- a resource server reading a null there must
    guess between "everything" and "nothing", and one of those guesses is a
    breach. The resource bound still travels."""
    _agent("worker")
    tok = tokenexchange.exchange("worker", "tool:x", ctx_sub="alice",
                                 ctx_scope=None, pin={"account": "447"})
    detail = tokenexchange.verify_delegated(tok, audience="tool:x")[
        "authorization_details"][0]
    assert detail["resources"] == {"account": "447"}
    assert "actions" not in detail


def test_an_unpinned_run_mints_without_authorization_details(env):
    """Unpinned is the pre-pin behaviour and must stay a working grant, not an
    empty one -- and it must not claim a resource bound it does not have."""
    _agent("worker")
    tok = tokenexchange.exchange("worker", "tool:x", ctx_sub="alice",
                                 ctx_scope=["files:read"])
    claims = tokenexchange.verify_delegated(tok, audience="tool:x")
    assert claims["scope"] == ["files:read"]
    assert "authorization_details" not in claims


# --- the endpoint: the pin comes from the run, never from the request ---------

def _run(agent, run_id, user, scope, pin=None) -> dict:
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at, acting_user, scope) "
            "VALUES (?, ?, 'running', ?, ?, ?)",
            (run_id, agent, db.utcnow(), user, json.dumps(scope) if scope else None),
        )
    return {"X-Andyur-Run-Token":
            runtoken.mint(agent, run_id, "wf", sub=user, scope=scope, pin=pin)}


def test_the_endpoint_mints_from_the_runs_pin(env):
    _agent("scout")
    _agent("reviewer")
    hdr = _run("scout", "run-p", "alice", ["files:read"], pin={"account": "447"})
    r = client.post("/oauth/token",
                    json={"audience": "tool:cal", "actor": "reviewer"}, headers=hdr)
    assert r.status_code == 200
    claims = tokenexchange.verify_delegated(r.json()["access_token"],
                                            audience="tool:cal")
    assert claims["authorization_details"][0]["resources"] == {"account": "447"}


def test_a_body_that_carries_a_pin_is_rejected_not_quietly_ignored(env):
    """The run is pinned to 447 and the body asks for 999. The body is not a place
    a pin can come from -- otherwise the model, which composes this request, could
    retarget its own authority by writing a different number.

    Rejected rather than dropped: pydantic would silently discard the unknown key,
    which tells a confused client nothing and tells a probing one nothing either.
    422 tells both, and it cannot rot the way "we happen not to read that field"
    can when someone later adds a field with that name."""
    _agent("scout")
    _agent("reviewer")
    hdr = _run("scout", "run-q", "alice", ["files:read"], pin={"account": "447"})
    r = client.post("/oauth/token",
                    json={"audience": "tool:cal", "actor": "reviewer",
                          "pin": {"account": "999"},
                          "authorization_details": [
                              {"type": "urn:andyur:authority",
                               "resources": {"account": "999"}}]},
                    headers=hdr)
    assert r.status_code == 422
    # the positive control: the same request WITHOUT the smuggled fields succeeds,
    # and the pin it comes back with is the run's, not anything the body said
    ok = client.post("/oauth/token",
                     json={"audience": "tool:cal", "actor": "reviewer"}, headers=hdr)
    assert ok.status_code == 200
    claims = tokenexchange.verify_delegated(ok.json()["access_token"],
                                            audience="tool:cal")
    assert claims["authorization_details"][0]["resources"] == {"account": "447"}


def test_a_ceiling_refusal_carries_the_invalid_target_error_code(env):
    """Well-formed request, answer is no. RFC 8693 sec 2.2.2 has a dedicated code
    for "the AS is unwilling to issue for that target", and RFC 6749 sec 5.2 makes
    it a 400. The code is what separates this from every other 400 on the endpoint
    -- greppable in an audit trail in a way a prose `detail` string is not."""
    _agent("scout")
    _agent("narrow", audiences=["tool:calendar"])
    hdr = _run("scout", "run-r", "alice", ["files:read"])
    r = client.post("/oauth/token",
                    json={"audience": "tool:payments", "actor": "narrow"},
                    headers=hdr)
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_target"
    # positive control: the same caller and the permitted audience still succeeds
    ok = client.post("/oauth/token",
                     json={"audience": "tool:calendar", "actor": "narrow"},
                     headers=hdr)
    assert ok.status_code == 200


def test_the_endpoint_refuses_an_unregistered_actor(env):
    _agent("scout")
    hdr = _run("scout", "run-s", "alice", ["files:read"])
    r = client.post("/oauth/token",
                    json={"audience": "tool:cal", "actor": "ghost"}, headers=hdr)
    assert r.status_code == 400
    body = r.json()["detail"]
    # invalid_target, not invalid_request: the caller named a delegatee that does
    # not exist, which is a policy answer about the target rather than a syntax
    # complaint about the request.
    assert body["error"] == "invalid_target"
    assert "registry" in body["error_description"]


def _op() -> dict:
    """Operator credentials. In the dev profile agent-auth is off, so the
    operator is whoever calls without a run token."""
    return {}


# --- the operator surface -----------------------------------------------------

def test_the_ceiling_can_be_set_and_read_by_the_operator(env):
    """The ceiling became a term the mint enforces on every call while being
    configurable only by hand-edited SQL, where a typo reads back as DENY_ALL. A
    control enforced automatically and configured manually will be wrong."""
    _agent("scout")
    r = client.put("/agents/scout/ceiling",
                   json={"actions": ["files:read"], "audiences": ["tool:cal"]},
                   headers=_op())
    assert r.status_code == 200
    assert r.json()["actions"] == ["files:read"]
    assert client.get("/agents/scout/ceiling",
                      headers=_op()).json()["audiences"] == ["tool:cal"]
    # and it is in force at the mint, not merely stored
    assert registry.get_ceiling("scout")["actions"] == ["files:read"]


def test_setting_a_ceiling_on_a_missing_agent_is_a_404_not_a_silent_success(env):
    """Silence would leave the operator believing a limit is in force that no row
    carries."""
    assert client.put("/agents/ghost/ceiling", json={"actions": ["files:read"]},
                      headers=_op()).status_code == 404


def test_an_agent_cannot_raise_or_read_its_own_ceiling(env):
    """A ceiling its holder can raise is not a ceiling -- and reading one tells an
    agent exactly how far it can be pushed."""
    _agent("scout")
    registry.set_ceiling("scout", actions=["files:read"])
    hdr = _run("scout", "run-c", "alice", ["files:read"])
    assert client.put("/agents/scout/ceiling",
                      json={"actions": ["files:read", "files:write"]},
                      headers=hdr).status_code in (401, 403)
    assert client.get("/agents/scout/ceiling", headers=hdr).status_code in (401, 403)
    assert registry.get_ceiling("scout")["actions"] == ["files:read"]


# --- the wire format an off-the-shelf RFC 8693 client actually sends ----------

def _form(hdr: dict, **params) -> dict:
    return {**hdr, "Content-Type": "application/x-www-form-urlencoded"}, params


def test_the_mint_accepts_a_real_form_encoded_rfc_8693_request(env):
    """The endpoint used to require JSON with a custom `actor` field, so no
    standard client could talk to it -- the reason the mint sat unreachable. These
    are the exact parameters agentgateway 1.4.1 sends, captured off the wire."""
    _agent("scout")
    hdr = _run("scout", "run-f", "alice", ["files:read", "files:write"],
               pin={"account": "447"})
    tok = hdr["X-Andyur-Run-Token"]
    r = client.post(
        "/oauth/token",
        headers={**hdr, "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
              "subject_token": tok,
              "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
              "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
              "audience": "tool:ci"})
    assert r.status_code == 200, r.text
    claims = tokenexchange.verify_delegated(r.json()["access_token"],
                                            audience="tool:ci")
    assert claims["sub"] == "alice"
    # no `actor` parameter exists in RFC 8693, so the actor is the calling run --
    # which is also the only value that was ever safe to accept
    assert claims["act"]["sub"] == "scout"
    assert claims["authorization_details"][0]["resources"] == {"account": "447"}


def test_a_form_request_naming_the_target_as_resource_is_accepted(env):
    """RFC 8707 `resource` and RFC 8693 `audience` both name the target. A client
    may send either, and refusing one of them is a compatibility bug."""
    _agent("scout")
    hdr = _run("scout", "run-g", "alice", ["files:read"])
    r = client.post(
        "/oauth/token",
        headers={**hdr, "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
              "subject_token": hdr["X-Andyur-Run-Token"],
              "subject_token_type": ACCESS_TOKEN_TYPE,
              "resource": "tool:ci"})
    assert r.status_code == 200
    assert tokenexchange.verify_delegated(
        r.json()["access_token"], audience="tool:ci")["aud"] == "tool:ci"


def test_a_form_request_with_the_wrong_grant_is_refused_by_its_own_name(env):
    _agent("scout")
    hdr = _run("scout", "run-h", "alice", ["files:read"])
    r = client.post(
        "/oauth/token",
        headers={**hdr, "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "authorization_code",
              "subject_token": hdr["X-Andyur-Run-Token"]})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "unsupported_grant_type"


def test_a_form_request_must_name_a_target_and_carry_a_subject(env):
    _agent("scout")
    hdr = _run("scout", "run-i", "alice", ["files:read"])
    tok = hdr["X-Andyur-Run-Token"]
    h = {**hdr, "Content-Type": "application/x-www-form-urlencoded"}
    g = "urn:ietf:params:oauth:grant-type:token-exchange"

    no_aud = client.post("/oauth/token", headers=h,
                         data={"grant_type": g, "subject_token": tok,
                               "subject_token_type": ACCESS_TOKEN_TYPE})
    assert no_aud.status_code == 400
    assert no_aud.json()["detail"]["error"] == "invalid_target"

    no_sub = client.post("/oauth/token", headers=h,
                         data={"grant_type": g, "audience": "tool:ci"})
    assert no_sub.status_code == 400
    assert no_sub.json()["detail"]["error"] == "invalid_request"

    # RFC 8693 sec 2.1 marks subject_token_type REQUIRED. A request that omits
    # it is malformed, however well the rest of it reads.
    no_type = client.post("/oauth/token", headers=h,
                          data={"grant_type": g, "subject_token": tok,
                                "audience": "tool:ci"})
    assert no_type.status_code == 400
    assert no_type.json()["detail"]["error"] == "invalid_request"
    assert "subject_token_type" in no_type.json()["detail"]["error_description"]


def test_the_json_body_still_works_so_the_cli_is_not_broken(env):
    """Both forms carry the same information, and breaking our own CLI to gain
    standards conformance would be a poor trade."""
    _agent("scout")
    _agent("reviewer")
    hdr = _run("scout", "run-j", "alice", ["files:read"])
    r = client.post("/oauth/token",
                    json={"audience": "tool:cal", "actor": "reviewer"}, headers=hdr)
    assert r.status_code == 200
    assert tokenexchange.verify_delegated(
        r.json()["access_token"], audience="tool:cal")["act"]["sub"] == "reviewer"


def test_client_id_names_the_caller_not_the_delegatee(env):
    """RFC 9068 sec 2.2: client_id is the party that REQUESTED the token. Keying
    it on `actor` let a caller name a different registered agent as the client
    while holding and spending the token itself -- `actor` is a caller-supplied
    body field on the JSON path, gated only by an allow-list that permits
    everything when unconfigured. Anything downstream keying on client_id was
    being fed a value the caller picked."""
    _agent("scout")
    _agent("specialist")
    hdr = _run("scout", "run-cid", "alice", ["files:read"])
    r = client.post("/oauth/token", headers=hdr,
                    json={"audience": "tool:ci", "actor": "specialist"})
    assert r.status_code == 200, r.text
    claims = tokenexchange.verify_delegated(r.json()["access_token"],
                                            audience="tool:ci")
    assert claims["act"]["sub"] == "specialist", "the delegatee is still the actor"
    assert claims["client_id"] == "scout", (
        "client_id must name the caller that requested the token, not the "
        "delegatee it was minted for")


def test_every_issued_token_is_individually_identifiable(env):
    """jti exists so an audit trail can name ONE credential. Two mints must not
    share one, or it names a class instead."""
    _agent("scout")
    hdr = _run("scout", "run-jti", "alice", ["files:read"])
    seen = set()
    for _ in range(3):
        r = client.post("/oauth/token", headers=hdr, json={"audience": "tool:ci"})
        assert r.status_code == 200, r.text
        seen.add(tokenexchange.verify_delegated(
            r.json()["access_token"], audience="tool:ci")["jti"])
    assert len(seen) == 3, "tokens shared a jti"


@pytest.mark.parametrize("repeated", [
    "grant_type", "subject_token", "subject_token_type", "requested_token_type",
    "scope",
])
def test_a_repeated_form_parameter_is_refused(env, repeated):
    """RFC 6749 sec 3.1: a parameter MUST NOT appear more than once. `form.get`
    silently takes the last, which is the same defect the audience/resource check
    was written to close -- left in place on its neighbours until a mutation
    showed nothing tested them."""
    _agent("scout")
    hdr = _run("scout", f"run-dup-{repeated}", "alice", ["files:read"])
    from urllib.parse import urlencode

    # EVERY parameter under test is present in the base request, so adding one
    # really produces a duplicate. Without that, a parameter absent from the base
    # was "duplicated" into a single occurrence and the case passed for an
    # unrelated reason -- requested_token_type=x was refused as unsupported, not
    # as repeated.
    data = [("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", hdr["X-Andyur-Run-Token"]),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("requested_token_type", ACCESS_TOKEN_TYPE),
            ("scope", "files:read"),
            ("audience", "tool:ci")]
    form = {**hdr, "Content-Type": "application/x-www-form-urlencoded"}
    # A conformant request first, so this proves the DUPLICATE is what refuses.
    ok = client.post("/oauth/token", content=urlencode(data), headers=form)
    assert ok.status_code == 200, ok.text
    dup = dict(data)[repeated]
    r = client.post("/oauth/token", content=urlencode(data + [(repeated, dup)]),
                    headers=form)
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"] == "invalid_request"
    assert repeated in r.json()["detail"]["error_description"]


def test_the_endpoint_applies_the_CALLERS_ceiling_not_only_the_delegatees(env):
    """The escalation that made `actor` indefensible, driven through the HTTP
    endpoint rather than through `mint()` directly.

    A read-only caller nominates a write-capable delegatee. The token comes back
    to the CALLER, so if only the delegatee's ceiling applied, the caller would
    walk away holding files:write it was never entitled to. `mint()` applies both
    ceilings, but every existing test proved that by calling `mint()` with a
    caller it was handed -- none proved the ENDPOINT hands it one. Replacing
    `caller=caller` with `caller=None` at the call site disables the whole
    caller-ceiling block and, when a review measured it, went unnoticed by all
    808 tests.
    """
    _agent("readonly", actions=["files:read"])
    _agent("writer")                       # unset ceiling = unrestricted
    hdr = _run("readonly", "run-caller-ceiling", "alice",
               ["files:read", "files:write"])
    r = client.post("/oauth/token", headers=hdr,
                    json={"audience": "tool:ci", "actor": "writer"})
    assert r.status_code == 200, r.text
    scope = _scope_of(r.json()["access_token"], "tool:ci")
    assert "files:write" not in scope, (
        "a read-only caller came away holding a delegatee's wider authority")
    assert scope == ["files:read"]


# --- the response body is a contract, and agentgateway reads it ---------------

def test_the_response_names_the_token_type_the_client_asked_for(env):
    """The field whose wrong value made agentgateway refuse every call. It was
    `:jwt` for an RFC 9068 at+jwt, and nothing in the repo asserted it, so the
    regression that cost an afternoon was unguarded afterwards."""
    _agent("scout")
    hdr = _run("scout", "run-itt", "alice", ["files:read"])
    r = client.post("/oauth/token", headers=hdr, json={"audience": "tool:ci"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["issued_token_type"] == ACCESS_TOKEN_TYPE
    assert body["token_type"] == "Bearer"


def test_expires_in_describes_the_token_that_was_actually_issued(env):
    """A credential broker caches on this value, so over-reporting it becomes a
    caller reusing a dead token. It must come from the issued claims, not from a
    second read of config."""
    _agent("scout")
    hdr = _run("scout", "run-exp", "alice", ["files:read"])
    r = client.post("/oauth/token", headers=hdr, json={"audience": "tool:ci"})
    assert r.status_code == 200, r.text
    claims = tokenexchange.verify_delegated(r.json()["access_token"],
                                            audience="tool:ci")
    assert r.json()["expires_in"] == claims["exp"] - claims["iat"]
    assert 0 < r.json()["expires_in"] <= 3600


def test_the_token_says_who_issued_it_and_is_an_rfc_9068_access_token(env):
    """`iss` could be replaced with an attacker's host and nothing noticed --
    partly because verify_delegated never passes issuer= to jwt.decode."""
    import jwt as _jwt

    _agent("scout")
    hdr = _run("scout", "run-iss", "alice", ["files:read"])
    r = client.post("/oauth/token", headers=hdr, json={"audience": "tool:ci"})
    token = r.json()["access_token"]
    assert _jwt.get_unverified_header(token)["typ"] == "at+jwt"
    claims = tokenexchange.verify_delegated(token, audience="tool:ci")
    assert claims["iss"] == config.EXCHANGE_ISSUER


@pytest.mark.parametrize("bad_type", [
    "urn:ietf:params:oauth:token-type:jwt",
    "urn:ietf:params:oauth:token-type:id_token",
    "urn:ietf:params:oauth:token-type:saml2",
])
def test_a_subject_token_type_we_cannot_honour_is_refused(env, bad_type):
    """Only the ABSENT case was tested. A client saying it presented a SAML
    assertion has a different intent from one presenting an access token, and
    treating them alike tells it that it got semantics it did not get."""
    from urllib.parse import urlencode

    _agent("scout")
    hdr = _run("scout", f"run-stt-{bad_type[-6:]}", "alice", ["files:read"])
    form = {**hdr, "Content-Type": "application/x-www-form-urlencoded"}
    r = client.post("/oauth/token", headers=form, content=urlencode([
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", hdr["X-Andyur-Run-Token"]),
        ("subject_token_type", bad_type),
        ("audience", "tool:ci")]))
    assert r.status_code == 400, r.text
    assert "subject_token_type" in r.json()["detail"]["error_description"]


def test_a_requested_token_type_we_cannot_issue_is_refused(env):
    from urllib.parse import urlencode

    _agent("scout")
    hdr = _run("scout", "run-rtt", "alice", ["files:read"])
    form = {**hdr, "Content-Type": "application/x-www-form-urlencoded"}
    r = client.post("/oauth/token", headers=form, content=urlencode([
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", hdr["X-Andyur-Run-Token"]),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("requested_token_type", "urn:ietf:params:oauth:token-type:id_token"),
        ("audience", "tool:ci")]))
    assert r.status_code == 400, r.text
    assert "requested_token_type" in r.json()["detail"]["error_description"]


def test_naming_more_than_one_target_is_refused(env):
    """A token names exactly ONE target -- that is the audience term in the
    authority intersection. Taking the first of several silently hands back a
    token for a target the client did not think it asked for."""
    from urllib.parse import urlencode

    _agent("scout")
    hdr = _run("scout", "run-multi", "alice", ["files:read"])
    form = {**hdr, "Content-Type": "application/x-www-form-urlencoded"}
    base = [("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", hdr["X-Andyur-Run-Token"]),
            ("subject_token_type", ACCESS_TOKEN_TYPE)]
    for pair in (["tool:ci", "tool:bank"], None):
        if pair:
            body = base + [("audience", pair[0]), ("audience", pair[1])]
        else:
            body = base + [("audience", "tool:ci"), ("resource", "tool:bank")]
        r = client.post("/oauth/token", headers=form, content=urlencode(body))
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "invalid_target"


def test_a_form_request_missing_only_the_subject_token_is_refused_for_that(env):
    """The existing case omitted subject_token_type too, so the type check
    answered first and the subject_token check was never reached."""
    from urllib.parse import urlencode

    _agent("scout")
    hdr = _run("scout", "run-nosub", "alice", ["files:read"])
    form = {**hdr, "Content-Type": "application/x-www-form-urlencoded"}
    r = client.post("/oauth/token", headers=form, content=urlencode([
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("audience", "tool:ci")]))
    assert r.status_code == 400, r.text
    assert "subject_token" in r.json()["detail"]["error_description"]


@pytest.mark.parametrize("evil", [
    "tool:ci\nmint ISSUED: jti=FORGED caller=operator audience=tool:payments",
    "tool:ci\r\nmint ISSUED: jti=FORGED",
    "tool:ci\tmint ISSUED: jti=FORGED",
    "tool:" + "x" * 400,
])
def test_an_audience_cannot_forge_an_audit_record(env, evil):
    """The audit record must not be writable by the audited party.

    `mint ISSUED` interpolates the caller-supplied audience. A newline in it
    produced a second, syntactically perfect issuance line for a target the
    caller was never granted, attributed to whoever it named -- demonstrated
    against the running app. A record an agent can fabricate is worse than no
    record, because it is trusted."""
    _agent("scout")
    hdr = _run("scout", f"run-log-{abs(hash(evil)) % 9999}", "alice", ["files:read"])
    r = client.post("/oauth/token", headers=hdr, json={"audience": evil})
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"] in ("invalid_request", "invalid_target")


def test_the_issuance_record_quotes_what_the_caller_supplied(env, caplog):
    """Defence in depth behind the validation: %r, so even a value that got past
    a future check cannot span lines in the log."""
    import logging

    _agent("scout")
    hdr = _run("scout", "run-logfmt", "alice", ["files:read"])
    with caplog.at_level(logging.INFO, logger="andyur.server.tokenexchange"):
        r = client.post("/oauth/token", headers=hdr, json={"audience": "tool:ci"})
    assert r.status_code == 200, r.text
    issued = [rec for rec in caplog.records if "mint ISSUED" in rec.getMessage()]
    assert issued, "no issuance record was emitted"
    message = issued[0].getMessage()
    assert "'tool:ci'" in message, message
    assert len(message.splitlines()) == 1


def test_a_form_request_cannot_choose_its_own_delegatee(env):
    """RFC 8693 has NO `actor` parameter, and the one Andyur had was deleted
    because it needed the ceiling applied twice to stop an agent naming a more
    capable delegatee. The form path must therefore IGNORE an `actor` field
    rather than honour it -- and nothing tested that, so restoring
    `actor=form.get("actor")` was invisible.
    """
    from urllib.parse import urlencode

    _agent("scout")
    _agent("privileged")
    hdr = _run("scout", "run-noactor", "alice", ["files:read"])
    form = {**hdr, "Content-Type": "application/x-www-form-urlencoded"}
    r = client.post("/oauth/token", headers=form, content=urlencode([
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", hdr["X-Andyur-Run-Token"]),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("actor", "privileged"),
        ("audience", "tool:ci")]))
    assert r.status_code == 200, r.text
    claims = tokenexchange.verify_delegated(r.json()["access_token"],
                                            audience="tool:ci")
    assert claims["act"]["sub"] == "scout", (
        "the form's `actor` chose the delegatee; it must be the run, always")


def test_a_restored_internal_files_read_never_reaches_a_tool_token(env):
    """The load-bearing property of the own-context-read restore (da36c7b): the
    coordinator puts files:read into the RUN scope so a run can load its own
    prompt, but a TOOL token must never carry it. The mint re-derives tool
    authority through authority_for, which reads the ceiling FROM THE REGISTRY
    ROW and intersects it with the request -- the tool ceiling here lacks
    files:read, so it is stripped even though the run scope and the request both
    carry it. A future change that trusted the run scope instead of re-narrowing
    at the mint would redden this."""
    _agent("oncall", actions=["obs:read"], audiences=["resource:telemetry"])
    tok = tokenexchange.exchange(
        "oncall", "resource:telemetry", ctx_sub="alice",
        ctx_scope=["files:read", "obs:read"],        # the RUN scope, with restored files:read
        requested_scope=["files:read", "obs:read"])
    scope = _scope_of(tok, "resource:telemetry")
    assert "files:read" not in scope                 # the internal read did NOT leak
    assert scope == ["obs:read"]                     # only the ceiling-granted tool action
