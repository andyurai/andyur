"""THE PIN (subject_context): what a run's work is ABOUT, sealed server-side.

`acting_user` says who a run acts FOR and `scope` says what it may DO. Neither
says what it may do it TO. A run entitled to write invoices for Alice is, without
a third term, entitled to write invoices for every account Alice can reach -- and
the only thing keeping it on account 447 is a sentence in its prompt, which is
text, and text is the one thing a compromised or merely persuadable model is
allowed to rewrite.

The pin is that sentence turned into a claim: asserted by an AUTHENTICATED
CALLER, sealed onto the run at creation, carried in the signed grant, and
inherited unchanged across delegation. These tests hold the boundary at each of
those points, and in particular the one that matters most: a compromised agent
handing work to another agent must not be able to retarget it at a different
account.
"""

import json

import pytest
import conftest
from pydantic import BaseModel
from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module, auth, coordinator, oidc, runtoken

client = TestClient(app_module.app)

PIN = {"account": "447"}
OTHER_PIN = {"account": "999"}


# --- helpers -----------------------------------------------------------------

def _run_row(run_id: str):
    with db.connect() as c:
        return c.execute(
            "SELECT agent, state, subject_context, pin_asserted_by FROM runs "
            "WHERE id = ?", (run_id,)
        ).fetchone()


def _latest_run(agent: str):
    """The most recently created run for `agent` (the one a delegation woke)."""
    with db.connect() as c:
        return c.execute(
            "SELECT id, subject_context, pin_asserted_by FROM runs WHERE agent = ? "
            "ORDER BY created_at DESC, id DESC LIMIT 1", (agent,)
        ).fetchone()


def _other_run(agent: str, exclude_id: str):
    """The run for `agent` that is NOT `exclude_id`.

    Deliberately not "the latest": created_at has one-second granularity, so two
    runs made in the same test share a timestamp and any ORDER BY tie-break lands
    on a random hex id. Excluding the run we already know about is the only
    deterministic way to name the one the drain created."""
    with db.connect() as c:
        return c.execute(
            "SELECT id, subject_context, pin_asserted_by FROM runs "
            "WHERE agent = ? AND id != ?", (agent, exclude_id)
        ).fetchone()


def _seed_run(env, agent: str, run_id: str, pin: dict | None,
              asserted_by: str | None = "user:alice", scope=None):
    """An already-running, already-pinned parent run, plus the header its runner
    would present. Written directly because the point under test is what the
    DELEGATION does with a pinned parent, not how the parent got pinned."""
    env.agent(agent)
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at, workflow_id, "
            "subject_context, pin_asserted_by, scope) "
            "VALUES (?, ?, 'running', ?, 'wf-parent', ?, ?, ?)",
            (run_id, agent, db.utcnow(),
             json.dumps(pin, sort_keys=True, separators=(",", ":")) if pin else None,
             asserted_by if pin else None,
             json.dumps(scope) if scope else None),
        )
    return {"X-Andyur-Run-Token": runtoken.mint(
        agent, run_id, "wf-parent", scope=scope, pin=pin)}


@pytest.fixture
def user_auth(monkeypatch):
    """User-auth on with a stubbed IdP (the OIDC decode itself is covered in
    test_user_delegation)."""
    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(oidc, "validate_user_claims",
                        lambda t: {"sub": "alice"} if t == "good" else _bad())


def _bad():
    raise oidc.InvalidUserToken("bad")


# --- the pin is sealed on the run, and rides in the grant ---------------------

def test_the_pin_is_sealed_on_the_run_and_appears_in_the_grant(env):
    env.agent("pinned")
    r = client.post("/agents/pinned/trigger",
                    json={"reason": "invoice run", "subject_context": PIN})
    assert r.status_code == 201
    run_id = r.json()["run_id"]

    # sealed on the run, canonicalised to one byte representation
    assert _run_row(run_id)["subject_context"] == '{"account":"447"}'

    # and carried in the SIGNED grant, so nothing downstream has to trust a
    # prompt, a header, or the agent's own account of what it is working on
    tok = client.post(f"/runs/{run_id}/token").json()["run_token"]
    assert runtoken.verify(tok)["pin"] == PIN


def test_the_grant_minted_at_assignment_carries_the_pin(env):
    """The daemon's path, not the CLI's: a worker heartbeat is where a real run's
    token is minted, so that is where the pin has to survive."""
    env.agent("pinned2")
    run_id = client.post("/agents/pinned2/trigger",
                         json={"subject_context": PIN}).json()["run_id"]
    beat = client.post("/worker/heartbeat",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w1", "slots": 2, "slots_free": 2,
                             "running": [], "profile": "dev"})
    assert beat.status_code == 200
    mine = [a for a in beat.json()["assignments"] if a["id"] == run_id]
    assert len(mine) == 1, "the run under test was not assigned; nothing was proved"
    assert runtoken.verify(mine[0]["run_token"])["pin"] == PIN


def test_the_pin_reaches_runctx_from_the_signed_grant(env):
    """Authorization reads the pin off RunCtx. It gets there from the signature,
    which is why a tampered payload is refused rather than believed."""
    env.agent("pinctx")
    run_id = client.post("/agents/pinctx/trigger",
                         json={"subject_context": PIN}).json()["run_id"]
    tok = runtoken.mint("pinctx", run_id, "wf", pin=PIN)
    ctx = auth.require_run().dependency(authorization=None, x_andyur_run_token=tok)
    assert ctx.pin == PIN

    # rewrite the pin in the payload without re-signing: 401, not account 999
    import base64
    payload_b64, sig = tok.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(
        payload_b64 + "=" * (-len(payload_b64) % 4)))
    payload["pn"] = OTHER_PIN
    forged = base64.urlsafe_b64encode(
        json.dumps(payload).encode()).rstrip(b"=").decode() + "." + sig
    with pytest.raises(Exception) as exc:
        auth.require_run().dependency(authorization=None, x_andyur_run_token=forged)
    assert getattr(exc.value, "status_code", None) == 401


# --- delegation: the pin is inherited, never chosen ---------------------------

def test_a_delegated_run_inherits_the_parents_pin_unchanged(env):
    env.agent("child")
    hdr = _seed_run(env, "boss", "run-boss", PIN, scope=["tasks:write"])
    r = client.post("/tasks", json={"assignee": "child", "title": "do it"}, headers=hdr)
    assert r.status_code == 201
    woken = _latest_run("child")
    assert woken is not None, "no run was woken for the assignee; nothing was proved"
    assert woken["subject_context"] == '{"account":"447"}'
    # and the ASSERTER travels with it: the child's pin is still attributed to
    # the human who chose it, not to the agent that passed it along
    assert woken["pin_asserted_by"] == "user:alice"


def test_a_run_woken_by_a_message_inherits_the_senders_pin(env):
    """The other delegation channel. A waking message is a second way to hand an
    agent work, and a boundary that holds on only one of the two is not a
    boundary."""
    env.agent("listener")
    hdr = _seed_run(env, "talker", "run-talker", PIN, scope=["messages:write"])
    r = client.post("/messages", json={"recipient": "listener", "body": "look at it"},
                    headers=hdr)
    assert r.status_code == 201
    woken = _latest_run("listener")
    assert woken is not None, "no run was woken for the recipient; nothing was proved"
    assert woken["subject_context"] == '{"account":"447"}'


def test_a_pin_in_a_delegation_body_is_refused_at_the_door_and_at_the_seam(env):
    """Two halves, because one alone would be dishonest.

    The task API has no `subject_context` field, and every request body on this
    server now REFUSES what it does not recognise rather than dropping it. So a
    delegator trying to retarget its child's pin through the body is turned away
    at request parsing with a 422 -- and, unlike the silent drop this used to
    assert, the caller is told. An attempt to widen authority that returns 201 is
    indistinguishable from one that worked.

    That half still cannot fail for the reason the name suggests: it would pass
    with the retarget refusal deleted, because the attack never reaches the
    refusal. So the second half calls the SEAM directly with the argument that
    field would become. That is the check that actually holds the line, and it is
    where the guarantee has to live, in the absence of a request field that any
    future endpoint could add back."""
    env.agent("child2")
    hdr = _seed_run(env, "boss2", "run-boss2", PIN, scope=["tasks:write"])
    r = client.post("/tasks",
                    json={"assignee": "child2", "title": "pay it",
                          "subject_context": OTHER_PIN},
                    headers=hdr)
    assert r.status_code == 422, (
        f"a body carrying an unknown authority field returned {r.status_code}; "
        "it must be refused, not quietly ignored")
    assert _latest_run("child2") is None, "the refused request still woke a run"

    # The positive control: the SAME request without the retarget succeeds. A 422
    # proves nothing if this endpoint refuses everything.
    ok = client.post("/tasks", json={"assignee": "child2", "title": "pay it"},
                     headers=hdr)
    assert ok.status_code == 201, ok.text
    woken = _latest_run("child2")
    assert woken is not None, "no run was woken for the assignee; nothing was proved"
    assert woken["subject_context"] == '{"account":"447"}', "the child lost its inherited pin"

    # the half that exercises the refusal itself
    with db.connect() as c:
        with pytest.raises(coordinator.PinRefused):
            coordinator.resolve_pin(c, "run-boss2", subject_context=OTHER_PIN)


def test_changing_an_inherited_pin_is_refused_at_the_seam(env):
    """The API above has no field for this today, so the guarantee is enforced
    where runs are actually created -- a future endpoint that grows one must not
    silently become a retargeting channel."""
    env.agent("child3")
    _seed_run(env, "boss3", "run-boss3", PIN)
    with pytest.raises(coordinator.PinRefused):
        coordinator.maybe_wakeup("child3", "delegated", parent_run_id="run-boss3",
                                 subject_context=OTHER_PIN)
    # Prove that was a REFUSAL and not a busy/idle accident: the same wakeup
    # without the retarget succeeds, and is pinned to the parent's account.
    run_id = coordinator.maybe_wakeup("child3", "delegated", parent_run_id="run-boss3")
    assert run_id is not None
    assert _run_row(run_id)["subject_context"] == '{"account":"447"}'


def test_an_unpinned_parent_cannot_have_a_pin_added_by_its_delegator(env):
    """The same attack wearing the other hat: acquiring a target the parent never
    had is exactly as bad as swapping one."""
    env.agent("child4")
    _seed_run(env, "boss4", "run-boss4", None)
    with pytest.raises(coordinator.PinRefused):
        coordinator.maybe_wakeup("child4", "delegated", parent_run_id="run-boss4",
                                 subject_context=PIN)
    run_id = coordinator.maybe_wakeup("child4", "delegated", parent_run_id="run-boss4")
    assert run_id is not None and _run_row(run_id)["subject_context"] is None


def test_an_unattributable_pin_is_refused(env):
    """A pin nobody is on the hook for is worse than no pin: it reads as a
    constraint while the audit answer to "who chose this target" is "something
    did". The ROOT case therefore refuses a pin with no asserter.

    This replaced a test that asserted the trigger endpoint rejects a run token.
    That rejection is real and the pin slice relies on it, but it is PRE-EXISTING
    auth behaviour -- the test passed with the entire pin feature deleted, which
    makes it coverage of somebody else's guard."""
    with db.connect() as c:
        with pytest.raises(coordinator.PinRefused):
            coordinator.resolve_pin(c, None, subject_context=PIN, asserted_by=None)
        # ...and the same pin WITH an asserter is accepted, so the refusal is
        # about attribution rather than about pins being rejected generally
        pin, by = coordinator.resolve_pin(c, None, subject_context=PIN,
                                          asserted_by="user:alice")
        assert pin == '{"account":"447"}' and by == "user:alice"


# --- who asserted it -----------------------------------------------------------

def test_pin_asserted_by_records_the_authenticated_user(env, user_auth):
    client.post("/agents", json={"name": "pinowned"},
                headers={"X-Andyur-User-Token": "good"})
    run_id = client.post("/agents/pinowned/trigger",
                         json={"subject_context": PIN},
                         headers={"X-Andyur-User-Token": "good"}).json()["run_id"]
    row = _run_row(run_id)
    assert row["pin_asserted_by"] == "user:alice"


def test_pin_asserted_by_records_the_caller_when_there_is_no_user(env):
    """User-auth off: the assertion is the application's, which is acceptable --
    but it must still be ATTRIBUTABLE, and it must never name the agent."""
    env.agent("pincaller")
    run_id = client.post("/agents/pincaller/trigger",
                         json={"subject_context": PIN}).json()["run_id"]
    asserter = _run_row(run_id)["pin_asserted_by"]
    assert asserter.startswith("caller:")
    assert "pincaller" not in asserter


# --- refusals and backwards compatibility --------------------------------------

def test_an_empty_pin_is_refused_rather_than_stored(env):
    """`{}` would persist as a pin that constrains nothing while the caller
    believes the run is pinned. Unpinned is honest; empty is a lie."""
    env.agent("pinempty")
    r = client.post("/agents/pinempty/trigger", json={"subject_context": {}})
    assert r.status_code == 422
    assert _latest_run("pinempty") is None, "a run was created for a refused pin"


def test_a_run_with_no_pin_still_works(env):
    """Backwards compatibility: no pin is today's behaviour, everywhere -- on the
    row, in the grant, and on RunCtx. Absence must read as UNPINNED, never as
    'pinned to nothing'."""
    env.agent("unpinned")
    r = client.post("/agents/unpinned/trigger", json={"reason": "as before"})
    assert r.status_code == 201
    run_id = r.json()["run_id"]
    row = _run_row(run_id)
    assert row["state"] == "pending"          # the run really was created
    assert row["subject_context"] is None
    assert row["pin_asserted_by"] is None
    tok = client.post(f"/runs/{run_id}/token").json()["run_token"]
    assert runtoken.verify(tok)["pin"] is None
    ctx = auth.require_run().dependency(authorization=None, x_andyur_run_token=tok)
    assert ctx.pin is None and ctx.agent == "unpinned"


# --- the deferred-delegation path: the bypass an adversarial review found -----

def _busy(env, agent_name):
    """Give an agent a live run, so a delegation to it is REFUSED and the work
    is deferred to the drain. This is the state a delegating agent can create on
    demand, which is what made the gap below reachable rather than incidental."""
    env.agent(agent_name)
    return coordinator.maybe_wakeup(agent_name, "keep it busy")


def test_work_deferred_to_the_drain_still_carries_the_pin(env):
    """THE BYPASS. Delegation wakes its target best-effort, so handing work to a
    BUSY agent is refused and re-driven later by heartbeat.drain_pending_work --
    which has no parent run to inherit from and therefore minted an UNPINNED run.
    The work then executed with its target stripped off.

    It was not incidental: the delegating agent chooses the assignee, so it can
    force the deferred path simply by picking one that is already busy. The pin
    now travels on the task row, which is the only thing that survives the
    deferral."""
    from andyur.server import heartbeat

    live = _busy(env, "child")
    assert live is not None, "the assignee is not actually busy; the test proves nothing"

    hdr = _seed_run(env, "boss", "run-boss", PIN, scope=["tasks:write"])
    r = client.post("/tasks", json={"assignee": "child", "title": "do it"}, headers=hdr)
    assert r.status_code == 201

    # the immediate wakeup was refused, exactly as the deferral requires
    with db.connect() as c:
        pending = c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = 'child' AND id != ?",
            (live,)).fetchone()["n"]
    assert pending == 0, "the assignee was woken directly; the drain path was not exercised"

    # the work item itself carries the pin, so the deferral cannot lose it
    with db.connect() as c:
        row = c.execute("SELECT subject_context FROM tasks WHERE assignee = 'child'").fetchone()
    assert row["subject_context"] == '{"account":"447"}'

    # free the agent, then let the drain re-drive the work
    coordinator.finish_run(live, "done", None)
    drained = heartbeat.drain_pending_work()
    assert drained, "the drain did not re-drive the waiting work; nothing was proved"

    # Identify the drained run by EXCLUDING the busy one, never by "most recent".
    # created_at has one-second granularity, so both runs share a timestamp and
    # an ordering tie-break falls through to a random hex id -- the same trap
    # that made an earlier drain fix unreliable in this repo.
    woken = _other_run("child", live)
    assert woken is not None, "the drain woke no new run; nothing was proved"
    assert woken["subject_context"] == '{"account":"447"}', (
        "the drained run is UNPINNED: work delegated to a busy agent executed "
        "with its target stripped off")


def test_the_drain_refuses_to_merge_work_pinned_to_different_targets(env):
    """No single run can be correct for two targets. Picking one would silently
    execute the other's work under the wrong pin, so the drain declines and
    leaves the work open and un-stamped rather than guessing."""
    from andyur.server import heartbeat

    live = _busy(env, "child")
    for pin, boss in ((PIN, "boss1"), (OTHER_PIN, "boss2")):
        hdr = _seed_run(env, boss, f"run-{boss}", pin, scope=["tasks:write"])
        assert client.post("/tasks", json={"assignee": "child", "title": "x"},
                           headers=hdr).status_code == 201

    coordinator.finish_run(live, "done", None)
    actions = heartbeat.drain_pending_work()
    assert any("different" in a for a in actions), actions
    assert _other_run("child", live) is None, (
        "a run was woken for work pinned to two different accounts")


def test_no_request_body_on_this_api_silently_drops_a_field(env):
    """The CLASS, not the instance.

    This bug was found twice and fixed twice, locally, on the two bodies where it
    happened to be noticed -- and survived on the other fifteen for exactly as
    long. A test for one body would repeat that. This one fails the moment
    ANYONE adds a request model that inherits the permissive default, including
    a model that does not exist yet.

    What it costs to get wrong: a caller that typos `subject_ctx` gets HTTP 200
    and an UNPINNED run; one that typos `scopes` gets a run this platform reads
    as UNRESTRICTED. Both believe they narrowed the run. Both widened it.
    """
    from andyur.server import app as server_app

    permissive = [
        cls.__name__
        for cls in vars(server_app).values()
        if isinstance(cls, type) and issubclass(cls, BaseModel)
        and cls not in (BaseModel, server_app.Body)
        and cls.model_config.get("extra") != "forbid"
    ]
    assert not permissive, (
        "these request bodies silently ignore unknown fields, so a typo in an "
        f"authority field returns 200 and a wider run: {permissive}. "
        "Inherit from app.Body.")


def test_the_trigger_refuses_a_mistyped_pin_rather_than_running_unpinned(env):
    """The concrete failure the class test abstracts, kept because a reader
    should not have to derive the consequence from a metaprogramming assertion."""
    env.agent("typo1")
    bad = client.post("/agents/typo1/trigger",
                      json={"reason": "x", "subject_ctx": {"account": "447"}})
    assert bad.status_code == 422, (
        f"a mistyped pin returned {bad.status_code}; the run would carry no pin "
        "and the caller would never know")

    # Positive control: spelled correctly, the same request is accepted AND pinned.
    good = client.post("/agents/typo1/trigger",
                       json={"reason": "x", "subject_context": {"account": "447"}})
    assert good.status_code == 201, good.text
    assert json.loads(_latest_run("typo1")["subject_context"]) == {"account": "447"}
