"""U2: scoped least privilege.

A run is granted only the scope its task declares (intersected with the user's
entitlements), sealed in the signed grant. Even when authenticated as the entitled
user, a run cannot exceed that scope -- the prompt-injection containment. Covers the
grant math, the require_scope check, and the live enforcement through the app.
"""

import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module, auth, coordinator, runtoken

client = TestClient(app_module.app)


def _run_with_scope(env, agent, run_id, scope):
    """An active run for `agent` granted `scope`; returns its run-token header."""
    env.agent(agent)
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at, scope) VALUES (?, ?, 'running', ?, ?)",
            (run_id, agent, db.utcnow(), json.dumps(scope) if scope is not None else None),
        )
    return {"X-Andyur-Run-Token": runtoken.mint(agent, run_id, "wf", scope=scope)}


# -- the grant math: intersection(entitlements, requested) ---------------------

def test_grant_is_intersection_of_entitlements_and_request(monkeypatch):
    from andyur.server.app import _grant_scope
    monkeypatch.setattr(config, "USER_ENTITLEMENTS", "files:read tasks:write")
    assert set(_grant_scope(["files:read", "files:write"])) == {"files:read"}  # write not entitled
    monkeypatch.setattr(config, "USER_ENTITLEMENTS", "*")
    assert _grant_scope(["files:read"]) == ["files:read"]     # entitled to all -> exactly requested
    assert _grant_scope(None) is None                          # no request -> unrestricted


# -- the require_scope check ---------------------------------------------------

def test_require_scope_allow_and_deny():
    def ctx(**kw):
        return auth.RunCtx("a", "r", "w", is_operator=False, **kw)
    auth.require_scope(auth.RunCtx("a", "r", "w", is_operator=True), "files:write")  # operator
    auth.require_scope(ctx(scope=None), "files:write")            # no scope model
    auth.require_scope(ctx(scope=["*"]), "files:write")           # granted all
    auth.require_scope(ctx(scope=["files:read"]), "files:read")   # in scope
    with pytest.raises(HTTPException) as e:
        auth.require_scope(ctx(scope=["files:read"]), "files:write")
    assert e.value.status_code == 403 and "insufficient_scope" in e.value.detail


# -- the signed grant carries scope, unforgeably -------------------------------

def test_scope_travels_in_the_signed_grant():
    tok = runtoken.mint("scout", "r1", "wf", scope=["files:read"])
    assert runtoken.verify(tok)["scope"] == ["files:read"]


def test_grant_reaches_runctx(env):
    hdr = _run_with_scope(env, "sv", "run-v", ["files:read"])
    assert client.get("/identity/verify-run", headers=hdr).json()["scope"] == ["files:read"]


# -- the containment: a read-only run cannot write, even as the entitled user --

def test_a_read_only_run_is_refused_a_write(env):
    hdr = _run_with_scope(env, "sr", "run-r", ["files:read"])
    # read is allowed by scope (404 = no such file yet, but NOT a scope refusal)
    assert client.get("/agents/sr/files/memory/notes.md", headers=hdr).status_code != 403
    w = client.put("/agents/sr/files/memory/notes.md", json={"content": "x"}, headers=hdr)
    assert w.status_code == 403 and "insufficient_scope" in w.json()["detail"]


def test_a_read_only_run_cannot_create_tasks_or_send_messages(env):
    hdr = _run_with_scope(env, "sr2", "run-r2", ["files:read"])
    env.agent("peer")
    t = client.post("/tasks", json={"assignee": "peer", "title": "x"}, headers=hdr)
    assert t.status_code == 403
    m = client.post("/messages", json={"recipient": "peer", "body": "x"}, headers=hdr)
    assert m.status_code == 403


def test_a_write_scoped_run_can_write(env):
    hdr = _run_with_scope(env, "sw", "run-w", ["files:write"])
    assert client.put("/agents/sw/files/memory/notes.md", json={"content": "x"}, headers=hdr).status_code == 200


def test_no_scope_is_unrestricted_backward_compatible(env):
    hdr = _run_with_scope(env, "su", "run-u", None)
    assert client.put("/agents/su/files/memory/notes.md", json={"content": "x"}, headers=hdr).status_code == 200


def test_star_scope_is_unrestricted(env):
    hdr = _run_with_scope(env, "sa", "run-a", ["*"])
    assert client.put("/agents/sa/files/memory/notes.md", json={"content": "x"}, headers=hdr).status_code == 200


def test_unknown_subject_type_is_denied():
    """Default deny: a subject the PDP does not recognise is granted nothing.

    Pins the fall-through in pdp._builtin, which a mutation run found untested.
    It matters beyond the unreachable case: an external PDP returns no result at
    all for an undefined policy, and that absence must read as a denial rather
    than as an error or a permit."""
    from andyur.server import pdp
    assert pdp.evaluate(pdp.Subject(type="mystery"), "files:read") is False


# --- claims that were not true ----------------------------------------------

def test_a_run_is_born_with_its_scope(env):
    """The grant used to be a post-INSERT UPDATE. A worker heartbeat landing in
    that window assigns the run and mints its token from the columns as they
    stand -- scope NULL -- and the PDP reads a null scope as UNRESTRICTED. So the
    endpoint whose whole purpose is narrowing a run's authority could hand out a
    token with none of the narrowing applied, under ordinary concurrency."""
    import json as _json
    from andyur import db
    env.agent("sc")
    r = client.post("/agents/sc/trigger", json={"scope": ["files:read"]})
    assert r.status_code == 201
    run_id = r.json()["run_id"]
    with db.connect() as c:
        row = c.execute("SELECT scope FROM runs WHERE id = ?", (run_id,)).fetchone()
    assert row["scope"] is not None, "the run existed before its scope did"
    assert _json.loads(row["scope"]) == ["files:read"]


def test_a_run_is_born_inside_its_governed_agent_ceiling(env):
    """The production external AS receives the scope sealed on the run, so the
    ceiling must be applied before the run exists, not only by the dev mint. The
    stripped action here is a DELEGATED tool action (obs:read): own-storage
    (files:read/write) is internal and restored regardless, so it cannot show
    that the ceiling was applied -- a delegated action the ceiling lacks can."""
    import json as _json
    from andyur import db
    env.agent("bounded")
    with db.connect() as c:
        c.execute("UPDATE agents SET ceiling_actions = ? WHERE name = ?",
                  (_json.dumps(["files:read"]), "bounded"))
    run_id = coordinator.maybe_wakeup(
        "bounded", "x", scope=["files:read", "obs:read"])
    with db.connect() as c:
        row = c.execute("SELECT scope FROM runs WHERE id = ?", (run_id,)).fetchone()
    # obs:read (delegated, not in the ceiling) is stripped at birth; files:read
    # (internal own-storage) survives -- proving the ceiling ran, not that it didn't.
    assert _json.loads(row["scope"]) == ["files:read"]


def test_a_run_carries_its_governed_audience_ceiling(env):
    import json as _json
    from andyur import db
    env.agent("aud-bounded")
    with db.connect() as c:
        c.execute("UPDATE agents SET ceiling_audiences = ? WHERE name = ?",
                  (_json.dumps(["resource:allowed"]), "aud-bounded"))
    run_id = coordinator.maybe_wakeup("aud-bounded", "x")
    with db.connect() as c:
        row = c.execute(
            "SELECT ceiling_audiences FROM runs WHERE id = ?", (run_id,)
        ).fetchone()
    assert _json.loads(row["ceiling_audiences"]) == ["resource:allowed"]


def test_reading_the_whole_mind_needs_the_same_scope_as_reading_a_file(env):
    """GET /agents/{name}/context returns knowledge, instructions and both
    memories in one call. It required no files:read while the narrower per-file
    endpoint did, so U2's read scope was bypassable through the endpoint every
    run already uses."""
    # via the API, so the agent's mind files exist for load_context to read
    assert client.post("/agents", json={"name": "sr2", "description": "x"}).status_code == 201
    run = coordinator.maybe_wakeup("sr2", "x", scope=["tasks:write"])
    hdr = {"X-Andyur-Run-Token": runtoken.mint("sr2", run, None, scope=["tasks:write"])}
    assert client.get("/agents/sr2/context", headers=hdr).status_code == 403
    coordinator.finish_run(run, "done", None)       # an agent has one live run
    run2 = coordinator.maybe_wakeup("sr2", "y")     # unrestricted
    hdr2 = {"X-Andyur-Run-Token": runtoken.mint("sr2", run2, None)}
    assert client.get("/agents/sr2/context", headers=hdr2).status_code == 200
