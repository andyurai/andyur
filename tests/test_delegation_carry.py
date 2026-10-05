"""U4 Part B: the never-widening carry through Andyur's own delegation.

When a run acting for Alice creates a task for another agent, that agent's woken run
inherits Alice as its user and a scope no wider than the delegator's own. So authority
narrows across an internal hop exactly as the token exchange narrows it across an
external one: a delegate can never gain scope its delegator lacked.
"""

import json

import pytest
from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module, runtoken

client = TestClient(app_module.app)


def _run(env, agent, run_id, user, scope):
    """An active run for `agent` acting for `user` with `scope`; returns its header."""
    env.agent(agent)
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at, acting_user, scope) "
            "VALUES (?, ?, 'running', ?, ?, ?)",
            (run_id, agent, db.utcnow(), user, json.dumps(scope) if scope else None),
        )
    return {"X-Andyur-Run-Token": runtoken.mint(agent, run_id, "wf", sub=user, scope=scope)}


def _delegated_run(assignee):
    """The run row the delegation woke for `assignee` (most recent)."""
    with db.connect() as c:
        return c.execute(
            "SELECT acting_user, scope FROM runs WHERE agent = ? ORDER BY created_at DESC LIMIT 1",
            (assignee,),
        ).fetchone()


def test_the_delegated_run_inherits_the_delegators_user(env):
    env.agent("worker")
    # a delegator needs tasks:write to delegate (U2); its full scope carries down
    hdr = _run(env, "boss", "run-boss", "alice", ["tasks:write", "files:read"])
    r = client.post("/tasks", json={"assignee": "worker", "title": "do it"}, headers=hdr)
    assert r.status_code == 201
    woken = _delegated_run("worker")
    assert woken["acting_user"] == "alice"                              # same user
    assert set(json.loads(woken["scope"])) == {"tasks:write", "files:read"}  # scope carried


def test_a_declared_narrower_scope_is_applied(env):
    env.agent("worker2")
    hdr = _run(env, "boss2", "run-boss2", "alice", ["tasks:write", "files:read", "files:write"])
    # the delegator hands the child only read, though it holds read+write itself
    r = client.post("/tasks",
                    json={"assignee": "worker2", "title": "read only", "scope": ["files:read"]},
                    headers=hdr)
    assert r.status_code == 201
    assert json.loads(_delegated_run("worker2")["scope"]) == ["files:read"]


def test_a_delegated_run_cannot_widen_beyond_the_delegator(env):
    env.agent("worker3")
    hdr = _run(env, "boss3", "run-boss3", "alice", ["tasks:write", "files:read"])  # no write
    # boss asks to hand down write too -> dropped, the delegate cannot exceed boss
    r = client.post("/tasks",
                    json={"assignee": "worker3", "title": "grab write",
                          "scope": ["files:read", "files:write"]},
                    headers=hdr)
    assert r.status_code == 201
    assert json.loads(_delegated_run("worker3")["scope"]) == ["files:read"]


def test_the_woken_run_enforces_its_inherited_scope(env):
    env.agent("worker4")
    hdr = _run(env, "boss4", "run-boss4", "alice", ["tasks:write", "files:read"])
    client.post("/tasks",
                json={"assignee": "worker4", "title": "read only", "scope": ["files:read"]},
                headers=hdr)
    # activate the woken run and mint its own token, then prove a write is refused
    with db.connect() as c:
        row = c.execute("SELECT id, acting_user, scope FROM runs WHERE agent = 'worker4' "
                        "ORDER BY created_at DESC LIMIT 1").fetchone()
        c.execute("UPDATE runs SET state = 'running' WHERE id = ?", (row["id"],))
    whdr = {"X-Andyur-Run-Token": runtoken.mint(
        "worker4", row["id"], "wf", sub=row["acting_user"], scope=json.loads(row["scope"]))}
    w = client.put("/agents/worker4/files/x.md", json={"content": "y"}, headers=whdr)
    assert w.status_code == 403 and "insufficient_scope" in w.json()["detail"]
