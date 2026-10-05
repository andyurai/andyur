"""Deleting an agent, and the things that must not survive it.

Andyur could create agents and never remove them. That made every experiment
permanent, which is why the authority demo originally stood up a throwaway
database rather than use the real one -- a workaround for a missing product
operation, and the kind that hides whether the product works.

The property under test is that deletion is COMPLETE within the agent's namespace.
A partial delete is worse than none: a recreated agent of the same name inherits a
dead one's runs, messages and ceiling, and the operator has no way to see it.
"""

import json
import threading

import pytest
from fastapi.testclient import TestClient

from andyur import db
from andyur.server import app as app_module, registry, runtoken

client = TestClient(app_module.app)


def _agent(name: str) -> str:
    client.post("/agents", json={"name": name, "description": name})
    return name


def _rows(table: str, where: str, *params) -> int:
    with db.connect() as c:
        return c.execute(f"SELECT COUNT(*) AS n FROM {table} WHERE {where}",
                         params).fetchone()["n"]


def _run_row(agent: str, run_id: str, state: str = "running") -> str:
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at) VALUES (?, ?, ?, ?)",
            (run_id, agent, state, db.utcnow()),
        )
    return run_id


# --- the namespace goes with the agent ---------------------------------------

def test_deleting_an_agent_removes_everything_in_its_namespace(env):
    _agent("doomed")
    _agent("other")
    _run_row("doomed", "r-done", state="done")
    with db.connect() as c:
        c.execute("INSERT INTO tasks (id, assignee, creator, title, state, "
                  "created_at, updated_at) "
                  "VALUES ('t1','doomed','other','t','open',?,?)",
                  (db.utcnow(), db.utcnow()))
        c.execute("INSERT INTO messages (id, sender, recipient, body, created_at) "
                  "VALUES ('m1','other','doomed','hi',?)", (db.utcnow(),))
    registry.set_ceiling("doomed", actions=["files:read"])

    r = client.delete("/agents/doomed")
    assert r.status_code == 200

    assert _rows("agents", "name = ?", "doomed") == 0
    assert _rows("runs", "agent = ?", "doomed") == 0
    assert _rows("tasks", "assignee = ? OR creator = ?", "doomed", "doomed") == 0
    assert _rows("messages", "sender = ? OR recipient = ?", "doomed", "doomed") == 0
    # the positive control: the OTHER agent is untouched, so the delete was
    # scoped to a namespace rather than being a wipe that happened to pass
    assert _rows("agents", "name = ?", "other") == 1


def test_a_recreated_agent_does_not_inherit_the_dead_ones_ceiling(env):
    """The ceiling lives on the agent row, so this is really a test that the row
    is gone rather than blanked. It matters because a ceiling is a SECURITY bound:
    inheriting a dead agent's would be silently wrong in either direction."""
    _agent("phoenix")
    registry.set_ceiling("phoenix", actions=["files:read"])
    client.delete("/agents/phoenix")
    _agent("phoenix")
    assert registry.get_ceiling("phoenix") == {"actions": None, "audiences": None}


def test_deleting_is_404_for_an_agent_that_never_existed(env):
    assert client.delete("/agents/ghost").status_code == 404


# --- the live-run guard -------------------------------------------------------

def test_an_agent_with_a_live_run_is_refused_rather_than_deleted(env):
    """A live run has a runner holding a token for this agent. Deleting the row
    underneath it turns a clean refusal into a runner failing later on a call
    whose error names nothing."""
    _agent("busy")
    _run_row("busy", "r-live", state="running")
    r = client.delete("/agents/busy")
    assert r.status_code == 409
    assert _rows("agents", "name = ?", "busy") == 1     # still there
    assert _rows("runs", "id = ?", "r-live") == 1       # and so is its run


def test_force_cannot_delete_an_agent_whose_run_may_still_execute(env):
    """Metadata deletion cannot stand in for an execution fence."""
    _agent("wedged")
    _run_row("wedged", "r-stuck", state="running")
    response = client.delete("/agents/wedged", params={"force": "true"})
    assert response.status_code == 409
    assert "terminal state" in response.json()["detail"]
    assert _rows("agents", "name = ?", "wedged") == 1
    assert _rows("runs", "agent = ?", "wedged") == 1


def test_a_finished_run_does_not_block_deletion(env):
    """Only pending/running block. A history of completed runs is the normal case
    and must not make an agent undeletable."""
    _agent("retired")
    _run_row("retired", "r-old", state="done")
    assert client.delete("/agents/retired").status_code == 200


def test_non_force_delete_and_concurrent_trigger_are_atomic(env, monkeypatch):
    """A trigger may happen before deletion or after it, never between the
    liveness decision and namespace deletion. This reproduces the former TOCTOU
    window with a barrier after the endpoint has acquired its write lock."""
    _agent("racing")
    real_connect = db.connect
    locked = threading.Event()
    release = threading.Event()

    class BarrierConnection:
        def __init__(self):
            self.inner = real_connect()
            self.has_agent_lock = False

        def __enter__(self):
            self.inner.__enter__()
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def execute(self, sql, params=()):
            if "UPDATE agents SET paused = paused" in sql:
                result = self.inner.execute(sql, params)
                self.has_agent_lock = True
                return result
            if self.has_agent_lock and "SELECT COUNT(*) AS n FROM runs" in sql:
                locked.set()
                assert release.wait(5), "test did not release the delete transaction"
            return self.inner.execute(sql, params)

    monkeypatch.setattr(db, "connect", BarrierConnection)
    deleted = {}

    def delete_now():
        deleted["response"] = client.delete("/agents/racing")

    delete_thread = threading.Thread(target=delete_now)
    delete_thread.start()
    assert locked.wait(5), "delete never reached the locked liveness decision"

    insert_done = threading.Event()
    insert_error = []

    def trigger_now():
        try:
            with real_connect() as conn:
                conn.execute(
                    "INSERT INTO runs (id, agent, state, created_at) "
                    "VALUES ('r-race', 'racing', 'pending', ?)",
                    (db.utcnow(),),
                )
        except Exception as exc:  # the deleted parent makes the insert lose
            insert_error.append(exc)
        finally:
            insert_done.set()

    trigger_thread = threading.Thread(target=trigger_now)
    trigger_thread.start()
    assert not insert_done.wait(0.2), "trigger entered the guarded transaction"
    release.set()
    delete_thread.join(5)
    trigger_thread.join(5)

    assert deleted["response"].status_code == 200
    assert insert_done.is_set()
    assert insert_error, "a run was created after the atomic delete decision"
    assert _rows("agents", "name = ?", "racing") == 0
    assert _rows("runs", "id = ?", "r-race") == 0


# --- what deletion means for credentials --------------------------------------

def test_a_run_token_for_a_deleted_agent_stops_working(env):
    """Deleting the agent removes its runs, and a run token is only honoured for a
    live run. Without that, a token minted before the delete would outlive the
    agent it names."""
    _agent("expired")
    _run_row("expired", "r-tok", state="running")
    tok = runtoken.mint("expired", "r-tok", "wf", sub="alice", scope=["files:read"])
    hdr = {"X-Andyur-Run-Token": tok}
    before = client.post("/oauth/token",
                         json={"audience": "tool:x", "actor": "expired"}, headers=hdr)
    # 200 exactly, not merely "not 401": a token that was already being refused
    # for some other reason would make the assertion below vacuous
    assert before.status_code == 200

    refused = client.delete("/agents/expired", params={"force": "true"})
    assert refused.status_code == 409
    # Teardown owns the transition. Only after the run is terminal may metadata
    # deletion invalidate its token and remove the authoritative record.
    with db.connect() as conn:
        conn.execute("UPDATE runs SET state = 'done' WHERE id = ?", ("r-tok",))
    assert client.delete("/agents/expired").status_code == 200
    after = client.post("/oauth/token",
                        json={"audience": "tool:x", "actor": "expired"}, headers=hdr)
    assert after.status_code == 401


def test_the_mint_refuses_a_deleted_actor(env):
    """The registry read is what refuses: a deleted agent has no row, so no
    ceiling can be derived and no authority can be minted naming it."""
    _agent("caller")
    _agent("gone")
    _run_row("caller", "r-c", state="running")
    tok = runtoken.mint("caller", "r-c", "wf", sub="alice", scope=["files:read"])
    client.delete("/agents/gone")
    r = client.post("/oauth/token", json={"audience": "tool:x", "actor": "gone"},
                    headers={"X-Andyur-Run-Token": tok})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_target"


# --- the storage layer refuses to be pointed outside the workspace ------------

def test_the_mind_delete_refuses_a_name_that_escapes_the_workspace(env):
    """`delete_agent_files` bypasses `_key` because it targets the directory
    itself, so it has to carry that confinement on its own. This is the one path
    where a bad name would mean rm -rf somewhere real."""
    from andyur import workspace
    for bad in ("../etc", "a/../../b", "/etc", ""):
        with pytest.raises(ValueError):
            workspace.delete_agent_files(bad)


# --- under user-auth, delete is owner-gated like every other agent endpoint ----

@pytest.fixture
def users(monkeypatch):
    """Two users, the same harness test_cross_user.py uses. Without this the
    owner gate is a no-op, and a destructive endpoint would be tested only in the
    configuration where its access control does nothing."""
    from andyur import config
    from andyur.server import oidc

    def _raise():
        raise oidc.InvalidUserToken("bad token")

    monkeypatch.setattr(config, "USER_AUTH", True)
    def _claims(t):
        sub = {"alice-tok": "alice", "bob-tok": "bob"}.get(t)
        return {"sub": sub} if sub else _raise()

    monkeypatch.setattr(oidc, "validate_user_claims", _claims)


def test_a_user_cannot_delete_another_users_agent(env, users):
    """404 rather than 403, so a non-owner cannot even confirm the agent exists.
    On a DESTRUCTIVE endpoint this matters more than on a read: without it, one
    tenant can permanently destroy another's agent and its entire memory."""
    client.post("/agents", json={"name": "alices"},
                headers={"X-Andyur-User-Token": "alice-tok"})
    r = client.delete("/agents/alices", headers={"X-Andyur-User-Token": "bob-tok"})
    assert r.status_code == 404
    assert _rows("agents", "name = ?", "alices") == 1        # survived

    ok = client.delete("/agents/alices", headers={"X-Andyur-User-Token": "alice-tok"})
    assert ok.status_code == 200                              # the owner still can
    assert _rows("agents", "name = ?", "alices") == 0


def test_owner_is_checked_on_the_same_locked_row_that_is_deleted(
    env, users, monkeypatch,
):
    """Name reuse cannot turn Alice's authorized delete into deletion of Bob's
    replacement. Pause immediately before the row lock, replace the row, then
    prove the endpoint compares ownership on the replacement it actually locks."""
    client.post("/agents", json={"name": "reused"},
                headers={"X-Andyur-User-Token": "alice-tok"})
    real_connect = db.connect
    before_lock = threading.Event()
    release = threading.Event()

    class BeforeLockConnection:
        def __init__(self):
            self.inner = real_connect()

        def __enter__(self):
            self.inner.__enter__()
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def execute(self, sql, params=()):
            if "UPDATE agents SET paused = paused" in sql:
                before_lock.set()
                assert release.wait(5)
            return self.inner.execute(sql, params)

    monkeypatch.setattr(db, "connect", BeforeLockConnection)
    result = {}

    def alice_deletes():
        result["response"] = client.delete(
            "/agents/reused", headers={"X-Andyur-User-Token": "alice-tok"})

    deleting = threading.Thread(target=alice_deletes)
    deleting.start()
    assert before_lock.wait(5)
    with real_connect() as conn:
        conn.execute("DELETE FROM agents WHERE name = 'reused'")
        conn.execute(
            "INSERT INTO agents (name, description, owner, created_at) "
            "VALUES ('reused', '', 'bob', ?)", (db.utcnow(),)
        )
    release.set()
    deleting.join(5)

    assert result["response"].status_code == 404
    with real_connect() as conn:
        replacement = conn.execute(
            "SELECT owner FROM agents WHERE name = 'reused'"
        ).fetchone()
    assert replacement is not None and replacement["owner"] == "bob"
