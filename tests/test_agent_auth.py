"""R1: agent-scoped authorization at the control plane.

With ANDYUR_AGENT_AUTH on (set in conftest), a run presents a signed run token
that names its agent+run, and the HTTP endpoints confine it to that agent's
namespace, server-stamp provenance, and bind mutations to ownership. A call
without a token is the operator (trusted-local, since identity is off in tests).

Driven through the real FastAPI app with TestClient, so it exercises the actual
dependencies and endpoint logic.
"""

import pytest
from fastapi.testclient import TestClient

from andyur import db, workspace
from andyur.server import app as app_module
from andyur.server import coordinator, messages, runtoken, tasks

client = TestClient(app_module.app)


def hdr(agent, run_id, wf):
    return {"X-Andyur-Run-Token": runtoken.mint(agent, run_id, wf)}


@pytest.fixture
def world(env):
    """alice + bob exist; alice has a live run in a workflow."""
    env.agent("alice")
    env.agent("bob")
    run = coordinator.maybe_wakeup("alice", "root")
    wf = env.run_workflow(run)
    return {"run": run, "wf": wf}


# -- namespace confinement (S1) ----------------------------------------------

def test_run_may_write_its_own_agent_files(world):
    r = client.put(
        "/agents/alice/files/memory/notes.md",
        json={"content": "hi"},
        headers=hdr("alice", world["run"], world["wf"]),
    )
    assert r.status_code == 200


def test_run_may_not_write_another_agents_files(world):
    r = client.put(
        "/agents/bob/files/memory/notes.md",
        json={"content": "poison mcp.json"},
        headers=hdr("alice", world["run"], world["wf"]),
    )
    assert r.status_code == 403


def test_invalid_run_token_is_rejected(world):
    r = client.put(
        "/agents/alice/files/memory/notes.md",
        json={"content": "hi"},
        headers={"X-Andyur-Run-Token": "garbage.sig"},
    )
    assert r.status_code == 401


def test_no_token_is_operator_and_may_touch_any_agent(world):
    # identity is off in tests, so a token-less call is the trusted-local operator
    r = client.put("/agents/bob/files/memory/notes.md", json={"content": "ok"})
    assert r.status_code == 200


# -- server-stamped provenance + derived parent (H_deputy) -------------------

def test_task_creator_and_parent_are_server_stamped(world):
    r = client.post(
        "/tasks",
        json={"assignee": "bob", "creator": "operator", "title": "t",
              "parent_run_id": "forged-run-id"},
        headers=hdr("alice", world["run"], world["wf"]),
    )
    assert r.status_code == 201
    tid = r.json()["id"]
    with db.connect() as c:
        row = c.execute(
            "SELECT creator, workflow_id FROM tasks WHERE id = ?", (tid,)
        ).fetchone()
    assert row["creator"] == "alice"            # not the forged 'operator'
    assert row["workflow_id"] == world["wf"]    # from alice's run, not the forged parent


# -- ownership binding (F6) --------------------------------------------------

def test_run_may_only_handle_its_own_messages(world):
    to_alice = messages.send_message("alice", "operator", "for alice")["id"]
    to_bob = messages.send_message("bob", "operator", "for bob")["id"]

    ok = client.post(f"/messages/{to_alice}/handle",
                     headers=hdr("alice", world["run"], world["wf"]))
    assert ok.status_code == 200
    denied = client.post(f"/messages/{to_bob}/handle",
                         headers=hdr("alice", world["run"], world["wf"]))
    assert denied.status_code == 403


def test_run_may_only_update_its_own_tasks(world):
    mine = tasks.create_task("alice", "operator", "mine")["id"]
    theirs = tasks.create_task("bob", "operator", "theirs")["id"]

    ok = client.post(f"/tasks/{mine}", json={"state": "in_progress"},
                     headers=hdr("alice", world["run"], world["wf"]))
    assert ok.status_code == 200
    denied = client.post(f"/tasks/{theirs}", json={"state": "closed"},
                         headers=hdr("alice", world["run"], world["wf"]))
    assert denied.status_code == 403


# -- run + workflow lifecycle scoping ----------------------------------------

def test_run_may_only_read_its_own_run(world):
    other = coordinator.maybe_wakeup("bob", "root")
    mine = client.get(f"/runs/{world['run']}",
                      headers=hdr("alice", world["run"], world["wf"]))
    assert mine.status_code == 200
    theirs = client.get(f"/runs/{other}",
                        headers=hdr("alice", world["run"], world["wf"]))
    assert theirs.status_code == 403


def test_workflow_state_is_not_an_oracle_for_other_workflows(world):
    other_run = coordinator.maybe_wakeup("bob", "root")
    other_wf = None
    with db.connect() as c:
        other_wf = c.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (other_run,)
        ).fetchone()["workflow_id"]

    mine = client.get(f"/workflows/{world['wf']}",
                      headers=hdr("alice", world["run"], world["wf"]))
    assert mine.status_code == 200
    theirs = client.get(f"/workflows/{other_wf}",
                        headers=hdr("alice", world["run"], world["wf"]))
    assert theirs.status_code == 403


def test_list_tasks_is_scoped_to_the_callers_agent(world):
    tasks.create_task("bob", "operator", "bob task")
    # alice's run asks for bob's tasks; the server forces assignee=alice
    r = client.get("/tasks?assignee=bob",
                   headers=hdr("alice", world["run"], world["wf"]))
    assert r.status_code == 200
    assert all(t["assignee"] == "alice" for t in r.json())


# -- path traversal (the confinement must survive relpath, not just {name}) --

def test_mind_key_rejects_path_traversal():
    for bad in ("../bob/instructions.md", "/etc/passwd", "a/../../bob/x",
                "..\\bob\\x", ""):
        with pytest.raises(ValueError):
            workspace._key("alice", bad)
    # legitimate paths still resolve under the agent
    assert workspace._key("alice", "notes.md") == "agents/alice/notes.md"
    assert workspace._key("alice", "memory/long_term.md") == \
        "agents/alice/memory/long_term.md"


def test_traversal_write_is_rejected_at_the_endpoint(world):
    # even with a valid alice token, a traversing relpath is refused (400), so a
    # run cannot escape its agent's namespace to another agent or host files
    r = client.put(
        "/agents/alice/files/sub/..%2f..%2fbob%2finstructions.md",
        json={"content": "poison"},
        headers=hdr("alice", world["run"], world["wf"]),
    )
    assert r.status_code in (400, 404)  # rejected, never a 200 write to bob


# -- run-token liveness (no post-terminal persistence) -----------------------

def test_token_for_a_finished_run_is_rejected(world):
    coordinator.finish_run(world["run"], "done", None)  # run is now terminal
    r = client.put(
        "/agents/alice/files/memory/notes.md",
        json={"content": "late write"},
        headers=hdr("alice", world["run"], world["wf"]),
    )
    assert r.status_code == 401  # a token for a finished run is no longer valid


def test_a_run_token_naming_no_agent_or_run_is_refused():
    """Only the server mints, and every mint names both -- so a signed token
    with an empty agent or run identifies nothing and must die at verify,
    not probe what liveness or SVID binding do with an empty string."""
    from andyur.server import runtoken
    import pytest
    for agent, run in (("", "r1"), ("a1", ""), ("", ""), ("  ", "r1"), ("a1", " ")):
        tok = runtoken.mint(agent, run, None, ttl=60)
        with pytest.raises(runtoken.InvalidRunToken, match="names no"):
            runtoken.verify(tok)
    # positive control: a fully named token verifies
    ctx = runtoken.verify(runtoken.mint("a1", "r1", None, ttl=60))
    assert ctx["agent"] == "a1" and ctx["run_id"] == "r1"
