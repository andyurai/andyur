"""GET /agents/{name} must not 500 when a DB row outlives its mind storage.

A half-deleted or storage-drifted agent has an `agents` row (so the status view
yields it) but no `profile.json`. The detail endpoint used to call
`workspace.load_profile` unguarded, so a single such record raised
FileNotFoundError -> 500, which also broke the whole operator fleet view
(`status`/`watch` fetch every agent's detail). It must return the row with a
null profile instead, so the operator can see and delete the corrupt record.
"""
import conftest  # noqa: F401  (installs the operator-auth default header)
from fastapi.testclient import TestClient

from andyur.server import app as app_module

client = TestClient(app_module.app)


def test_agent_detail_returns_a_null_profile_when_the_mind_is_missing(env):
    # env.agent inserts an agents row (the status view yields it as idle) but
    # creates NO mind, so profile.json does not exist -- the exact corrupt state.
    env.agent("orphan_no_mind")
    r = client.get("/agents/orphan_no_mind")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "orphan_no_mind"
    assert body["profile"] is None
    # the rest of the record is still well-formed so the fleet view can render it
    assert body["state"] == "idle"
    assert body["recent_runs"] == []


def test_a_genuinely_absent_agent_is_still_404(env):
    # the null-profile handling must not turn a missing agent into a 200
    assert client.get("/agents/nope_not_here").status_code == 404
