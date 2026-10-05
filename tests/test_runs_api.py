"""The run routes the console reads: one projection (run_view) that never
returns the subject token, one owner gate that mirrors the agents' gate,
history with keyset paging, the transcript and exchanges projections, and the
workflow flow graph. Each has the standing auth negatives: a run token on an
operator route is 403; a plain user reaching another owner's run is 404 with
an owner positive control.
"""
import base64
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from andyur import config, db, workspace
from andyur.registry import service as registry_service
from andyur.registry.models import (AgentNotFound, AgentResolution, AuthorityCeiling,
                                    RuntimeResolution)
from andyur.server import app as app_module, oidc

client = TestClient(app_module.app)

ADMIN_ROLE = "andyur-admin"
_CLAIMS = {
    "alice-tok": {"sub": "alice"},
    "bob-tok": {"sub": "bob", "realm_access": {"roles": ["ops"]}},
    "carol-tok": {"sub": "carol", "realm_access": {"roles": ["ops", ADMIN_ROLE]}},
}


def _raise():
    raise oidc.InvalidUserToken("bad token")


@pytest.fixture
def users(monkeypatch):
    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(config, "ADMIN_ROLE", ADMIN_ROLE)
    monkeypatch.setattr(oidc, "validate_user_claims", lambda t: _CLAIMS.get(t) or _raise())


def _hdr(tok):
    return {"X-Andyur-User-Token": tok}


def _u(base):
    # agent minds persist in the workspace store across tests; names must be fresh
    return f"{base}-{uuid.uuid4().hex[:6]}"


SECRET = "USER-LOGIN-TOKEN-9f3c"


def _mk_agent(name, tok=None):
    r = client.post("/agents", json={"name": name}, headers=_hdr(tok) if tok else {})
    assert r.status_code == 201, r.text
    return r


def _mk_run(env, run_id, agent, *, state="done", created="2026-08-26T10:00:00",
            workflow=None, depth=0, run_type="work", reason="r",
            subject_token=None, trace_ctx=None, runtime_resolution=None, input_=None,
            parent=None):
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO runs (id, agent, run_type, state, reason, created_at, workflow_id, "
            "depth, subject_token, trace_ctx, runtime_resolution, input, parent_run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, agent, run_type, state, reason, created, workflow, depth,
             subject_token, trace_ctx, runtime_resolution, input_, parent))


TP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


# -- run_view: the secret never leaves --------------------------------------------

def test_get_run_never_returns_the_subject_token_but_keeps_the_facts(env):
    a = _u("a1"); _mk_agent(a)
    _mk_run(env, "r1", a, subject_token=SECRET, trace_ctx=TP,
            input_='{"q": 1}')
    r = client.get("/runs/r1")
    assert r.status_code == 200
    body = r.json()
    assert SECRET not in r.text and "subject_token" not in body
    assert body["id"] == "r1" and body["state"] == "done" and body["agent"] == a
    assert body["trace_ctx"] == TP                           # the runner joins its trace with this
    assert body["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert body["input"] == '{"q": 1}'
    # the VALUE, not merely the key: an always-None mutant died only in an
    # unrelated pod-mode test, so presence was all this pinned
    assert body["agent_spiffe_id"] == workspace.load_profile(a).get("spiffe_id")
    assert body["agent_spiffe_id"] and body["agent_spiffe_id"].startswith("spiffe://")


def test_recent_runs_go_through_the_same_projection(env):
    a = _u("a2"); _mk_agent(a)
    _mk_run(env, "r2", a, subject_token=SECRET)
    r = client.get(f"/agents/{a}")
    assert r.status_code == 200 and SECRET not in r.text
    assert r.json()["recent_runs"][0]["id"] == "r2"
    assert "trace_id" in r.json()["recent_runs"][0]


def test_run_view_is_the_single_place_and_drops_only_the_secret():
    row = {"id": "x", "subject_token": "s", "trace_ctx": TP, "state": "done"}
    v = app_module.run_view(row)
    assert v == {"id": "x", "trace_ctx": TP, "state": "done",
                 "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                 "interface_version": None}
    assert app_module.run_view({"id": "y", "trace_ctx": "garbage"})["trace_id"] is None
    # The protocol is derived on EVERY run view, not only the list one, so the
    # page has a single reader for it whichever route it came from.
    rt = json.dumps({"interface_version": "exec/v1"})
    assert app_module.run_view({"id": "z", "runtime_resolution": rt})["interface_version"] == "exec/v1"
    assert app_module.run_list_view({"id": "z", "runtime_resolution": rt})["interface_version"] == "exec/v1"
    # A row this cannot parse must not take out the page it appears on: the
    # column is TEXT and SQLite hands back whatever was written to it.
    for junk in ("null", "[]", '"exec/v1"', "123", "true", "not json", 7, None, ""):
        assert app_module.run_view({"id": "z", "runtime_resolution": junk})["interface_version"] is None


# -- a list page's size depends on the page limit and nothing else ----------------

def test_a_caller_cannot_grow_a_run_row_through_reason_scope_or_a_task_title(env):
    # One 17 MiB task title made GET /runs a 17 MiB response, past the
    # console's 16 MiB cap, on EVERY page until the row was deleted -- and
    # POST /tasks takes a run token, so an agent reached it with no operator
    # credential. Bound at the boundary, by name.
    a = _u("bound"); _mk_agent(a)
    over = "x" * (app_module.MAX_REASON_CHARS + 1)
    assert client.post(f"/agents/{a}/trigger", json={"reason": over}).status_code == 422
    assert client.post("/tasks", json={"assignee": a, "title": over}).status_code == 422
    big = "y" * (app_module.MAX_SCOPE_CHARS + 1)
    assert client.post(f"/agents/{a}/trigger", json={"reason": "ok", "scope": [big]}).status_code == 422
    many = ["s"] * (app_module.MAX_SCOPE_ENTRIES + 1)
    assert client.post(f"/agents/{a}/trigger", json={"reason": "ok", "scope": many}).status_code == 422
    # positive control: the same routes work inside the bound, so the refusals
    # above are the LENGTH being refused and not the route being broken
    assert client.post("/tasks", json={"assignee": a, "title": "t" * app_module.MAX_TITLE_CHARS}
                       ).status_code in (200, 201)


def test_a_list_page_stays_bounded_even_when_a_stored_row_is_not(env):
    # Input validation cannot undo a row that is ALREADY stored (written before
    # the bound existed, or by a path that does not go through the API), so the
    # projection has to hold on its own.
    a = _u("stored"); _mk_agent(a)
    huge = "z" * 200_000
    for i in range(5):
        _mk_run(env, f"h{i}", a, created=f"2026-08-26T11:0{i}:00", reason=huge)
    page = client.get("/runs", params={"limit": 5})
    assert page.status_code == 200
    rows = page.json()["runs"]
    assert len(rows) == 5
    # the bound FIRED: every reason here was 200_000 characters going in
    assert all(r["reason"].endswith("\u2026") for r in rows), \
        "nothing was truncated, so the bound is not what this test measured"
    for row in rows:
        assert len(row["reason"]) <= app_module._LIST_REASON_CHARS + 1     # + the ellipsis
        assert row["reason"].startswith("z") and row["reason"].endswith("\u2026")
        # nothing else caller-supplied and unbounded survives the projection
        assert "scope" not in row
    # the whole page, at the maximum limit, cannot approach the console's cap
    assert len(page.content) < 200_000, len(page.content)
    # the row route still carries the full reason: the bound is the LIST's
    assert client.get("/runs/h0").json()["reason"] == huge


def test_a_workflow_you_own_nothing_in_is_byte_identical_to_one_that_does_not_exist(env, users):
    """The route's docstring says it closes an existence oracle; nothing asked.

    The nearest test covers a caller who owns SOMETHING in the workflow. The
    property is the OTHER case: a caller who owns nothing in a workflow that
    DOES exist must get the same answer, byte for byte, as for an id that never
    existed -- otherwise the difference between the two is the oracle. Changing
    the not-visible branch to 403 "not yours" survived the whole suite.
    """
    a = _u("alices-only"); _mk_agent(a, "alice-tok")
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) "
                     "VALUES ('wf-alice-only', 'active', 'x')")
    _mk_run(env, "aonly", a, workflow="wf-alice-only", depth=0,
            created="2026-08-27T01:00:00")

    real = client.get("/workflows/wf-alice-only/flow", headers=_hdr("bob-tok"))
    fake = client.get("/workflows/wf-does-not-exist/flow", headers=_hdr("bob-tok"))
    assert real.status_code == fake.status_code == 404
    # the id differs, so compare everything ABOUT the answer except the id
    assert real.json()["detail"].replace("wf-alice-only", "X") == \
           fake.json()["detail"].replace("wf-does-not-exist", "X")
    assert set(real.headers) - {"date"} == set(fake.headers) - {"date"}
    # POSITIVE CONTROL: the owner does get it, so the 404 above is the gate and
    # not the route being broken for everyone
    assert client.get("/workflows/wf-alice-only/flow",
                      headers=_hdr("alice-tok")).status_code == 200


def test_one_owner_cannot_crowd_another_out_of_their_own_workflow(env, users, monkeypatch):
    """Applying the caps before the owner filter is a cross-owner DENIAL.

    Reproduced: alice seeds runs, tasks and messages into a shared workflow
    until the cap; bob owns one run, one task and one message in it; bob's
    GET /workflows/.../flow answers 404 "no workflow" for work he owns. The
    admin's graph was silently wrong the same way -- its cap fell on whichever
    rows sorted first.
    """
    monkeypatch.setattr(app_module, "_FLOW_MAX_RUNS", 5)
    monkeypatch.setattr(app_module, "_FLOW_MAX_ITEMS", 5)
    alice_agent, bob_agent = _u("alice-bulk"), _u("bob-leaf")
    _mk_agent(alice_agent, "alice-tok")
    _mk_agent(bob_agent, "bob-tok")
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) "
                     "VALUES ('wf-crowd', 'active', 'x')")
    # alice fills the workflow first, so her rows sort ahead of bob's
    for i in range(20):
        _mk_run(env, f"al{i}", alice_agent, workflow="wf-crowd", depth=0,
                created=f"2026-08-26T22:{i:02d}:00")
    with db.connect() as conn:
        for i in range(20):
            conn.execute("INSERT INTO tasks (id, assignee, creator, title, detail, state, "
                         "created_at, updated_at, workflow_id) VALUES "
                         "(?, ?, 'op', 't', 'd', 'closed', ?, 'x', 'wf-crowd')",
                         (f"at{i}", alice_agent, f"2026-08-26T22:{i:02d}:00"))
            conn.execute("INSERT INTO messages (id, recipient, sender, body, state, "
                         "created_at, workflow_id) VALUES "
                         "(?, ?, 'op', 'b', 'handled', ?, 'wf-crowd')",
                         (f"am{i}", alice_agent, f"2026-08-26T22:{i:02d}:00"))
    # bob's single run, task and message arrive LAST
    _mk_run(env, "bobrun", bob_agent, workflow="wf-crowd", depth=1, run_type="task",
            created="2026-08-26T23:00:00")
    with db.connect() as conn:
        conn.execute("INSERT INTO tasks (id, assignee, creator, title, detail, state, "
                     "created_at, updated_at, workflow_id) VALUES "
                     "('bt', ?, 'op', 'bobs task', 'd', 'open', '2026-08-26T23:00:00', "
                     "'x', 'wf-crowd')", (bob_agent,))
        conn.execute("INSERT INTO messages (id, recipient, sender, body, state, created_at, "
                     "workflow_id) VALUES ('bm', ?, 'op', 'bobs message', 'unread', "
                     "'2026-08-26T23:00:00', 'wf-crowd')", (bob_agent,))

    r = client.get("/workflows/wf-crowd/flow", headers=_hdr("bob-tok"))
    assert r.status_code == 200, "bob was told his own workflow does not exist"
    flow = r.json()
    assert any(n.get("id") == "bobrun" for n in flow["nodes"]), \
        "bob's own run was crowded out of his own graph"
    assert [t["id"] for t in flow["tasks"]] == ["bt"]
    assert [m["id"] for m in flow["messages"]] == ["bm"]
    # and alice's payloads are still not his to read
    assert "alice-bulk" not in str(flow["tasks"]) + str(flow["messages"])

    # THE ADMIN still sees a capped graph, and it still says so
    admin = client.get("/workflows/wf-crowd/flow", headers=_hdr("carol-tok")).json()
    assert admin["truncated_runs"] is True and admin["truncated_items"] is True


def test_an_edge_into_a_run_you_may_not_read_carries_no_cause_or_reason(env, users):
    """The S1 fix, pinned. A run's `reason` embeds the task title and the sender
    agent's name -- "new task from oncall: check deploy" -- so an edge INTO an
    elided node must carry neither cause nor reason.

    The test beside this one asserts the edge SHAPE (how many, between which
    indices) and the elided node's key set, and never what an edge CARRIES.
    Deleting the `if mine` guard on those two fields therefore survived the
    entire suite while bob, owning one leaf run, read alice's task title.
    """
    oncall, reader, audit = _mk_workflow(env)
    bobs = client.get("/workflows/wf1/flow", headers=_hdr("bob-tok"))
    assert bobs.status_code == 200
    flow = bobs.json()
    # POSITIVE CONTROL: bob does see the chain's shape, so an all-empty answer
    # cannot pass this test.
    assert [n["elided"] for n in flow["nodes"]] == [True, True, False]
    assert len(flow["edges"]) == 2

    for edge in flow["edges"]:
        child = flow["nodes"][edge["to"]]
        if child["elided"]:
            assert edge["cause"] is None, edge
            assert edge["reason"] is None, edge
    # ...and the task title itself is nowhere in the response. The elided
    # node's AGENT NAME is a deliberate, documented disclosure (the chain's
    # shape stays visible; production-gaps records it), so it is not asserted
    # absent here -- what must not travel is the payload a reason embeds.
    assert "check deploy" not in bobs.text          # alice's task title
    assert flow["tasks"] == []                      # nor the task row itself

    # POSITIVE CONTROL on the other side: the owner of the edge's child DOES
    # get the cause and the reason, so the assertions above are the withholding
    # and not the field being unset for everyone.
    alices = client.get("/workflows/wf1/flow", headers=_hdr("alice-tok")).json()
    into_reader = [e for e in alices["edges"] if alices["nodes"][e["to"]]["agent"] == reader]
    assert into_reader and into_reader[0]["cause"] == "task"
    assert "check deploy" in (into_reader[0]["reason"] or "")


def test_the_list_query_never_materialises_a_body(env, monkeypatch):
    """`SELECT r.*` then drop is not a bound.

    Measured before this: 1,887 MiB peak to serve 83 KB on `?limit=200` --
    the page the console loads by default, with no adversary involved. The
    columns are named in the query so a summary is never read at all.
    """
    seen = []
    real_connect = db.connect

    class _Spy:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, params=()):
            seen.append(sql)
            return self._conn.execute(sql, params)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    class _Ctx:
        def __enter__(self):
            self._cm = real_connect()
            return _Spy(self._cm.__enter__())

        def __exit__(self, *a):
            return self._cm.__exit__(*a)

    a = _u("nobody"); _mk_agent(a)
    _mk_run(env, "lr1", a, created="2026-08-26T21:00:00", input_="I" * 10_000)
    with db.connect() as conn:
        conn.execute("UPDATE runs SET summary = ? WHERE id = 'lr1'", ("S" * 10_000,))

    monkeypatch.setattr(db, "connect", lambda: _Ctx())
    r = client.get("/runs", params={"limit": 50})
    monkeypatch.undo()
    assert r.status_code == 200
    [sql] = [q for q in seen if "FROM runs r JOIN agents a" in q]
    assert "SELECT r.*" not in sql, sql
    for body in ("summary", "input", "error", "subject_context", "ceiling_audiences"):
        assert f'r."{body}"' not in sql, f"{body} is read by the list query: {sql}"
    # ...and the two the projection DERIVES from are read, or the row would
    # come back with a null trace id and a null protocol
    assert 'r."trace_ctx"' in sql and 'r."runtime_resolution"' in sql
    assert "S" * 100 not in r.text and "I" * 100 not in r.text
    # positive control: the row is still complete for what a list shows
    row = [x for x in r.json()["runs"] if x["id"] == "lr1"][0]
    assert row["agent"] == a and row["state"] and "trace_id" in row


def test_a_run_report_is_bounded_at_the_boundary(env):
    # The list projection's comment said "captured stdout up to 1 MiB" and no
    # code enforced it: the only limit was the 64 MiB request cap.
    a = _u("finisher"); _mk_agent(a)
    _mk_run(env, "fr1", a, state="running", created="2026-08-26T21:05:00")
    over = "x" * (app_module.MAX_SUMMARY_CHARS + 1)
    assert client.post("/runs/fr1/finish", json={"summary": over}).status_code == 422
    over_err = "y" * (app_module.MAX_ERROR_CHARS + 1)
    assert client.post("/runs/fr1/finish", json={"error": over_err}).status_code == 422
    # positive control: at the bound it is accepted, so this is the LENGTH
    # being refused and not the route being broken
    ok = client.post("/runs/fr1/finish", json={"summary": "s" * 1000})
    assert ok.status_code in (200, 409), ok.text


def test_the_run_projection_is_an_allow_list_covering_every_column(env):
    # A deny-list published every FUTURE column by default. This asserts the
    # decision was made for each one: a column added to `runs` without being
    # named on either side fails here rather than shipping to a client.
    with db.connect() as conn:
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(runs)").fetchall()}
    published = app_module._RUN_VIEW_FIELDS
    withheld = set(app_module._RUN_WITHHELD)
    assert not (published & withheld)
    assert columns == published | withheld, {
        "undecided": columns - published - withheld,
        "named but not a column": (published | withheld) - columns,
    }


def test_no_run_view_hands_a_caller_another_owners_run_id(env, users):
    # parent_run_id crosses owners whenever the delegation did. bob owning the
    # CHILD run must not read alice's run id off his own row -- it is the exact
    # id the elided node in the flow graph exists to withhold, and the row
    # route, the list route and the graph all publish the same projection.
    sa, vb = _u("lead-alice"), _u("leaf-bob")
    _mk_agent(sa, "alice-tok")
    _mk_agent(vb, "bob-tok")
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wfx', 'active', 'x')")
    _mk_run(env, "alice-secret-run", sa, workflow="wfx", depth=0,
            created="2026-08-26T15:00:00")
    _mk_run(env, "bobs-own-run", vb, workflow="wfx", depth=1, run_type="task",
            created="2026-08-26T15:01:00", parent="alice-secret-run")

    row = client.get("/runs/bobs-own-run", headers=_hdr("bob-tok"))
    assert row.status_code == 200                       # positive control: he owns it
    assert "alice-secret-run" not in row.text
    assert "parent_run_id" not in row.json()

    listing = client.get("/runs", headers=_hdr("bob-tok"))
    assert listing.status_code == 200 and "bobs-own-run" in listing.text   # control
    assert "alice-secret-run" not in listing.text

    flow = client.get("/workflows/wfx/flow", headers=_hdr("bob-tok"))
    assert flow.status_code == 200
    assert [n["elided"] for n in flow.json()["nodes"]] == [True, False]    # control
    assert "alice-secret-run" not in flow.text
    # and the graph still knows the edge it computed from the withheld column
    assert [(e["from"], e["to"]) for e in flow.json()["edges"]] == [(0, 1)]


# -- the owner gate ----------------------------------------------------------------

def test_a_user_reads_only_runs_of_agents_they_own_and_an_admin_reads_all(env, users):
    sa, vb = _u("scout-alice"), _u("vault-bob")
    _mk_agent(sa, "alice-tok")
    _mk_agent(vb, "bob-tok")
    _mk_run(env, "ra", sa, subject_token=SECRET)
    _mk_run(env, "rb", vb)
    assert client.get("/runs/ra", headers=_hdr("alice-tok")).status_code == 200      # owner
    denied = client.get("/runs/ra", headers=_hdr("bob-tok"))
    assert denied.status_code == 404 and SECRET not in denied.text                       # no oracle
    assert client.get("/runs/ra", headers=_hdr("carol-tok")).status_code == 200      # admin
    assert client.get("/runs/nope", headers=_hdr("carol-tok")).status_code == 404
    assert client.get("/runs/ra", headers=_hdr("forged")).status_code == 401


def test_a_run_token_is_not_an_operator_credential_on_the_new_routes(env):
    a = _u("a3"); _mk_agent(a)
    _mk_run(env, "r3", a)
    for path in ("/runs", "/runs/r3/transcript", "/runs/r3/exchanges", "/workflows/w/flow"):
        r = client.get(path, headers={"X-Andyur-Run-Token": "x"})
        assert r.status_code == 403, path


# -- GET /runs: history, filters, keyset paging -----------------------------------

def test_runs_are_listed_newest_first_with_keyset_paging(env):
    a4, a5 = _u("a4"), _u("a5")
    _mk_agent(a4); _mk_agent(a5)
    for i in range(5):
        _mk_run(env, f"p{i}", a4 if i % 2 else a5, created=f"2026-08-26T10:0{i}:00",
                state="done" if i < 4 else "running", subject_token=SECRET)
    page1 = client.get("/runs", params={"limit": 2}).json()
    assert [r["id"] for r in page1["runs"]] == ["p4", "p3"] and page1["next"]
    assert SECRET not in json.dumps(page1)
    # a LIST row carries no bodies: fifty runs with captured stdout in them
    # exceeded the console's response cap
    row = page1["runs"][0]
    assert not ({"summary", "error", "input", "runtime_resolution"} & set(row))
    assert "interface_version" in row and "state" in row and "agent" in row
    page2 = client.get("/runs", params={"limit": 2, "before": page1["next"]}).json()
    assert [r["id"] for r in page2["runs"]] == ["p2", "p1"] and page2["next"]
    page3 = client.get("/runs", params={"limit": 2, "before": page2["next"]}).json()
    assert [r["id"] for r in page3["runs"]] == ["p0"] and page3["next"] is None
    # filters
    assert [r["id"] for r in client.get("/runs", params={"agent": a4}).json()["runs"]] == ["p3", "p1"]
    assert [r["id"] for r in client.get("/runs", params={"state": "running"}).json()["runs"]] == ["p4"]
    # exactly `limit` rows: no phantom next page
    exact = client.get("/runs", params={"limit": 5}).json()
    assert len(exact["runs"]) == 5 and exact["next"] is None
    # a cursor past the end is an empty page, not an error
    past = app_module._encode_cursor("2000-01-01T00:00:00+00:00", "zzz")
    assert client.get("/runs", params={"before": past}).json() == {"runs": [], "next": None}
    # the cursor is OPAQUE: it survives a round trip through a URL untouched
    # (the old "<created_at>|<id>" form lost its "+00:00" to form decoding and
    # silently returned an empty page instead of a 422)
    assert "+" not in page1["next"] and "|" not in page1["next"] and ":" not in page1["next"]


def test_paging_breaks_ties_on_the_run_id(env):
    # created_at is second-granular and ids are random, so a page boundary can
    # fall inside one second; the id is what makes the walk total.
    a = _u("tie"); _mk_agent(a)
    for rid in ("tA", "tB", "tC", "tD"):
        _mk_run(env, rid, a, created="2026-08-26T12:00:00")
    page1 = client.get("/runs", params={"limit": 2}).json()
    assert [r["id"] for r in page1["runs"]] == ["tD", "tC"] and page1["next"]
    page2 = client.get("/runs", params={"limit": 2, "before": page1["next"]}).json()
    assert [r["id"] for r in page2["runs"]] == ["tB", "tA"] and page2["next"] is None


def _b64(payload):
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def test_a_mangled_cursor_is_a_422_not_a_silently_empty_page(env):
    bad = ["no-pipe", "2026-08-26T09:23:53 00:00|r1", "!!!!", "e30", "W10",
           # Unpacking any 2-length iterable let these through as ("a", "b"):
           # a two-character JSON STRING and a two-KEY object. Both then paged
           # from a keyset nobody issued, which is the silently empty page the
           # opaque cursor exists to rule out.
           _b64("ab"), _b64({"a": 1, "b": 2}),
           _b64([1, 2]), _b64(["", ""]), _b64(["a", "b", "c"]), _b64(None)]
    for token in bad:
        r = client.get("/runs", params={"before": token})
        assert r.status_code == 422, (token, r.status_code, r.text)
    # positive control: a real cursor of the same shape is still accepted, so
    # the refusals above are the SHAPE being refused and not the route.
    assert client.get("/runs", params={"before": _b64(["2026-08-26T10:00:00", "r1"])}
                      ).status_code == 200


def test_runs_paging_bounds_are_422(env):
    assert client.get("/runs", params={"limit": 0}).status_code == 422
    assert client.get("/runs", params={"limit": 201}).status_code == 422
    assert client.get("/runs", params={"limit": "abc"}).status_code == 422
    # ...AND THE BOUNDS THEMSELVES ARE ACCEPTED. Only the outside was checked,
    # so the documented maximum could have been silently refused and nothing
    # would have noticed -- a refusal test with no positive control tells you
    # the route refuses, not that it refuses the right things.
    # Written as the NUMBER, not as the constant: a test that asks for
    # `_RUNS_PAGE_MAX` moves with the constant, so lowering the maximum stays
    # green while every client that read the published bound starts getting
    # 422s. The page size is part of the route's contract.
    assert app_module._RUNS_PAGE_MAX == 200
    assert client.get("/runs", params={"limit": 1}).status_code == 200
    assert client.get("/runs", params={"limit": 200}).status_code == 200


def test_the_run_list_is_owner_filtered_like_the_agent_list(env, users):
    sa, vb = _u("scout-alice"), _u("vault-bob")
    _mk_agent(sa, "alice-tok")
    _mk_agent(vb, "bob-tok")
    _mk_run(env, "ra", sa); _mk_run(env, "rb", vb, created="2026-08-26T11:00:00")
    assert [r["id"] for r in client.get("/runs", headers=_hdr("alice-tok")).json()["runs"]] == ["ra"]
    assert [r["id"] for r in client.get("/runs", headers=_hdr("bob-tok")).json()["runs"]] == ["rb"]
    assert [r["id"] for r in client.get("/runs", headers=_hdr("carol-tok")).json()["runs"]] == ["rb", "ra"]


# -- transcript and exchanges ---------------------------------------------------------

TRANSCRIPT = "\n".join(json.dumps(x) for x in [
    {"turn": 1, "human": "which pods restarted?"},
    {"type": "AssistantMessage", "data": {"model": "m1", "content": [
        {"text": "Let me check."},
        {"id": "tu1", "name": "k8s.read_events", "input": {"namespace": "payments"}}],
        "usage": {"input_tokens": 10}, "stop_reason": "tool_use"}},
    {"type": "UserMessage", "data": {"content": [
        {"tool_use_id": "tu1", "content": [{"type": "text", "text": "3 restarts"}], "is_error": False}]}},
    {"type": "AssistantMessage", "data": {"model": "m1", "content": [
        {"thinking": "secret reasoning", "signature": "x"}, {"text": "Three pods restarted."}]}},
    {"type": "ResultMessage", "data": {"is_error": False, "num_turns": 2, "duration_ms": 1200,
                                       "total_cost_usd": 0.01}},
]) + "\n"


def test_transcript_and_exchanges_come_from_the_runners_file(env):
    a = _u("a6"); _mk_agent(a)
    _mk_run(env, "r6", a)
    assert client.get("/runs/r6/transcript").status_code == 404
    workspace.write_text(a, "runs/r6/transcript.jsonl", TRANSCRIPT)
    t = client.get("/runs/r6/transcript")
    assert t.status_code == 200 and t.headers["content-type"].startswith("application/x-ndjson")
    assert t.text == TRANSCRIPT
    ex = client.get("/runs/r6/exchanges").json()["exchanges"]
    kinds = [e["kind"] for e in ex]
    assert kinds == ["turn", "tool", "model", "model", "result"]
    tool = ex[1]
    assert tool["name"] == "k8s.read_events" and tool["input"] == {"namespace": "payments"}
    assert tool["result"] == [{"type": "text", "text": "3 restarts"}] and tool["is_error"] is False
    first_model = ex[2]
    assert first_model["model"] == "m1" and first_model["usage"] == {"input_tokens": 10}
    assert [b["type"] for b in first_model["blocks"]] == ["text", "tool_use"]
    # thinking is acknowledged, never reproduced
    assert [b["type"] for b in ex[3]["blocks"]] == ["thinking", "text"]
    assert "secret reasoning" not in json.dumps(ex)


def test_an_exec_v1_run_has_no_transcript_by_name(env):
    a = _u("a7"); _mk_agent(a)
    _mk_run(env, "r7", a, runtime_resolution=json.dumps({"interface_version": "exec/v1"}))
    r = client.get("/runs/r7/exchanges")
    assert r.status_code == 404 and "exec/v1" in r.json()["detail"]
    assert client.get("/runs/r7/transcript").json()["detail"].startswith("no transcript: exec/v1")


def test_transcript_and_exchanges_are_owner_gated(env, users):
    sa = _u("scout-alice"); _mk_agent(sa, "alice-tok")
    _mk_run(env, "ra", sa)
    workspace.write_text(sa, "runs/ra/transcript.jsonl", TRANSCRIPT)
    for path in ("/runs/ra/transcript", "/runs/ra/exchanges"):
        assert client.get(path, headers=_hdr("alice-tok")).status_code == 200, path
        assert client.get(path, headers=_hdr("bob-tok")).status_code == 404, path
        assert client.get(path, headers=_hdr("carol-tok")).status_code == 200, path


# -- the workflow flow graph ------------------------------------------------------------

def _mk_workflow(env):
    oncall, reader, audit = _u("oncall"), _u("deploy-reader"), _u("billing-audit")
    _mk_agent(oncall, "alice-tok"); _mk_agent(reader, "alice-tok")
    _mk_agent(audit, "bob-tok")
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wf1', 'active', 'x')")
    _mk_run(env, "root", oncall, workflow="wf1", depth=0, created="2026-08-26T10:00:00",
            reason="manual trigger by operator", subject_token=SECRET)
    _mk_run(env, "child1", reader, workflow="wf1", depth=1, run_type="task",
            reason="new task from oncall: check deploy", created="2026-08-26T10:01:00",
            parent="root")
    _mk_run(env, "child2", audit, workflow="wf1", depth=1, run_type="message",
            reason="new message from oncall", created="2026-08-26T10:02:00",
            parent="root")
    with db.connect() as conn:
        conn.execute("INSERT INTO tasks (id, assignee, creator, title, detail, state, created_at, "
                     "updated_at, workflow_id) VALUES ('t1', ?, ?, 'check deploy', "
                     "'last deploy of payments', 'done', 'x', 'x', 'wf1')", (reader, oncall))
        conn.execute("INSERT INTO messages (id, recipient, sender, body, state, created_at, "
                     "workflow_id) VALUES ('m1', ?, ?, 'audit this', 'unread', 'x', 'wf1')", (audit, oncall))
    return oncall, reader, audit


def test_the_flow_graph_comes_from_run_task_and_message_records(env, users):
    oncall, reader, audit = _mk_workflow(env)
    flow = client.get("/workflows/wf1/flow", headers=_hdr("carol-tok")).json()
    assert flow["state"] == "active"
    assert [n["agent"] for n in flow["nodes"]] == [oncall, reader, audit]
    assert all(n["elided"] is False for n in flow["nodes"])
    assert flow["edges"] == [
        {"from": 0, "to": 1, "cause": "task", "reason": "new task from oncall: check deploy"},
        {"from": 0, "to": 2, "cause": "message", "reason": "new message from oncall"},
    ]
    assert flow["tasks"][0]["title"] == "check deploy" and flow["messages"][0]["body"] == "audit this"
    assert SECRET not in json.dumps(flow)


def test_another_owners_runs_are_elided_nodes_not_leaks(env, users):
    oncall, reader, audit = _mk_workflow(env)
    flow = client.get("/workflows/wf1/flow", headers=_hdr("alice-tok")).json()
    kinds = [(n["agent"], n["elided"]) for n in flow["nodes"]]
    assert kinds == [(oncall, False), (reader, False), (audit, True)]
    elided = flow["nodes"][2]
    assert set(elided) == {"agent", "state", "depth", "elided", "index"}     # no id, no reason
    assert len(flow["edges"]) == 2                                          # the shape stays
    assert flow["messages"] == [] and flow["tasks"][0]["assignee"] == reader
    # bob owns only the leaf: he sees the chain's shape and his own payload
    bobs = client.get("/workflows/wf1/flow", headers=_hdr("bob-tok")).json()
    assert [n["elided"] for n in bobs["nodes"]] == [True, True, False]
    assert bobs["messages"][0]["body"] == "audit this" and bobs["tasks"] == []
    # nobody who owns nothing in it learns the workflow exists
    assert client.get("/workflows/wf-none/flow", headers=_hdr("alice-tok")).status_code == 404


def test_an_edge_names_the_recorded_parent_not_whoever_sits_one_level_up(env):
    # Two parents at the same depth. The depth heuristic attributes a child to
    # the LAST run one level up, so with the column ignored both children hang
    # off boss-b; the record says otherwise.
    a, b, c1, c2 = _u("boss-a"), _u("boss-b"), _u("kid-1"), _u("kid-2")
    for name in (a, b, c1, c2):
        _mk_agent(name)
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wf2', 'active', 'x')")
    _mk_run(env, "pa", a, workflow="wf2", depth=0, created="2026-08-26T12:00:00")
    _mk_run(env, "pb", b, workflow="wf2", depth=0, created="2026-08-26T12:01:00")
    _mk_run(env, "ca", c1, workflow="wf2", depth=1, created="2026-08-26T12:02:00",
            run_type="task", parent="pa")
    _mk_run(env, "cb", c2, workflow="wf2", depth=1, created="2026-08-26T12:03:00",
            run_type="task", parent="pb")
    flow = client.get("/workflows/wf2/flow").json()
    idx = {n["id"]: n["index"] for n in flow["nodes"]}
    assert sorted((e["from"], e["to"]) for e in flow["edges"]) == sorted(
        [(idx["pa"], idx["ca"]), (idx["pb"], idx["cb"])])


def test_a_dangling_parent_draws_no_edge_rather_than_inventing_one(env):
    # DELETE /agents cascades its runs away and leaves other agents' children
    # pointing at rows that are gone. Falling back to the depth heuristic there
    # attributed the orphan to an unrelated run and carried that run's cause and
    # reason, indistinguishable from a real edge.
    a, b, c = _u("owner-a"), _u("other-root"), _u("orphan")
    for name in (a, b, c):
        _mk_agent(name)
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wf3', 'active', 'x')")
    _mk_run(env, "gone", a, workflow="wf3", depth=0, created="2026-08-26T13:00:00")
    _mk_run(env, "unrelated", b, workflow="wf3", depth=0, created="2026-08-26T13:01:00")
    _mk_run(env, "orphan", c, workflow="wf3", depth=1, created="2026-08-26T13:02:00",
            run_type="task", reason="new task from owner-a: secret title", parent="gone")
    assert len(client.get("/workflows/wf3/flow").json()["edges"]) == 1   # control: it resolves
    with db.connect() as conn:
        conn.execute("DELETE FROM runs WHERE id = 'gone'")
    flow = client.get("/workflows/wf3/flow").json()
    assert flow["edges"] == []
    assert len(flow["nodes"]) == 2                     # the orphan is still drawn, as a root


def test_a_row_written_before_the_column_still_gets_its_heuristic_edge(env):
    # The fallback is for rows that PREDATE parent_run_id, and only those. It
    # must keep working for them or an upgrade blanks every existing graph.
    a, b = _u("legacy-root"), _u("legacy-kid")
    _mk_agent(a); _mk_agent(b)
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wf4', 'active', 'x')")
    _mk_run(env, "lroot", a, workflow="wf4", depth=0, created="2026-08-26T14:00:00")
    _mk_run(env, "lkid", b, workflow="wf4", depth=1, created="2026-08-26T14:01:00",
            run_type="task", parent=None)
    flow = client.get("/workflows/wf4/flow").json()
    assert [(e["from"], e["to"]) for e in flow["edges"]] == [(0, 1)]


# -- exchange counts: the graph is drawn from one call -----------------------------

def _transcript(*lines):
    return "\n".join(json.dumps(line) for line in lines)


def test_exchange_counts_are_bounded_and_name_what_they_left_out():
    line = {"type": "AssistantMessage", "data": {"model": "claude-x", "content": [
        {"type": "tool_use", "id": "1", "name": "files", "input": {}}]}}
    text = _transcript(*[line] * 5)
    counts = app_module.exchange_counts(text)
    assert counts == {"models": {"claude-x": 5}, "tools": {"files": 5}, "truncated": False}

    # Names come out of a transcript the RUN wrote, so their cardinality is
    # agent-controlled; every distinct one is a node in the response and a lane
    # in the drawing. Bounded, and the bound is reported rather than silent.
    many = _transcript(*[{"type": "AssistantMessage", "data": {"model": "m", "content": [
        {"type": "tool_use", "id": str(i), "name": f"t{i}", "input": {}}]}}
        for i in range(app_module._FLOW_MAX_KEYS + 10)])
    counts = app_module.exchange_counts(many)
    assert len(counts["tools"]) == app_module._FLOW_MAX_KEYS and counts["truncated"] is True

    # ...and the LENGTH of each name, not only how many there are. A name comes
    # out of the transcript the run wrote, so thirty-two of them at 16 KiB each
    # was half a megabyte in one node while every documented cap held.
    long_name = "T" * 16_384
    wide = _transcript({"type": "AssistantMessage", "data": {"model": long_name, "content": [
        {"type": "tool_use", "id": "1", "name": long_name, "input": {}}]}})
    counts = app_module.exchange_counts(wide)
    assert max(len(k) for k in counts["tools"]) <= app_module._FLOW_KEY_CHARS + 1
    assert max(len(k) for k in counts["models"]) <= app_module._FLOW_KEY_CHARS + 1
    assert counts["truncated"] is True


def test_a_tool_name_is_normalised_in_one_place():
    # The counts and the page were coercing a non-string name their own way, so
    # the same call became two different graph nodes.
    text = _transcript({"type": "AssistantMessage", "data": {"model": "m", "content": [
        {"type": "tool_use", "id": "1", "name": None, "input": {}}]}})
    assert app_module.exchange_counts(text)["tools"] == {"tool": 1}
    assert app_module.exchanges_from_transcript(text)[0]["name"] == "tool"


def test_the_flow_graph_bounds_what_one_request_reads(env, monkeypatch):
    """One request must not read more than its budget, whatever the workflow holds.

    A run writes its own transcript, so every byte on this path is
    agent-controlled, and the graph reads EVERY visible run's transcript in one
    request. Measured before this bound: 200 runs x 5 MiB was 1001 MiB read to
    return 0.13 MiB, and twenty concurrent operator requests took the process
    to ~1 GiB RSS with /health at 4.9 s.

    Asserted on the LIMITS the route asks the storage layer for, not on process
    memory, so it is a contract and not a flaky measurement.
    """
    # Small caps, so the fixture can exceed BOTH of them without writing a
    # gigabyte: the property is the arithmetic, not the size.
    monkeypatch.setattr(app_module, "_FLOW_MAX_RUNS", 10)
    monkeypatch.setattr(app_module, "_FLOW_TRANSCRIPT_BYTES", 4096)
    monkeypatch.setattr(app_module, "_FLOW_READ_BUDGET", 16384)
    a = _u("chatty"); _mk_agent(a)
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wfbig', 'active', 'x')")
    for i in range(30):
        _mk_run(env, f"big{i}", a, workflow="wfbig", depth=0,
                created=f"2026-08-26T16:{i // 60:02d}:{i % 60:02d}")

    asked = []
    # The spy records the limit the route ASKED for and fabricates at most a
    # sane amount: a test must not have to allocate what an unbounded read
    # would, or the mutant that removes the bound kills the test process
    # instead of failing the assertion.
    FABRICATE = 64 * 1024
    # MULTI-BYTE, deliberately. The budget is in BYTES and `len(str)` is
    # characters, so an ASCII fixture makes the two indistinguishable and the
    # assertion below unfalsifiable -- a correct assertion with a fixture that
    # cannot exercise it. This character is 4 bytes in UTF-8, so a route that
    # spends `len(text)` overruns the budget fourfold and the sum below catches
    # it. (Session-R found the real bug the same way, on emoji transcripts.)
    WIDE = "\U0001F600"

    def spy(name, relpath, limit):
        asked.append(limit)
        chars = max(1, min(limit, FABRICATE) // len(WIDE.encode()))
        text = WIDE * chars
        # (text, more, RAW BYTES READ) -- the third member is what the budget
        # is charged, and it is deliberately the FULL allowance here: a read
        # costs its allowance whatever the bytes decode to.
        return (text, True, limit)

    monkeypatch.setattr(workspace, "read_text_bounded", spy)
    flow = client.get("/workflows/wfbig/flow")
    assert flow.status_code == 200
    assert asked, "the route never asked for a bounded read"
    # THE BOUND MUST HAVE FIRED, not merely not been exceeded. A stubbed read, a
    # fixture too small, or a cap silently reverted mid-test all satisfy "under
    # the limit" and none of them satisfies "the limit did something" -- three
    # of the five unfalsifiable fixtures in this lane passed exactly that way.
    assert max(asked) == app_module._FLOW_TRANSCRIPT_BYTES, \
        f"no read ever hit the per-file cap: {sorted(set(asked))}"
    assert sum(asked) >= app_module._FLOW_READ_BUDGET, \
        "the request budget was never exhausted, so this asserts nothing"
    # no single read exceeds the per-file cap...
    assert max(asked) <= app_module._FLOW_TRANSCRIPT_BYTES
    # ...and the whole request cannot exceed its budget however many runs there
    # are. Asserted on BYTES: a route that spends characters passes this with an
    # ASCII fixture and overruns fourfold on a real transcript.
    assert sum(asked) <= app_module._FLOW_READ_BUDGET, sum(asked)
    body = flow.json()
    # A NODE THE BUDGET SKIPPED SAYS SO, by value and not by absence. Asserting
    # only that some node's exchanges is None cannot tell "there is nothing to
    # read" from "I did not read it", which is the exact bug the marker exists
    # for: 184 nodes labelled "no transcript" while every one had a 5 MiB
    # transcript the budget had already run out before.
    skipped = [n for n in body["nodes"] if n.get("exchanges_omitted")]
    assert skipped, "no node was skipped, so this asserts nothing about the marker"
    assert all(n["exchanges_omitted"] == "budget" for n in skipped)
    assert all(n["exchanges"] is None for n in skipped)
    # ...and a node that simply HAS no transcript carries no marker at all
    # ...and the run count itself is capped, so a wide workflow cannot make the
    # request grow by adding runs rather than by growing one of them.
    assert len(body["nodes"]) == app_module._FLOW_MAX_RUNS
    assert body["truncated_runs"] is True
    assert body["truncated_reads"] is True          # and it SAYS what it left out
    assert any(n["exchanges"] is None for n in body["nodes"])


def test_the_flow_graph_bounds_its_tasks_and_messages_too(env, monkeypatch):
    # The cheapest request that hurt was 112 bytes: ONE run plus 500 closed
    # tasks and 500 read messages returned 1.05 GB and took the process to
    # 3.6 GiB. Neither query had a LIMIT and detail/result/body had no bound,
    # and MAX_WORKFLOW_RUNS counts none of it -- it counts only NON-TERMINAL
    # work, so a workflow may hold any number of finished items.
    monkeypatch.setattr(app_module, "_FLOW_MAX_ITEMS", 5)
    monkeypatch.setattr(app_module, "_FLOW_ITEM_BYTES", 32)
    a = _u("chatty2"); _mk_agent(a)
    # CONTROL CHARACTERS, deliberately: each is one character in and six bytes
    # out as a JSON escape. An ASCII fixture makes a character bound and a byte
    # bound indistinguishable, so the assertion below could not see the
    # difference -- the same unfalsifiable-fixture mistake as the ASCII spy.
    huge = "\x01" * 100_000
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wfi', 'active', 'x')")
        for i in range(20):
            conn.execute("INSERT INTO tasks (id, assignee, creator, title, detail, state, "
                         "result, created_at, updated_at, workflow_id) VALUES "
                         "(?, ?, 'op', 't', ?, 'closed', ?, 'x', 'x', 'wfi')",
                         (f"tk{i}", a, huge, huge))
            conn.execute("INSERT INTO messages (id, recipient, sender, body, state, "
                         "created_at, workflow_id) VALUES (?, ?, 'op', ?, 'handled', 'x', 'wfi')",
                         (f"mg{i}", a, huge))
    _mk_run(env, "onerun", a, workflow="wfi", depth=0, created="2026-08-26T18:00:00")

    # ASSERTED ON THE QUERY, not only on the response. Slicing in Python bounds
    # what is RETURNED and not what is READ, and the finding was 1.05 GB read
    # from the database for a 112-byte request -- so a test that only checks the
    # response passes with the LIMIT deleted.
    seen = []
    real_connect = db.connect

    class _Spy:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, params=()):
            seen.append(sql)
            return self._conn.execute(sql, params)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    class _Ctx:
        def __enter__(self):
            self._cm = real_connect()
            return _Spy(self._cm.__enter__())

        def __exit__(self, *a):
            return self._cm.__exit__(*a)

    # Restore ONLY the connection spy. `monkeypatch.undo()` reverts EVERY
    # patch this test made, including the two caps above -- so the assertions
    # below were comparing against the production bound and passed whatever the
    # route did. That is how the chars-vs-bytes mutant survived a test written
    # to catch it.
    real_db_connect = db.connect
    monkeypatch.setattr(db, "connect", lambda: _Ctx())
    try:
        r = client.get("/workflows/wfi/flow")
    finally:
        monkeypatch.setattr(db, "connect", real_db_connect)
    assert r.status_code == 200
    for table in ("FROM tasks t", "FROM messages m"):
        [sql] = [q for q in seen if table in q]
        assert "LIMIT" in sql.upper(), f"{table} is read without a LIMIT: {sql}"
    body = r.json()
    assert len(body["tasks"]) <= app_module._FLOW_MAX_ITEMS
    assert len(body["messages"]) <= app_module._FLOW_MAX_ITEMS
    assert body["truncated_items"] is True                  # and it SAYS so
    # measured on the ENCODING, which is what the response is made of
    def enc(v):
        return len(json.dumps(v)) - 2
    # the bound FIRED: every detail was 100_000 control characters going in
    assert all(t["detail"].endswith("\u2026") for t in body["tasks"]), body["tasks"][:1]
    for t in body["tasks"]:
        assert enc(t["detail"]) <= app_module._FLOW_ITEM_BYTES + 6
        assert enc(t["result"]) <= app_module._FLOW_ITEM_BYTES + 6
    for m in body["messages"]:
        assert enc(m["body"]) <= app_module._FLOW_ITEM_BYTES + 6
    # the whole response is bounded by the caps, not by what the workflow holds
    assert len(r.content) < 20_000, len(r.content)


def test_a_flow_node_carries_no_run_bodies(env):
    # A node needs a run's FACTS, not its bodies. With the full run view, 200
    # nodes carrying summaries at the platform's 1 MiB retention cap plus their
    # inputs was a 1.89 GB response.
    a = _u("bodies"); _mk_agent(a)
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wfb', 'active', 'x')")
    _mk_run(env, "bigrun", a, workflow="wfb", depth=0, created="2026-08-26T19:00:00",
            input_="I" * 50_000)
    with db.connect() as conn:
        conn.execute("UPDATE runs SET summary = ? WHERE id = 'bigrun'", ("S" * 50_000,))
    # ASSERTED ON THE QUERY as well as the response: run_list_view drops the
    # bodies either way, so the response cannot tell `SELECT r.*` from a named
    # column list -- and the finding is about what is READ. Up to 401 rows
    # across the two owner buckets made this route's cost depend on a bound two
    # modules away instead of on its own projection.
    seen = []
    real_connect = db.connect

    class _Spy:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, params=()):
            seen.append(sql)
            return self._conn.execute(sql, params)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    class _Ctx:
        def __enter__(self):
            self._cm = real_connect()
            return _Spy(self._cm.__enter__())

        def __exit__(self, *a):
            return self._cm.__exit__(*a)

    saved_connect = db.connect
    db.connect = lambda: _Ctx()
    try:
        r = client.get("/workflows/wfb/flow")
    finally:
        db.connect = saved_connect
    [sql] = [q for q in seen if "FROM runs r " in q]
    assert "SELECT r.*" not in sql, sql
    for body_col in ("summary", "input", "error", "subject_context"):
        assert f'r."{body_col}"' not in sql, f"{body_col} is read by the flow query: {sql}"
    # ...and the columns the GRAPH needs beyond a list row ARE read
    assert 'r."parent_run_id"' in sql and "a.owner AS agent_owner" in sql
    assert r.status_code == 200
    node = r.json()["nodes"][0]
    assert not ({"summary", "input", "runtime_resolution", "scope"} & set(node))
    # positive control: the facts a graph draws with ARE there
    assert node["id"] == "bigrun" and node["state"] and node["agent"] == a
    assert "S" * 100 not in r.text and "I" * 100 not in r.text


def test_a_partly_read_transcript_is_reported_as_partly_read(env, monkeypatch):
    """`counts["truncated"] = counts["truncated"] or more` was untested.

    The nearby tests call exchange_counts directly and never exercise the
    READ's `more` flag. That flag drives the node's "counted in part only"
    label and the graph's "at least" lower bound, so dropping `or more` makes
    the page state a partial total as an exact one -- silently.
    """
    a = _u("partial"); _mk_agent(a)
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wfp', 'active', 'x')")
    _mk_run(env, "pr1", a, workflow="wfp", depth=0, created="2026-08-27T02:00:00")
    line = json.dumps({"type": "AssistantMessage",
                       "data": {"model": "m", "content": []}})
    # the read returns COMPLETE, PARSEABLE content and reports there was more
    monkeypatch.setattr(workspace, "read_text_bounded",
                        lambda n, p, limit: (line, True, limit))
    node = client.get("/workflows/wfp/flow").json()["nodes"][0]
    assert node["exchanges"]["models"] == {"m": 1}      # it parsed what it got
    assert node["exchanges"]["truncated"] is True, \
        "the read said there was more and the node does not say so"

    # POSITIVE CONTROL: the same content with more=False is NOT partial
    monkeypatch.setattr(workspace, "read_text_bounded",
                        lambda n, p, limit: (line, False, limit))
    node = client.get("/workflows/wfp/flow").json()["nodes"][0]
    assert node["exchanges"]["truncated"] is False


def test_a_transcript_of_many_tiny_lines_is_bounded_by_work_not_only_by_bytes(monkeypatch):
    # The byte budget bounds BYTES; nothing bounded work per byte. Millions of
    # tiny lines was 4.2 million failed json.loads for a 121 KB response and
    # 5.2 s of CPU -- worse than the case it was fixing, on an eighth the data.
    monkeypatch.setattr(app_module, "_FLOW_MAX_LINES", 100)
    text = "\n".join(["{}"] * 5000)
    counts = app_module.exchange_counts(text)
    assert counts["truncated"] is True
    # positive control: under the cap it is not reported as truncated
    assert app_module.exchange_counts("\n".join(["{}"] * 10))["truncated"] is False


def test_the_flow_span_never_carries_the_callers_own_string(env):
    # The span added on this route made an unbounded path parameter reachable
    # in telemetry: the 404 interpolates the caller's workflow id, and an
    # exception raised inside a span is recorded with its message AND a stack
    # trace. redact() is applied nowhere in this module.
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    original = app_module._tracer
    app_module._tracer = provider.get_tracer("test")
    secret = "Bearer eyJhbGciOiJSUzI1NiJ9.SECRETPAYLOAD.sig"
    try:
        r = client.get("/workflows/" + secret + "X" * 4000 + "/flow")
        assert r.status_code == 404
        spans = exporter.get_finished_spans()
        assert spans, "the route emitted no span"
        [span] = [s for s in spans if s.name == "server.workflow_flow"]
        blob = json.dumps({"attrs": dict(span.attributes),
                           "status": str(span.status.description),
                           "events": [str(e.attributes) for e in span.events]})
        assert "SECRETPAYLOAD" not in blob, blob[:400]
        assert "XXXXXXXXXX" not in blob, blob[:400]
        # positive control: the DECISION is on the span, by name
        assert span.attributes["andyur.outcome"] == "refused"
        assert span.attributes["andyur.reason"] == "no_such_workflow"
        assert span.attributes["http.response.status_code"] == 404
    finally:
        app_module._tracer = original
    # and the caller's own answer is bounded too
    assert len(r.json()["detail"]) < 200


def test_the_run_list_route_puts_its_decision_on_a_span(env):
    # The control plane mounts no request-level instrumentation, so without a
    # span here this lane's boundary refusals and its cursor 422s -- the fixes
    # for the blockers -- produce nothing at all in the trace.
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    original = app_module._tracer
    app_module._tracer = provider.get_tracer("test")
    try:
        assert client.get("/runs").status_code == 200
        [allowed] = [x for x in exporter.get_finished_spans() if x.name == "server.list_runs"]
        assert allowed.attributes["andyur.outcome"] == "allowed"
        assert "andyur.runs.returned" in allowed.attributes

        exporter.clear()
        bad = "!!!!not-a-cursor!!!!"
        assert client.get("/runs", params={"before": bad}).status_code == 422
        [refused] = [x for x in exporter.get_finished_spans() if x.name == "server.list_runs"]
        assert refused.attributes["andyur.outcome"] == "refused"
        assert refused.attributes["andyur.reason"] == "invalid"
        assert refused.attributes["http.response.status_code"] == 422
        # and the caller's own string is not in the span
        assert bad not in json.dumps({"a": dict(refused.attributes),
                                      "s": str(refused.status.description),
                                      "e": [str(e.attributes) for e in refused.events]})
    finally:
        app_module._tracer = original


def test_the_flow_span_says_how_much_it_read_and_what_it_left_out(env, monkeypatch):
    # A route that reads N agent-written files per request is invisible in the
    # trace without these: "the graph is slow" and "the graph read a gigabyte"
    # are the same event otherwise. All four survived the suite unasserted.
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    monkeypatch.setattr(app_module, "_FLOW_MAX_RUNS", 2)
    monkeypatch.setattr(app_module, "_FLOW_TRANSCRIPT_BYTES", 64)
    monkeypatch.setattr(app_module, "_FLOW_READ_BUDGET", 64)
    a = _u("spans"); _mk_agent(a)
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wfs', 'active', 'x')")
    for i in range(4):
        _mk_run(env, f"sp{i}", a, workflow="wfs", depth=0, created=f"2026-08-26T20:0{i}:00")
    monkeypatch.setattr(workspace, "read_text_bounded",
                        lambda n, p, limit: ("y" * limit, True, limit) if limit else None)

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    original = app_module._tracer
    app_module._tracer = provider.get_tracer("test")
    try:
        assert client.get("/workflows/wfs/flow").status_code == 200
        [span] = [x for x in exporter.get_finished_spans() if x.name == "server.workflow_flow"]
    finally:
        app_module._tracer = original
    assert span.attributes["andyur.flow.runs_drawn"] == 2
    assert span.attributes["andyur.flow.bytes_read"] > 0
    assert span.attributes["andyur.flow.truncated_runs"] is True
    assert span.attributes["andyur.flow.truncated_reads"] is True
    assert span.attributes["andyur.flow.truncated_items"] is False   # none in this fixture
    # The attribute added THIS round precisely because two of the three ways
    # this route can return a partial answer were dark. Asserting the other
    # five and not this one is the same defect class, one round later, on the
    # fix for that class.
    # one: the budget covers exactly one full-allowance read, so the second
    # node is SKIPPED (truncated_reads) rather than partly read
    assert span.attributes["andyur.flow.partial_transcripts"] == 1


def test_a_read_that_decodes_to_nothing_is_still_charged_to_the_budget(env, monkeypatch):
    """Charging the DECODED length charges zero for a full read.

    `b"\xff" * 8 MiB` decodes under errors="ignore" to the empty string, so the
    loop kept going: 104,857,600 raw bytes against an 8 MiB budget, 12.5x, and
    the response said `truncated_reads: false` with every node marked "no
    transcript" -- verbatim the falsehood the marker exists to stop.
    """
    monkeypatch.setattr(app_module, "_FLOW_MAX_RUNS", 50)
    monkeypatch.setattr(app_module, "_FLOW_TRANSCRIPT_BYTES", 1024)
    monkeypatch.setattr(app_module, "_FLOW_READ_BUDGET", 4096)
    a = _u("undecodable"); _mk_agent(a)
    with db.connect() as conn:
        conn.execute("INSERT INTO workflows (id, state, created_at) VALUES ('wfu', 'active', 'x')")
    for i in range(20):
        _mk_run(env, f"u{i}", a, workflow="wfu", depth=0, created=f"2026-08-27T00:{i:02d}:00")

    raw_read = []

    def undecodable(name, relpath, limit):
        raw_read.append(limit)
        return ("", True, limit)          # decodes to nothing, still cost a read

    monkeypatch.setattr(workspace, "read_text_bounded", undecodable)
    r = client.get("/workflows/wfu/flow")
    assert r.status_code == 200
    assert sum(raw_read) <= app_module._FLOW_READ_BUDGET, sum(raw_read)
    # ...and it does not claim nothing was left out
    assert r.json()["truncated_reads"] is True


def test_a_run_row_with_a_junk_runtime_resolution_does_not_500_the_route(env):
    # _interface_version is derived on EVERY projection now, so the guard is
    # load-bearing on the single-row route too, not only on the list.
    a = _u("junk"); _mk_agent(a)
    for i, junk in enumerate(("null", "[]", '"exec/v1"', "123", "true", "not json")):
        _mk_run(env, f"j{i}", a, runtime_resolution=junk,
                created=f"2026-08-26T17:0{i}:00")
    for i in range(6):
        row = client.get(f"/runs/j{i}")
        assert row.status_code == 200, (i, row.text)
        assert row.json()["interface_version"] is None
    assert client.get("/runs").status_code == 200
    assert client.get(f"/agents/{a}").status_code == 200


# -- resolve widening ---------------------------------------------------------------------

def test_resolve_carries_the_digest_and_runtime_summary_keys():
    # The four runtime keys are what the console's Catalog detail renders, so a
    # rename here is a blank field there. Reading them off whatever the demo
    # catalog happens to hold left that assertion on a branch that never ran:
    # no demo manifest declares a runtime, and the plain-directory registry
    # cannot express one (only the governed snapshot carries a runtime block),
    # so `res["runtime"] is None` short-circuited it on every run. A catalog
    # that DOES hold a runtime makes the shape load-bearing.
    runtime = RuntimeResolution(
        runtime_type="container",
        interface_version="exec/v1",
        manifest_digest="sha256:" + "cd" * 32,
        image_ref="ghcr.io/andyur/packer:1",
        image_digest="sha256:" + "ab" * 32,
        command=("/usr/bin/pack", "--in", "/tmp/andyur/input"),
    )
    resolution = AgentResolution(
        agent_id="agt_packer", name="packer", instructions="Package the content.",
        model=None, tools=(), ceiling=AuthorityCeiling(actions=None, resources=None),
        registry_digest="sha256:" + "ef" * 32, runtime=runtime,
    )

    class _Catalog:
        def list_agents(self):
            return [resolution]

        def resolve(self, agent_id):
            if agent_id != resolution.agent_id:
                raise AgentNotFound(agent_id)
            return resolution

    registry_service.configure_registry_factory(_Catalog)
    try:
        agents = client.get("/v1/registry/agents").json()["agents"]
        assert [a["agent_id"] for a in agents] == ["agt_packer"]
        res = client.get("/v1/registry/agents/agt_packer/resolve").json()
        assert res["registry_digest"] == "sha256:" + "ef" * 32
        assert set(res["runtime"]) == {"interface_version", "image_ref",
                                       "image_digest", "command"}
        assert res["runtime"]["interface_version"] == "exec/v1"
        assert res["runtime"]["image_ref"] == "ghcr.io/andyur/packer:1"
        assert res["runtime"]["image_digest"] == "sha256:" + "ab" * 32
        assert res["runtime"]["command"] == ["/usr/bin/pack", "--in", "/tmp/andyur/input"]
    finally:
        registry_service.restore_default_registry()
