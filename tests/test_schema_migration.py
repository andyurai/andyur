"""What init_db must guarantee once it returns, and what it must refuse to hide.

The indexes here are not decoration: GET /runs pages run history with a keyset
cursor and the flow graph reads three tables by workflow_id, and neither is
affordable as a scan. Nothing asserted any of them existed -- dropping all four
left the whole suite green -- and nothing asserted that a migration column that
could NOT be added is reported rather than swallowed.
"""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from andyur import db
from andyur.server import app as _app_module

client = TestClient(_app_module.app)


def test_every_migration_column_exists_once_init_db_returns(env):
    """The indexes created after the migration loop NAME migration columns, so a
    column silently missing is not a slower query -- `CREATE INDEX ... ON
    runs(workflow_id)` raises `no such column` out of init_db and the server
    does not start.

    Asked with a SELECT rather than through `db._has_column`: that helper is
    what the migration itself consults to decide whether to ALTER, so a test
    that asks it the same question can only ever agree with the code under
    test. The database is the authority here, not the accessor.
    """
    with db.connect() as conn:
        for table, column, _type in db.MIGRATION_COLUMNS:
            # raises OperationalError("no such column") if it is not there
            conn.execute(f'SELECT "{column}" FROM {table} LIMIT 1').fetchall()


def test_a_failing_alter_is_raised_not_swallowed(env, monkeypatch):
    # `except sqlite3.OperationalError: pass` reads "the column already exists"
    # but also catches "database is locked". Asking first means only a real
    # failure reaches the raise -- and that it reaches it, at the statement that
    # caused it, instead of surfacing later as a startup crash in an unrelated
    # CREATE INDEX.
    monkeypatch.setattr(db, "_has_column", lambda conn, table, column: False)
    with pytest.raises(sqlite3.OperationalError):
        db.init_db()


@pytest.mark.parametrize("name, table", [
    # Run history, newest first, with the (created_at, id) keyset cursor.
    ("idx_runs_created", "runs"),
    # The owner predicate of GET /runs under user-auth lives on agents.
    ("idx_agents_owner", "agents"),
    # One workflow's runs, tasks and messages: the flow graph reads all three.
    ("idx_runs_workflow", "runs"),
    ("idx_tasks_workflow", "tasks"),
    ("idx_messages_workflow", "messages"),
])
def test_the_indexes_the_console_read_paths_depend_on_exist(env, name, table):
    with db.connect() as conn:
        row = conn.execute(
            "SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?",
            (name,)).fetchone()
    assert row is not None, f"{name} was not created"
    assert row["tbl_name"] == table


def test_the_run_history_page_is_a_keyset_walk_when_it_is_not_owner_filtered(env, monkeypatch):
    """The unfiltered page -- user-auth off, or an admin -- must be an index walk
    with NO temp sort at any depth. The PLAN, not a timing: a timing test on a
    small fixture passes whatever the planner does.

    The SQL is captured from the ROUTE, not written again here. A first version
    wrote its own copy and EXPLAINed that; adding `COLLATE NOCASE` to the route's
    own ORDER BY restored the scan and the temp b-tree and nothing reddened,
    because the test was verifying the copy.

    Deliberately not asserted for the OWNER-FILTERED query: that one joins
    agents for the owner and SQLite materialises a temp b-tree for the ORDER BY.
    No index on `runs` changes it, because the predicate is not on `runs`. See
    idx_runs_created in db.py and ROADMAP.md.
    """
    from andyur.server import app as app_module

    seen = {}
    real_connect = db.connect

    class _Spy:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, params=()):
            if "FROM runs r JOIN agents a" in sql:
                seen["sql"], seen["params"] = sql, params
            return self._conn.execute(sql, params)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    class _Ctx:
        def __enter__(self):
            self._cm = real_connect()
            return _Spy(self._cm.__enter__())

        def __exit__(self, *a):
            return self._cm.__exit__(*a)

    monkeypatch.setattr(db, "connect", lambda: _Ctx())
    client.get("/runs", params={"limit": 50})
    monkeypatch.undo()
    assert "sql" in seen, "the route did not run the query this test explains"

    with db.connect() as conn:
        plan = " ".join(r["detail"] for r in
                        conn.execute("EXPLAIN QUERY PLAN " + seen["sql"],
                                     seen["params"]).fetchall())
    assert "idx_runs_created" in plan, plan
    assert "TEMP B-TREE" not in plan.upper(), plan
