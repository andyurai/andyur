"""Nothing reaches an agent through /tasks or /messages by accident.

Both routes served `SELECT *`, so a column added for the server's own
bookkeeping became API the moment the schema grew one -- and the caller is a
RUN, the least-trusted component here. Adding `parent_run_id` for the drain
(production-gaps 28) is what demonstrated it: an internal handle would have
reached every agent without anyone deciding it should.

The assertion is deliberately STRUCTURAL rather than a list of expected keys. A
key list goes stale silently; this reddens the moment a migration adds a column,
and the only way to green it is to say out loud whether the new column is for
the agent or not.
"""
import pytest

from andyur import db
from andyur.server import coordinator, messages, tasks


def _columns(table: str) -> set[str]:
    with db.connect() as c:
        return {r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}


@pytest.mark.parametrize("table, published, withheld", [
    ("tasks", set(tasks.TASK_VIEW_FIELDS), tasks.TASK_WITHHELD),
    ("messages", set(messages.MESSAGE_VIEW_FIELDS), messages.MESSAGE_WITHHELD),
])
def test_every_column_is_either_published_or_named_as_withheld(env, table, published, withheld):
    unclassified = _columns(table) - published - withheld
    assert not unclassified, (
        f"{table} grew {sorted(unclassified)}; add each to the view fields or "
        "to the withheld set with the reason it is not the agent's business")
    # and the two sets do not overlap, which would make the withholding a lie
    assert not (published & withheld)


def test_the_internal_handles_really_are_absent_from_what_an_agent_reads(env):
    """The property, not the constant: a real row through the real projection."""
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run")
    assert coordinator.start_run(parent)
    tasks.create_task("helper", "planner", "t", "d", parent_run_id=parent)
    messages.send_message("helper", "planner", "m", parent_run_id=parent)

    [task] = tasks.list_tasks(assignee="helper")
    [msg] = messages.list_messages("helper")
    for name, row in (("task", task), ("message", msg)):
        assert "parent_run_id" not in row, f"{name} handed the agent a run id"
        assert "notified_at" not in row, f"{name} handed the agent drain state"
    # positive control: the projection is not simply empty, and it still carries
    # what the agent actually needs to do the work
    assert task["title"] == "t" and task["state"] == "open"
    assert msg["body"] == "m" and msg["state"] == "unread"
    # ...and the column really is on the row underneath, so the absence above is
    # the projection withholding it and not the write silently failing
    # ...for BOTH, because an assertion that a field is absent cannot tell
    # "withheld" from "never written" on its own.
    with db.connect() as c:
        for table, row in (("tasks", task), ("messages", msg)):
            assert c.execute(
                f"SELECT parent_run_id FROM {table} WHERE id = ?", (row["id"],)
            ).fetchone()[0] == parent, f"{table} never stored the creating run"
