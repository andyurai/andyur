"""Provider-neutral observation helpers for the orchestration contract.

Every assertion in this suite goes through one of these, so that when a second
provider arrives there is exactly one place that knows how to look at it. The
bodies below reach into the native engine's database because that is what the
only current provider offers; the SIGNATURES are the contract, and a second
provider reimplements them without any test body changing.

Read `README.md` in this directory before adding anything here.
"""

import pytest

from andyur import db


# --- observations -----------------------------------------------------------

def run_state(run_id: str) -> str | None:
    """The lifecycle state a caller can see: pending, running, done, failed,
    cancelled -- or None when the provider has no such run."""
    with db.connect() as c:
        row = c.execute("SELECT state FROM runs WHERE id = ?", (run_id,)).fetchone()
    return row["state"] if row else None


def live_run_of(agent: str) -> str | None:
    """The one run currently holding this agent, or None when it is free.

    'Live' means admitted and not yet terminal. Whether the provider calls that
    pending, queued, scheduled or dispatched is its own business; what the
    contract fixes is that AT MOST ONE exists per agent, and that a free agent
    reports None.
    """
    with db.connect() as c:
        rows = c.execute(
            "SELECT id FROM runs WHERE agent = ? AND state IN ('pending', 'running')",
            (agent,),
        ).fetchall()
    assert len(rows) <= 1, (
        f"{agent} holds {len(rows)} live runs; the one-live-run-per-agent "
        f"invariant is the contract's foundation and this provider broke it")
    return rows[0]["id"] if rows else None


def live_runs_of(agent: str) -> list[str]:
    """Every live run for an agent, WITHOUT the single-run assertion.

    Only for the tests that are themselves checking the invariant -- everything
    else should use live_run_of and let it police the count.
    """
    with db.connect() as c:
        return [r["id"] for r in c.execute(
            "SELECT id FROM runs WHERE agent = ? AND state IN ('pending', 'running')",
            (agent,)).fetchall()]


def is_free(agent: str) -> bool:
    """Whether new work could be admitted for this agent right now."""
    return live_run_of(agent) is None


def authority_of(run_id: str) -> dict:
    """The authority a run carries: who it acts for, the scope it was narrowed
    to, its workflow, and how deep in a delegation chain it sits.

    This is the half of the contract a provider must carry FAITHFULLY rather
    than merely efficiently. Getting a timer wrong costs latency; getting this
    wrong widens authority.
    """
    with db.connect() as c:
        row = c.execute(
            "SELECT acting_user, scope, workflow_id, depth, subject_context, "
            "user_asserted_by FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return {}
    return {
        "user": row["acting_user"],
        "scope": row["scope"],
        "workflow": row["workflow_id"],
        "depth": row["depth"],
        "subject_context": row["subject_context"],
        "asserted_by": row["user_asserted_by"],
    }


def terminal_states() -> set[str]:
    """The states from which no further work happens on a run."""
    return {"done", "failed", "cancelled"}


# --- fixtures ---------------------------------------------------------------

@pytest.fixture
def agent(env):
    """One idle agent, the smallest thing that can be admitted."""
    return env.agent("alice")


@pytest.fixture
def two_agents(env):
    return env.agent("alice"), env.agent("bob")
