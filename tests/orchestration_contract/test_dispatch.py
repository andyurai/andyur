"""Dispatch: getting an admitted run to something that will execute it.

This is the module a durable-execution provider would replace most completely.
The native engine dispatches by having workers pull assignments on a heartbeat
and by requeueing whatever a dead worker was holding; Temporal would use a task
queue and its own worker liveness. Almost none of that is contract.

What IS contract is the pair of properties those mechanisms exist to provide:

  1. an admitted run is handed to AT MOST ONE executor at a time, and
  2. a run whose executor dies becomes available again rather than being lost.

Everything below asserts one of those two, or the backstop that stops an
undispatchable run waiting forever. Worker ids appear only because the current
provider needs a name for "an executor"; nothing asserts anything about them.
"""

from datetime import datetime, timedelta, timezone

from andyur import db
from andyur.server import coordinator, heartbeat

from .conftest import is_free, run_state


def _executor(name: str = "executor-1", slots: int = 4) -> str:
    """Register something that can execute runs, and return its handle."""
    coordinator.record_heartbeat(name, slots)
    return name


def _executor_went_silent(name: str, seconds: int = 600) -> None:
    """Make an executor look dead to the provider's liveness check."""
    when = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with db.connect() as c:
        c.execute("UPDATE workers SET last_heartbeat = ? WHERE id = ?", (when, name))


def _dispatched_to(run_id: str) -> str | None:
    with db.connect() as c:
        row = c.execute("SELECT worker FROM runs WHERE id = ?", (run_id,)).fetchone()
    return row["worker"] if row else None


def _backdate_creation(run_id: str, seconds: int) -> None:
    when = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with db.connect() as c:
        c.execute("UPDATE runs SET created_at = ? WHERE id = ?", (when, run_id))


# --- an admitted run is dispatched ------------------------------------------

def test_an_admitted_run_is_offered_to_an_executor(agent):
    run = coordinator.maybe_wakeup(agent, "work")
    worker = _executor()

    assigned = coordinator.assign_runs(worker, 1)

    assert [a["id"] for a in assigned] == [run]


def test_a_dispatched_run_is_not_offered_again(agent):
    """The exactly-one-executor half of the contract. A second poll must not
    re-offer work already in flight, or two executors run the same agent."""
    coordinator.maybe_wakeup(agent, "work")
    first = _executor("executor-1")
    second = _executor("executor-2")

    coordinator.assign_runs(first, 1)

    assert coordinator.assign_runs(second, 1) == [], "the same run was dispatched twice"


def test_an_executor_is_never_given_more_than_it_asked_for(two_agents):
    """Capacity is the executor's to declare. A provider that overcommits an
    executor turns one slow run into a queue nobody can see."""
    alice, bob = two_agents
    coordinator.maybe_wakeup(alice, "work")
    coordinator.maybe_wakeup(bob, "work")
    worker = _executor(slots=4)

    assert len(coordinator.assign_runs(worker, 1)) == 1


def test_asking_for_no_capacity_is_offered_nothing(agent):
    coordinator.maybe_wakeup(agent, "work")
    worker = _executor()

    assert coordinator.assign_runs(worker, 0) == []


def test_nothing_admitted_means_nothing_dispatched(env):
    assert coordinator.assign_runs(_executor(), 4) == []


# --- a dead executor gives its work back ------------------------------------

def test_work_held_by_a_dead_executor_becomes_available_again(agent):
    """The no-run-is-lost half of the contract, and the reason the native
    engine tracks executor liveness at all."""
    run = coordinator.maybe_wakeup(agent, "work")
    dead = _executor("executor-doomed")
    coordinator.assign_runs(dead, 1)
    assert _dispatched_to(run) == dead

    _executor_went_silent(dead)
    heartbeat.recover_stuck_runs()

    assert _dispatched_to(run) is None, "a dead executor kept its claim"
    assert run_state(run) == "pending", "the run was lost rather than requeued"

    survivor = _executor("executor-survivor")
    assert [a["id"] for a in coordinator.assign_runs(survivor, 1)] == [run], (
        "the requeued run was not offered to a healthy executor")


def test_a_live_executor_keeps_its_work(agent):
    """The negative control. Reclaiming from a healthy executor would hand the
    same run to two of them -- the exact failure the requeue exists to prevent,
    caused by the requeue itself."""
    run = coordinator.maybe_wakeup(agent, "work")
    worker = _executor()
    coordinator.assign_runs(worker, 1)

    heartbeat.recover_stuck_runs()

    assert _dispatched_to(run) == worker


def test_a_started_run_is_not_requeued_when_its_executor_dies(agent):
    """Requeue applies to work that has not begun. A run already executing
    cannot be handed to a second executor just because the first went quiet --
    the process may well still be running, and this is the point where an
    over-eager provider produces two live agents.

    What happens to such a run instead is the deadline reaper's business; see
    test_run_lifecycle.py.
    """
    run = coordinator.maybe_wakeup(agent, "work")
    worker = _executor()
    coordinator.assign_runs(worker, 1)
    coordinator.start_run(run)

    _executor_went_silent(worker)
    heartbeat.recover_stuck_runs()

    assert run_state(run) == "running"
    assert _dispatched_to(run) == worker, "an executing run was handed to another executor"


# --- the backstop on work nobody takes --------------------------------------

def test_a_run_nobody_takes_is_eventually_given_up_on(agent):
    """The queue backstop. Without it an undispatchable run holds its agent
    indefinitely, and the agent is the scarce thing."""
    run = coordinator.maybe_wakeup(agent, "work")
    _backdate_creation(run, heartbeat.QUEUE_MAX_WAIT_SECONDS + 600)

    heartbeat.recover_stuck_runs()

    assert run_state(run) in {"done", "failed"}
    assert is_free(agent)


def test_the_backstop_window_is_long_enough_to_be_a_backstop_not_a_ttl(agent):
    """CHARACTERIZATION, and the measure of a known gap.

    The backstop is 24 hours by default. That is correct for what it is -- a
    queue nobody is draining -- but it is also the ONLY automatic release for a
    run that can never be dispatched, and 24 hours is indistinguishable from
    forever to an operator watching a gate, or to a developer whose agent is
    stuck. Combined with the absence of a direct cancel (see
    test_run_lifecycle.py) this is the sharpest ergonomic edge in the current
    orchestration.

    Recorded, not fixed: Stage 1 changes no behaviour.
    """
    assert heartbeat.QUEUE_MAX_WAIT_SECONDS >= 3600, (
        "the backstop is now short enough to act as a TTL; that is a behaviour "
        "change the contract should describe deliberately")

    run = coordinator.maybe_wakeup(agent, "work")
    _backdate_creation(run, 3600)
    heartbeat.recover_stuck_runs()

    assert run_state(run) == "pending", (
        "an hour is not yet long enough for the backstop -- if this now fails, "
        "the window was shortened and docs/orchestration-semantics.md is stale")
    assert not is_free(agent), "the agent is still held, which is the gap"
