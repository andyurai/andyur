"""The life of one run: start, finish, fail, and the reaper that ends the ones
that never report.

The transitions here are the part a durable-execution engine is genuinely good
at, and therefore the part most likely to be handed over wholesale. What must
survive that handover is not the transition names but the GUARDS: a run may
start once, may finish once, and an agent is freed exactly once. A provider with
at-least-once delivery will call these more than once, and the contract is that
the extra calls are refused rather than applied.
"""

from datetime import datetime, timedelta, timezone

from andyur import db
from andyur.server import coordinator, heartbeat

from .conftest import is_free, live_run_of, run_state


def _backdate_start(run_id: str, seconds: int) -> None:
    """Make a run look as though it started `seconds` ago.

    Time travel by editing the record, because the alternative is a test that
    sleeps for seventeen minutes. This touches the provider's own bookkeeping
    and so is the one helper here that a second provider would reimplement.
    """
    when = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with db.connect() as c:
        c.execute("UPDATE runs SET started_at = ? WHERE id = ?", (when, run_id))


# --- starting ---------------------------------------------------------------

def test_a_run_starts_once(agent):
    run = coordinator.maybe_wakeup(agent, "work")

    assert coordinator.start_run(run) is True
    assert run_state(run) == "running"


def test_starting_an_already_started_run_is_refused(agent):
    """At-least-once dispatch is normal for a durable engine. The second
    delivery must not re-start the run, because start is where the run's clock
    is armed and its identity is minted."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)

    assert coordinator.start_run(run) is False, "a run started twice"
    assert run_state(run) == "running"


def test_starting_a_finished_run_is_refused(agent):
    """A late start after a finish would resurrect a terminal run -- and with
    it, an agent that something else may already have claimed."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)
    coordinator.finish_run(run, "done", None)

    assert coordinator.start_run(run) is False
    assert run_state(run) == "done"


# --- finishing --------------------------------------------------------------

def test_a_clean_finish_is_done_and_frees_the_agent(agent):
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)

    assert coordinator.finish_run(run, "the summary", None) is True
    assert run_state(run) == "done"
    assert is_free(agent)


def test_an_error_finish_is_failed_and_still_frees_the_agent(agent):
    """Failure must free the agent just as success does. The asymmetry is a
    classic engine bug: the happy path releases the lease, the error path
    leaves it held."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)

    assert coordinator.finish_run(run, None, "it went wrong") is True
    assert run_state(run) == "failed"
    assert is_free(agent)


def test_the_presence_of_an_error_is_what_decides_failed(agent):
    """One decider, in one place. The native engine derives `failed` from the
    presence of an error and nothing else; a provider that also forms an
    opinion from its own activity outcome would be a second decider, and the
    two will eventually disagree."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)
    coordinator.finish_run(run, "a summary was still produced", "but it errored")

    assert run_state(run) == "failed"


def test_finishing_twice_is_refused(agent):
    """Idempotency stated as the contract needs it: the SECOND finish is a
    no-op that reports it did nothing, so a provider retrying an ambiguous
    completion cannot overwrite the recorded outcome."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)
    coordinator.finish_run(run, "first", None)

    assert coordinator.finish_run(run, None, "second") is False
    assert run_state(run) == "done", "a retry rewrote a terminal outcome"


def test_a_run_may_finish_without_ever_starting(agent):
    """Admitted, then finished, with no start. A run that could never be
    dispatched still has to be endable -- see the cancellation section
    below for why this matters more than it looks."""
    run = coordinator.maybe_wakeup(agent, "work")

    assert coordinator.finish_run(run, None, "never dispatched") is True
    assert run_state(run) == "failed"
    assert is_free(agent)


# --- cancellation, as it actually exists today ------------------------------

def test_halting_the_workflow_cancels_an_un_started_run(agent):
    """One of exactly two ways a live run reaches `cancelled` today."""
    run = coordinator.maybe_wakeup(agent, "work")
    with db.connect() as c:
        workflow = c.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (run,)).fetchone()["workflow_id"]

    coordinator.halt_workflow(workflow)

    assert run_state(run) == "cancelled"
    assert is_free(agent)


def test_pausing_the_agent_cancels_an_un_started_run(agent):
    """The other of the two."""
    run = coordinator.maybe_wakeup(agent, "work")

    coordinator.set_paused(agent, True)

    assert run_state(run) == "cancelled"
    assert is_free(agent)


def test_there_is_no_direct_cancel_for_a_single_pending_run(agent):
    """CHARACTERIZATION OF A KNOWN GAP, not an endorsement of it.

    Andyur has no "cancel this run" entry point. A run that can never be
    dispatched is released only by halting its whole workflow or by pausing its
    agent -- both of which are blunter than the situation calls for, because
    both affect more than the one run.

    This is recorded here rather than fixed because Stage 1 changes no
    behaviour. It is also the single clearest thing a durable-execution provider
    would give Andyur for free, so the contract should state the current
    position precisely enough that the improvement is visible when it lands.

    The assertion is deliberately about the SHAPE of the API, so it fails the
    day a direct cancel is added and this text has to be rewritten.
    """
    assert not hasattr(coordinator, "cancel_run"), (
        "a direct cancel now exists -- update this contract and the gap note "
        "in docs/orchestration-semantics.md")

    run = coordinator.maybe_wakeup(agent, "work")
    assert live_run_of(agent) == run

    # The blunt instruments, and their collateral: pausing to release one run
    # also stops the agent taking any other work until it is unpaused.
    coordinator.set_paused(agent, True)
    assert run_state(run) == "cancelled"
    assert coordinator.maybe_wakeup(agent, "unrelated") is None, (
        "releasing one run left the agent unable to accept any other")

    coordinator.set_paused(agent, False)
    assert coordinator.maybe_wakeup(agent, "unrelated") is not None


# --- the reaper -------------------------------------------------------------

def test_a_run_past_its_deadline_is_reaped(agent):
    """A started run whose executor never reported must not hold its agent
    forever. Every provider needs an equivalent; what the contract fixes is
    that the outcome is terminal AND the agent comes back."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)
    _backdate_start(run, 4000)

    heartbeat.recover_stuck_runs()

    assert run_state(run) in {"done", "failed"}
    assert is_free(agent)


def test_a_fresh_run_is_not_reaped(agent):
    """The negative control. A reaper that collects healthy runs is worse than
    no reaper."""
    run = coordinator.maybe_wakeup(agent, "work")
    coordinator.start_run(run)

    heartbeat.recover_stuck_runs()

    assert run_state(run) == "running"
    assert not is_free(agent)


def test_an_un_started_run_is_not_the_deadline_reapers_business(agent):
    """A run that never started has no deadline to be past. This is the case
    that becomes interesting under a provider with its own dispatch: the run is
    admitted, the provider has not picked it up, and the deadline reaper must
    not treat that as a hung execution."""
    run = coordinator.maybe_wakeup(agent, "work")

    heartbeat.recover_stuck_runs()

    assert run_state(run) == "pending"
