"""Admission: who may hold a run, and who is refused.

Admission is the contract's foundation, and it is the one part a provider may
NOT simply reimplement in its own idiom. Andyur decides whether work is admitted
-- the provider orchestrates work that has already been admitted. A provider
that admits a second run for a busy agent has not been merely inefficient; it
has produced two live identities for one agent.
"""

from andyur.server import coordinator

from .conftest import is_free, live_run_of, live_runs_of, run_state


# --- an idle agent is admitted ----------------------------------------------



def test_admitting_an_idle_agent_returns_a_run_that_holds_it(agent):
    run = coordinator.maybe_wakeup(agent, "work")

    assert run is not None, "an idle agent must be admissible"
    assert live_run_of(agent) == run, "the admitted run must hold its agent"
    assert not is_free(agent), "an agent holding a run is not free"


def test_an_admitted_run_starts_in_a_non_terminal_state(agent):
    """The provider may call the pre-execution state anything; the contract
    only requires that it is not terminal, because terminal means no further
    work will happen and the run has not run yet."""
    run = coordinator.maybe_wakeup(agent, "work")

    assert run_state(run) not in {"done", "failed", "cancelled"}


# --- a busy agent is refused ------------------------------------------------

def test_a_busy_agent_refuses_a_second_admission(agent):
    first = coordinator.maybe_wakeup(agent, "first")
    second = coordinator.maybe_wakeup(agent, "second")

    assert first is not None
    assert second is None, "two live runs for one agent"
    assert live_run_of(agent) == first, "the refusal must not disturb the holder"


def test_the_refusal_is_a_refusal_not_a_queue(agent):
    """REFUSED, not deferred. This distinction matters to a provider with a
    native queue: the obvious implementation of `maybe_wakeup` on such an engine
    is to enqueue behind the running one, and that would silently convert
    Andyur's 'one live run' into 'one run at a time, backlog unbounded'.

    Work that arrives for a busy agent is re-offered later by the drain, which
    is a different mechanism with its own caps -- see test_deferred_work.py.
    """
    first = coordinator.maybe_wakeup(agent, "first")
    coordinator.maybe_wakeup(agent, "second")
    coordinator.maybe_wakeup(agent, "third")

    assert live_runs_of(agent) == [first]

    coordinator.finish_run(first, "done", None)

    assert is_free(agent), (
        "finishing the only run must free the agent; a provider that queued "
        "the refused admissions would start one here")
    assert live_run_of(agent) is None


# --- a paused agent is refused ----------------------------------------------

def test_a_paused_agent_refuses_admission(agent):
    coordinator.set_paused(agent, True)

    assert coordinator.maybe_wakeup(agent, "work") is None
    assert is_free(agent), "a refused admission must leave no run behind"


def test_unpausing_restores_admission(agent):
    coordinator.set_paused(agent, True)
    coordinator.set_paused(agent, False)

    assert coordinator.maybe_wakeup(agent, "work") is not None


def test_pausing_releases_an_agent_that_had_not_started(agent):
    """Pause is an operator control, so it must take effect against work that
    is already admitted but not yet executing -- otherwise 'pause' means 'pause
    eventually' and an operator cannot use it to stop anything."""
    run = coordinator.maybe_wakeup(agent, "work")
    assert run is not None

    coordinator.set_paused(agent, True)

    assert run_state(run) in {"done", "failed", "cancelled"}, (
        "a pause must resolve the un-started run rather than leave it pending")
    assert is_free(agent)


# --- at most one live run per agent, however it is reached ------------------

def test_repeated_admission_attempts_yield_exactly_one_live_run(agent):
    """The invariant stated as the provider must guarantee it, rather than as
    the native engine happens to enforce it.

    The native provider gets this from a partial unique index -- the database
    decides the race, and `tests/test_agent_claim.py` pins that mechanism
    directly. A provider without that primitive must reach the same outcome
    some other way; this is the assertion it has to satisfy.
    """
    admitted = [coordinator.maybe_wakeup(agent, f"attempt-{i}") for i in range(8)]
    granted = [r for r in admitted if r is not None]

    assert len(granted) == 1, f"{len(granted)} admissions granted, expected 1"
    assert live_runs_of(agent) == granted


def test_admission_is_per_agent_not_global(two_agents):
    """One busy agent must not block another. A provider backed by a single
    serialised work queue could accidentally make admission global."""
    alice, bob = two_agents

    alice_run = coordinator.maybe_wakeup(alice, "work")
    bob_run = coordinator.maybe_wakeup(bob, "work")

    assert alice_run is not None
    assert bob_run is not None, "bob was refused because alice was busy"
    assert live_run_of(alice) == alice_run
    assert live_run_of(bob) == bob_run


def test_a_terminal_run_does_not_hold_its_agent(agent):
    """Every terminal state frees the agent. A provider that treats only its own
    notion of success as terminal would strand agents on failures."""
    for outcome in ("done", "failed"):
        run = coordinator.maybe_wakeup(agent, outcome)
        assert run is not None, f"agent was not free before the {outcome} case"
        coordinator.finish_run(
            run, "summary" if outcome == "done" else None,
            None if outcome == "done" else "it failed")

        assert run_state(run) == outcome
        assert is_free(agent), f"a {outcome} run still holds its agent"
