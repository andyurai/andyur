"""Work handed to a busy agent, and the re-drive that comes back for it.

Delegation and messaging wake their target BEST-EFFORT: handing work to a busy
agent is normal, the wakeup is refused, and the work sits durable until
something comes back for it. That "something" is the drain, and it is the
mechanism with the most subtle contract in the whole engine, because both
failure directions are bad:

    never re-driven   an agent that only runs when delegated to sits idle
                      beside its own work indefinitely
    always re-driven  an agent that cannot complete a task is woken every
                      tick forever, burning a slot and a model budget each time

The native engine resolves this by stamping each item the moment it is OFFERED
to a run, and re-driving only unstamped work. That stamp is mechanism. The
EXACTLY-ONCE OFFER it produces is contract, and it is what these tests pin.

The distinction matters for a durable provider because the obvious alternative
-- "wake the agent if it has work newer than its last run" -- is a timestamp
comparison, and it is wrong: the clock's granularity cannot represent the
difference between a task and the run woken for it, so every tie must be
resolved as either dropping the work or waking forever.
"""

from andyur import db
from andyur.server import coordinator, heartbeat, messages, tasks

from .conftest import authority_of, is_free, live_run_of


def _runs_of(agent: str) -> int:
    with db.connect() as c:
        return c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = ?", (agent,)).fetchone()["n"]


# --- work that arrives for a busy agent is not lost -------------------------

def test_a_task_for_a_busy_agent_is_driven_once_it_frees_up(two_agents):
    alice, bob = two_agents
    occupying = coordinator.maybe_wakeup(bob, "already busy")
    tasks.create_task(assignee=bob, creator=alice, title="do the thing")
    assert live_run_of(bob) == occupying, "precondition: bob should still be busy"

    coordinator.finish_run(occupying, "done", None)
    heartbeat.drain_pending_work()

    assert live_run_of(bob) is not None, "the deferred task was never re-driven"


def test_an_unread_message_also_drives_a_run(two_agents):
    alice, bob = two_agents
    occupying = coordinator.maybe_wakeup(bob, "already busy")
    messages.send_message(recipient=bob, sender=alice, body="please look")

    coordinator.finish_run(occupying, "done", None)
    heartbeat.drain_pending_work()

    assert live_run_of(bob) is not None, "an unread message did not drive a run"


def test_an_agent_that_has_never_run_is_still_driven(two_agents):
    """The case the drain exists for: an agent with no schedule that is only
    ever delegated to. Nothing else would ever come back for its work."""
    alice, bob = two_agents
    tasks.create_task(assignee=bob, creator=alice, title="the only thing")

    # The best-effort wakeup at creation time already took it, which is the
    # happy path; the drain must not then produce a SECOND run for it.
    admitted = live_run_of(bob)
    assert admitted is not None, "the creation-time wakeup should have taken it"
    coordinator.start_run(admitted)
    before = _runs_of(bob)

    heartbeat.drain_pending_work()

    assert _runs_of(bob) == before, "the drain duplicated an offer already made"


# --- the offer is exactly once ----------------------------------------------

def test_the_drain_does_not_become_a_treadmill(two_agents):
    """An agent that never completes its task must not be woken forever. This
    is the property that bounds the drain's cost, and the one an
    at-least-once provider is most likely to break."""
    alice, bob = two_agents
    occupying = coordinator.maybe_wakeup(bob, "already busy")
    tasks.create_task(assignee=bob, creator=alice, title="never completed")
    coordinator.finish_run(occupying, "done", None)

    heartbeat.drain_pending_work()
    driven = live_run_of(bob)
    assert driven is not None
    coordinator.start_run(driven)          # the run renders the queue: one offer
    coordinator.finish_run(driven, "did not finish the task", None)

    for _ in range(5):
        heartbeat.drain_pending_work()

    assert is_free(bob), (
        "the still-open task is re-driving the agent on every tick")


def test_a_second_item_arriving_later_earns_its_own_offer(two_agents):
    """Exactly-once is PER ITEM, not per agent. A provider that marked the
    agent rather than the work would drop everything that arrived after the
    first offer."""
    alice, bob = two_agents
    occupying = coordinator.maybe_wakeup(bob, "already busy")
    tasks.create_task(assignee=bob, creator=alice, title="first")
    coordinator.finish_run(occupying, "done", None)
    heartbeat.drain_pending_work()
    first_run = live_run_of(bob)
    coordinator.start_run(first_run)
    coordinator.finish_run(first_run, "done", None)

    tasks.create_task(assignee=bob, creator=alice, title="second")
    heartbeat.drain_pending_work()

    assert live_run_of(bob) is not None, "the later item never earned an offer"


# --- the drain respects every control that admission respects ---------------

def test_the_drain_does_not_wake_a_paused_agent(two_agents):
    alice, bob = two_agents
    occupying = coordinator.maybe_wakeup(bob, "already busy")
    tasks.create_task(assignee=bob, creator=alice, title="work")
    coordinator.finish_run(occupying, "done", None)
    coordinator.set_paused(bob, True)

    heartbeat.drain_pending_work()

    assert is_free(bob), "the drain woke a paused agent"


def test_the_drain_does_not_undo_the_kill_switch(two_agents):
    """The drain is a second path to admission, so every control that guards
    the first must guard it too. A halt that the drain could undo would be no
    halt at all -- and this is exactly the shape of bug a new dispatch path
    introduces."""
    alice, bob = two_agents
    root = coordinator.maybe_wakeup(alice, "root")
    workflow = authority_of(root)["workflow"]
    tasks.create_task(assignee=bob, creator=alice, title="work", parent_run_id=root)

    coordinator.halt_workflow(workflow)
    heartbeat.drain_pending_work()

    assert is_free(bob), "the drain re-drove work from a halted workflow"


def test_the_drain_does_not_wake_a_busy_agent(two_agents):
    alice, bob = two_agents
    occupying = coordinator.maybe_wakeup(bob, "already busy")
    tasks.create_task(assignee=bob, creator=alice, title="work")

    heartbeat.drain_pending_work()

    assert live_run_of(bob) == occupying, "the drain displaced a live run"


# --- a drained run carries the authority of the work that caused it ---------

def test_a_drained_run_joins_the_workflow_of_the_work_that_caused_it(two_agents):
    """The drain mints a run with no parent to inherit from, so the authority
    has to be carried across explicitly. A run that joined a FRESH workflow
    here would get a fresh work-item budget and a reset delegation depth --
    which is the more permissive of the two possible mistakes, and therefore
    the one to pin."""
    alice, bob = two_agents
    root = coordinator.maybe_wakeup(alice, "root")
    workflow = authority_of(root)["workflow"]
    occupying = coordinator.maybe_wakeup(bob, "busy")
    tasks.create_task(assignee=bob, creator=alice, title="work", parent_run_id=root)
    coordinator.finish_run(occupying, "done", None)

    heartbeat.drain_pending_work()

    drained = live_run_of(bob)
    assert drained is not None
    assert authority_of(drained)["workflow"] == workflow, (
        "the drained run started a fresh workflow, resetting its budget and depth")


def test_a_drained_run_does_not_reset_the_delegation_depth(two_agents):
    """Depth must not fall back to zero on the drain path. An agent could
    otherwise reset the cap on demand simply by delegating to an assignee it
    keeps busy."""
    alice, bob = two_agents
    root = coordinator.maybe_wakeup(alice, "root")
    occupying = coordinator.maybe_wakeup(bob, "busy")
    tasks.create_task(assignee=bob, creator=alice, title="work", parent_run_id=root)
    coordinator.finish_run(occupying, "done", None)

    heartbeat.drain_pending_work()

    drained = live_run_of(bob)
    assert authority_of(drained)["depth"] > authority_of(root)["depth"], (
        "the drained run rejoined at or above its parent's depth")


def test_the_offer_is_consumed_when_the_run_starts_not_when_it_is_admitted(two_agents):
    """CHARACTERIZATION OF THE EXACT MOMENT, because a provider will have to
    pick one and the two are not interchangeable.

    A run is the offer of an agent's whole waiting queue, and the queue is
    rendered into the prompt when the run STARTS. So that is when the work is
    marked as offered -- not when the run is admitted.

    The difference is the failure case: a run admitted and then lost before it
    ever started never showed the agent anything, so its work must still be
    re-drivable. A provider that marked the work at admission would silently
    drop exactly the items belonging to runs its own dispatch failed to
    deliver -- and it would look correct in every test where dispatch worked.
    """
    alice, bob = two_agents
    occupying = coordinator.maybe_wakeup(bob, "already busy")
    tasks.create_task(assignee=bob, creator=alice, title="work")
    coordinator.finish_run(occupying, "done", None)

    heartbeat.drain_pending_work()
    admitted = live_run_of(bob)
    assert admitted is not None

    # lost before it ever ran: admitted, never started
    coordinator.finish_run(admitted, None, "the executor died before starting")

    heartbeat.drain_pending_work()

    assert live_run_of(bob) is not None, (
        "work belonging to a run that never started was treated as delivered")


def test_work_arriving_after_a_run_starts_waits_for_the_next_one(two_agents):
    """The other half of the same rule. The prompt was already built, so work
    that arrives mid-run cannot have been shown to the agent -- it stays
    unstamped and is re-driven once the run ends."""
    alice, bob = two_agents
    first = coordinator.maybe_wakeup(bob, "a run of its own")
    coordinator.start_run(first)

    tasks.create_task(assignee=bob, creator=alice, title="arrived mid-run")
    coordinator.finish_run(first, "done", None)

    heartbeat.drain_pending_work()

    assert live_run_of(bob) is not None, (
        "work that arrived after the prompt was built was treated as delivered")
