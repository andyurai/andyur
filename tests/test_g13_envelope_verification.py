"""Independent verification of the delegation-authority-envelope fix (gap-11a).

The drain-scope fix (a deferred TASK carries acting_user+scope) has its own test
in test_work_drain.py. These close the two properties that fix left unverified:

  1. a deferred MESSAGE carries the sender's user AND scope onto the woken run
     -- the MED finding was that messages carried a subject_token but NULL
     acting_user/scope, so a message-woken run acted unattributed and, at the
     internal PDP, unrestricted (scope None -> every require_scope passes).
  2. the multi-authority guard: an agent holding waiting work under more than
     one distinct delegated authority is NOT drained, because no single woken
     run can be correct for all of them. New fail-closed code with no test.

Written by session A as the end-to-end verification of session B's fix
(commit aac7771), per the operator's G13 assignment.
"""

import json

from andyur import db
from andyur.server import coordinator, heartbeat, messages, tasks


def _pending_run(agent: str):
    with db.connect() as c:
        return c.execute(
            "SELECT acting_user, scope FROM runs WHERE agent = ? "
            "AND state = 'pending'", (agent,)).fetchone()


def _live_count(agent: str) -> int:
    with db.connect() as c:
        return c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = ? "
            "AND state IN ('pending', 'running')", (agent,)).fetchone()["n"]


def test_a_deferred_message_carries_the_senders_user_and_scope(env):
    """The MED finding, directly: a message delivered to a busy agent and later
    drained must wake a run that acts FOR the sender's user, bounded to the
    sender's scope -- not acting_user=NULL / scope=NULL (unrestricted at PDP)."""
    env.agent("scout")
    env.agent("sender")
    coordinator.maybe_wakeup("scout", "already working")     # scout is busy
    messages.send_message(
        "scout", "sender", "look at this",
        deleg_user="alice", deleg_scope=["obs:read"])
    env.set_idle("scout")

    assert heartbeat.drain_pending_work()
    run = _pending_run("scout")
    assert run["acting_user"] == "alice", "message-woken run acts for no one"
    assert json.loads(run["scope"]) == ["obs:read"], "message dropped the scope"


def test_an_immediately_delivered_message_carries_the_senders_user_and_scope(env):
    """The other message path: when the recipient is IDLE, send_message's own
    wakeup creates the run directly. That run must carry attribution too, so the
    envelope holds whether the message is delivered live or deferred."""
    env.agent("idle_scout")
    env.agent("sender")
    messages.send_message(
        "idle_scout", "sender", "handle this now",
        deleg_user="alice", deleg_scope=["obs:read"])

    run = _pending_run("idle_scout")
    assert run is not None, "an idle recipient should have been woken immediately"
    assert run["acting_user"] == "alice"
    assert json.loads(run["scope"]) == ["obs:read"]


def test_an_agent_holding_two_delegated_authorities_is_not_drained(env):
    """The multi-authority guard: two waiting items under different (user, scope)
    authorities have no single correct woken run, so the drain must refuse
    rather than pick one and let the other's work run under the wrong authority."""
    env.agent("helper")
    env.agent("alice_boss")
    env.agent("bob_boss")
    coordinator.maybe_wakeup("helper", "already working")    # helper is busy
    tasks.create_task("helper", "alice_boss", "for alice",
                      deleg_user="alice", deleg_scope=["obs:read"])
    tasks.create_task("helper", "bob_boss", "for bob",
                      deleg_user="bob", deleg_scope=["tickets:write"])
    env.set_idle("helper")

    actions = heartbeat.drain_pending_work()
    assert any("different delegated authorities" in a for a in actions), \
        f"the two-authority case was not recognised: {actions}"
    assert _live_count("helper") == 0, \
        "drained an agent holding two different delegated authorities"


def test_one_authority_across_several_items_still_drains(env):
    """Positive control: the guard must refuse only genuine ambiguity. Two items
    under the SAME (user, scope) are one authority and must still be driven --
    otherwise the guard would be a denial-of-service on ordinary fan-in."""
    env.agent("worker")
    env.agent("boss")
    coordinator.maybe_wakeup("worker", "already working")
    tasks.create_task("worker", "boss", "first",
                      deleg_user="alice", deleg_scope=["obs:read"])
    tasks.create_task("worker", "boss", "second",
                      deleg_user="alice", deleg_scope=["obs:read"])
    env.set_idle("worker")

    assert any("worker" in a for a in heartbeat.drain_pending_work())
    run = _pending_run("worker")
    assert run["acting_user"] == "alice"
    assert json.loads(run["scope"]) == ["obs:read"]
