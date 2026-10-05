"""What a run is allowed to be, and what it inherits from the run that asked
for it.

THIS IS THE MODULE THAT MUST NOT MOVE. Timers, dispatch and retries can all be
handed to a provider and the worst case is latency. The properties below decide
who a run acts for and what it may reach, and the worst case is authority that
was never granted.

Section 4.2 of the refactor plan draws the line: the provider decides WHEN work
progresses, never WHETHER the actor is authorized. Everything here is on
Andyur's side of that line, so a provider should be able to reproduce none of it
-- it should be calling into this, not reimplementing it. The tests exist so
that a future facade cannot quietly relocate one of these decisions into
provider code, where it would be replayed from durable history rather than
re-decided against the current state.
"""

import pytest

from andyur import db
from andyur.server import coordinator

from .conftest import authority_of


def _row(run_id: str) -> dict:
    with db.connect() as c:
        return dict(c.execute(
            "SELECT workflow_id, depth, acting_user, user_asserted_by, "
            "subject_token FROM runs WHERE id = ?", (run_id,)).fetchone())


@pytest.fixture
def cast(env):
    """Enough agents to build a delegation chain."""
    return [env.agent(f"agent{i}") for i in range(12)]


# --- workflow identity is inherited, and depth counts the chain -------------

def test_a_root_run_seals_a_fresh_workflow_at_depth_zero(agent):
    run = coordinator.maybe_wakeup(agent, "root")

    assert authority_of(run)["workflow"] is not None
    assert authority_of(run)["depth"] == 0


def test_independent_roots_get_distinct_workflows(two_agents):
    alice, bob = two_agents

    a = coordinator.maybe_wakeup(alice, "root")
    b = coordinator.maybe_wakeup(bob, "root")

    assert authority_of(a)["workflow"] != authority_of(b)["workflow"]


def test_a_child_joins_its_parents_workflow_one_level_deeper(cast):
    parent = coordinator.maybe_wakeup(cast[0], "root")
    child = coordinator.maybe_wakeup(cast[1], "child", parent_run_id=parent)

    assert authority_of(child)["workflow"] == authority_of(parent)["workflow"]
    assert authority_of(child)["depth"] == authority_of(parent)["depth"] + 1


def test_an_unknown_parent_is_refused_rather_than_rooted(cast):
    """THE BYPASS THIS CLOSES: falling back to a fresh depth-0 root would let
    any caller reset the delegation depth -- and the work-item budget -- just
    by naming a parent that does not exist. Refusal is the only safe answer,
    because the permissive one is indistinguishable from starting over."""
    run, reason = coordinator.wakeup_or_reason(
        cast[1], "child", parent_run_id="de" * 16)

    assert run is None, "a forged parent produced a run"
    assert reason is not None


def test_the_delegation_chain_is_capped(cast):
    """Depth is bounded, and the bound is enforced at admission rather than by
    anything downstream noticing later."""
    depth = coordinator.MAX_DELEGATION_DEPTH
    chain = [coordinator.maybe_wakeup(cast[0], "root")]
    for i in range(1, depth + 1):
        nxt = coordinator.maybe_wakeup(cast[i], f"hop {i}", parent_run_id=chain[-1])
        assert nxt is not None, f"the chain was refused early, at hop {i}"
        chain.append(nxt)

    assert authority_of(chain[-1])["depth"] == depth

    refused, reason = coordinator.wakeup_or_reason(
        cast[depth + 1], "one hop too far", parent_run_id=chain[-1])

    assert refused is None, "the delegation depth cap did not hold"
    assert reason is not None


# --- the subject: who the run acts for --------------------------------------

def test_a_child_naming_the_same_subject_inherits_the_parents_credential(cast):
    """Delegation for the same person carries that person's credential
    forward. This is the intended path."""
    parent = coordinator.maybe_wakeup(
        cast[0], "root", user="u1", user_asserted_by="idp",
        subject_token="PARENT-CREDENTIAL")
    child = coordinator.maybe_wakeup(
        cast[1], "child", parent_run_id=parent, user="u1")

    assert _row(child)["acting_user"] == "u1"
    assert _row(child)["subject_token"] == "PARENT-CREDENTIAL"


def test_a_delegating_caller_cannot_state_the_provenance_of_its_subject(cast):
    """PROVENANCE IS READ FROM THE PARENT, NEVER FROM THE CALLER.

    If a hop could restate how its subject was established, delegation would be
    a laundering step: a subject nobody authenticated would emerge from one hop
    indistinguishable from a real login. The caller's claim here is deliberately
    a lie, and it must be discarded in favour of the parent's.
    """
    parent = coordinator.maybe_wakeup(
        cast[0], "root", user="u1", user_asserted_by="idp",
        subject_token="PARENT-CREDENTIAL")

    child = coordinator.maybe_wakeup(
        cast[1], "child", parent_run_id=parent, user="u1",
        user_asserted_by="forged-by-the-caller")

    assert _row(child)["user_asserted_by"] == "idp", (
        "a delegating caller successfully stated its own subject provenance")


def test_a_child_naming_a_different_subject_gets_no_credential(cast):
    """FAILS CLOSED, and this is the assertion that actually protects anything.

    A run may end up recording a different acting_user than its parent -- the
    operator-parented case is legitimate. What it must NOT get is the parent's
    credential, because the credential and the identity it is for come from two
    different places and nothing else checks that they name the same person.

    With no token the downstream exchange refuses, which is the right direction
    for a disagreement about whose authority this is.
    """
    parent = coordinator.maybe_wakeup(
        cast[0], "root", user="u1", user_asserted_by="idp",
        subject_token="PARENT-CREDENTIAL")

    child = coordinator.maybe_wakeup(
        cast[1], "child", parent_run_id=parent, user="someone-else")

    assert _row(child)["subject_token"] is None, (
        "a run acting for a different subject was handed the parent's credential")


def test_a_run_acting_for_nobody_holds_nobodys_credential(cast):
    """The operator branch: work parented to a run but belonging to no
    delegated subject. A run acting for nobody must hold nobody's token, and
    must claim no provenance either."""
    parent = coordinator.maybe_wakeup(
        cast[0], "root", user="u1", user_asserted_by="idp",
        subject_token="PARENT-CREDENTIAL")

    child = coordinator.maybe_wakeup(
        cast[1], "operator work", parent_run_id=parent,
        user_asserted_by="claimed-anyway")

    assert _row(child)["acting_user"] is None
    assert _row(child)["subject_token"] is None
    assert _row(child)["user_asserted_by"] is None, (
        "a run with no subject still claimed a subject provenance")


# --- the work-item budget ---------------------------------------------------

def test_a_workflow_is_bounded_in_how_much_live_work_it_may_hold(cast, monkeypatch):
    """Fan-out is bounded per workflow. The cap counts live runs alongside open
    tasks and unread messages, so an agent cannot widen its reach by choosing a
    different channel.

    Patched down to something a test can reach; the production value is far
    higher and is not what this asserts. What it asserts is that the budget
    exists, is per workflow, and refuses at admission.
    """
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 3)

    root = coordinator.maybe_wakeup(cast[0], "root")
    workflow = authority_of(root)["workflow"]

    admitted = [root]
    for i in range(1, 3):
        run = coordinator.maybe_wakeup(cast[i], f"sibling {i}", parent_run_id=root)
        if run:
            admitted.append(run)

    refused, reason = coordinator.wakeup_or_reason(
        cast[5], "past the budget", parent_run_id=root)

    assert refused is None, (
        f"the work-item cap did not hold: {len(admitted)} admitted under a cap of 3")
    assert reason is not None


def test_the_budget_is_per_workflow_not_global(cast, monkeypatch):
    """One workflow exhausting its budget must not stop an unrelated one. A
    provider backed by a single shared queue could easily make this global."""
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 2)

    root = coordinator.maybe_wakeup(cast[0], "root")
    coordinator.maybe_wakeup(cast[1], "sibling", parent_run_id=root)
    exhausted, _ = coordinator.wakeup_or_reason(cast[2], "over", parent_run_id=root)
    assert exhausted is None, "precondition: the first workflow should be at its cap"

    other = coordinator.maybe_wakeup(cast[3], "an unrelated root")

    assert other is not None, "one workflow's budget blocked another's"
    assert authority_of(other)["workflow"] != authority_of(root)["workflow"]


def test_terminal_runs_stop_counting_against_the_budget(cast, monkeypatch):
    """The budget bounds work IN FLIGHT. If finished runs kept counting, a
    long-lived workflow would eventually be unable to do anything."""
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 2)

    root = coordinator.maybe_wakeup(cast[0], "root")
    sibling = coordinator.maybe_wakeup(cast[1], "sibling", parent_run_id=root)
    assert coordinator.wakeup_or_reason(cast[2], "over", parent_run_id=root)[0] is None

    coordinator.finish_run(sibling, "done", None)

    assert coordinator.maybe_wakeup(cast[2], "now there is room", parent_run_id=root) \
        is not None, "a finished run kept occupying the workflow's budget"


def test_a_run_can_belong_to_no_workflow_at_all(env):
    """CHARACTERIZATION MISSED IN THE FIRST PASS, and it cost a 404 on
    `POST /tasks`.

    `resolve_workflow` inherits the parent's workflow, so a run parented to one
    that has none gets none either. The platform tolerates this on purpose --
    `assign_runs` carries an explicit `workflow_id IS NULL` branch, because a
    run belonging to no workflow cannot be halted by one.

    Nothing said so anywhere, so the orchestration facade assumed every run had
    a workflow and refused the ones that do not.
    """
    from andyur import db

    env.agent("boss")
    env.agent("worker")
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at) "
            "VALUES ('run-boss', 'boss', 'running', ?)", (db.utcnow(),))

    child = coordinator.maybe_wakeup("worker", "child", parent_run_id="run-boss")

    assert child is not None, "a run with a workflow-less parent was refused"
    assert authority_of(child)["workflow"] is None
