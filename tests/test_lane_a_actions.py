"""The consequential-action decision, at its edges.

Board rows 7-8. The MVP's differentiated claim is that Andyur decides whether an
agent's requested production change happens. These test the decision itself --
the three outcomes, and the properties that make them meaningful rather than
decorative.
"""

import pytest

from andyur import actions


# --- the three outcomes the demo must prove ------------------------------

ROLLBACK = actions.SCOPE_ROLLBACK
WITH_APPROVAL = actions.SCOPE_ROLLBACK_WITH_APPROVAL


def test_read_only_authority_is_denied():
    d = actions.decide(actions.ROLLBACK_DEPLOYMENT, ["files:read"])
    assert d.decision == actions.DENIED
    assert d.reason == actions.REASON_NO_WRITE_AUTHORITY


def test_write_authority_is_allowed():
    d = actions.decide(actions.ROLLBACK_DEPLOYMENT, ["files:read", ROLLBACK])
    assert d.decision == actions.ALLOWED
    assert d.reason == actions.REASON_WRITE_AUTHORIZED


def test_approval_policy_holds_an_otherwise_allowed_action():
    d = actions.decide(actions.ROLLBACK_DEPLOYMENT, ["files:read", WITH_APPROVAL])
    assert d.decision == actions.APPROVAL_REQUIRED
    assert d.reason == actions.REASON_APPROVAL_POLICY


# --- the properties that make those three mean something -----------------

def test_approval_cannot_launder_authority_the_run_never_had():
    """THE ORDER IS THE POINT, and here it is STRUCTURAL rather than
    procedural: approval is a property of a GRANT, so there is no input a
    read-only run could carry that would queue it for approval. An operator
    clicking approve consents to the use of an authority and can never grant
    one."""
    d = actions.decide(actions.ROLLBACK_DEPLOYMENT, ["files:read"])
    assert d.decision == actions.DENIED, "approval laundered missing authority"
    assert d.reason == actions.REASON_NO_WRITE_AUTHORITY


@pytest.mark.parametrize("granted", [
    None, [], ["files:read"], ["execute"], ["admin"], ["*"],
    ["deployments:read"], ["deployments:rollback:other"], ["rollback_deployment"],
])
def test_nothing_but_the_named_grant_authorises_a_rollback(granted):
    """Including `admin` and `*`: authority is the ENUMERATED grant, not a name
    that sounds powerful, and not the absence of a scope model.

    `*` is the sharp one. The PDP reads it as unrestricted for ordinary
    operations and this module deliberately does not, because a wildcard is a
    statement that nobody enumerated the authority -- which is the one thing a
    consequential production change requires."""
    assert actions.decide(actions.ROLLBACK_DEPLOYMENT, granted).decision \
        == actions.DENIED


def test_holding_both_grants_is_the_unconditional_one():
    """A condition added to an authority cannot subtract from one already given
    without it."""
    d = actions.decide(actions.ROLLBACK_DEPLOYMENT, [ROLLBACK, WITH_APPROVAL])
    assert d.decision == actions.ALLOWED


def test_a_policy_denial_narrows_and_never_widens():
    """The PDP is asked about the authority the run HOLDS. It can refuse one
    (including by being unreachable, which `pdp` reads as a refusal), and it
    cannot supply one the grant does not name."""
    held = actions.decide(actions.ROLLBACK_DEPLOYMENT, [ROLLBACK],
                          policy_permits=False)
    assert held.decision == actions.DENIED
    assert held.reason == actions.REASON_POLICY_DENIED
    absent = actions.decide(actions.ROLLBACK_DEPLOYMENT, ["files:read"],
                            policy_permits=True)
    assert absent.reason == actions.REASON_NO_WRITE_AUTHORITY


@pytest.mark.parametrize("scope,expected", [
    ([ROLLBACK], ROLLBACK),
    ([WITH_APPROVAL], WITH_APPROVAL),
    ([WITH_APPROVAL, ROLLBACK], ROLLBACK),
    (["files:read"], None),
    (None, None),
])
def test_the_grant_in_effect_is_the_term_the_pdp_is_asked_about(scope, expected):
    """Asking the PDP about the UNCONDITIONAL grant would deny every
    approval-gated run under the builtin PDP -- the authority it holds is not
    the authority it was asked about. Reproduced before it was fixed."""
    assert actions.grant_in_effect(actions.ROLLBACK_DEPLOYMENT, scope) == expected


def test_an_unknown_tool_is_refused_rather_than_decided():
    """The MVP admits ONE remediation. An unknown tool must not fall through to
    a decision at all -- a generic executor would smuggle every other
    remediation in behind one grant."""
    with pytest.raises(ValueError):
        actions.decide("delete_namespace", [ROLLBACK])
    with pytest.raises(ValueError):
        actions.grant_in_effect("delete_namespace", [ROLLBACK])


def test_the_vocabularies_are_closed():
    """A decision or reason outside the set is a programming error, not a
    decision. Free text here is the same defect as a free-text span attribute:
    unbounded, caller-influenced, useless to aggregate."""
    with pytest.raises(ValueError):
        actions.Decision("probably_fine", actions.REASON_APPROVED)
    with pytest.raises(ValueError):
        actions.Decision(actions.ALLOWED, "seemed reasonable")


def test_every_decision_and_reason_is_declared_in_the_observability_vocabulary():
    """The contract says a reason "lands in observability.py's closed sets in
    the same change that emits it". This is that sentence as a test: the metric
    boundary RAISES on an undeclared value, and `try_record_metric` SWALLOWS
    that -- so without this, a name added here and nowhere else would silently
    emit no telemetry at all, which is the quietest possible false green."""
    from andyur import observability
    for decision in actions.DECISIONS:
        for reason in actions.REASONS:
            observability.metric_attributes(andyur__action_decision=decision,
                                            andyur__action_reason=reason)
    for result in actions.RESULTS:
        observability.metric_attributes(andyur__action_result=result)
    with pytest.raises(ValueError):
        observability.metric_attributes(andyur__action_decision="probably_fine")


# --- the target is the PINNED resource, or it is refused -----------------

def test_only_the_pinned_resource_can_be_targeted():
    assert actions.target_is_pinned({"namespace": "prod", "deployment": "checkout"},
                                    "prod", "checkout")


@pytest.mark.parametrize("pin", [
    None, {}, {"namespace": "prod"}, {"deployment": "checkout"},
    {"namespace": "staging", "deployment": "checkout"},
    {"namespace": "prod", "deployment": "payments"},
    {"account": "447"},
    "prod/checkout",
])
def test_a_target_the_pin_does_not_name_is_not_pinned(pin):
    """An UNPINNED run fails this too. Elsewhere an absent pin denies nothing,
    because denying on absence would break every existing run; here there are no
    existing runs to break and the scope is one rollback of ONE pinned
    resource."""
    assert not actions.target_is_pinned(pin, "prod", "checkout")


# --- the target names a real object, or is refused -----------------------

def test_a_valid_target_is_canonical():
    assert actions.canonical_target("prod", "checkout") == "prod/checkout"


@pytest.mark.parametrize("ns,dep", [
    ("prod", "checkout; kubectl delete ns prod"),
    ("../../etc", "checkout"),
    ("prod", "Checkout"),
    ("prod", ""),
    ("", "checkout"),
    ("prod", "a" * 254),
])
def test_a_target_that_needs_cleaning_is_refused_not_sanitised(ns, dep):
    """This string names what gets rolled back and it arrives from an agent.
    Refused rather than sanitised: a target that needs cleaning is a target
    nobody reviewed, and anything outside Kubernetes' own name charset could
    not have named a real object anyway."""
    with pytest.raises(ValueError):
        actions.canonical_target(ns, dep)
