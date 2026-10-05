"""Consequential actions: the decision an agent requests and Andyur makes.

Lane A, board rows 7-8. The MVP's differentiated claim is that an untrusted
third-party agent can REQUEST a production change and Andyur decides whether it
happens -- deny, allow, or require a human. The agent never holds the
credential and never performs the action.

Four rules this module exists to keep, each of which was a defect somewhere in
this codebase before it was a rule:

1. THE DECISION IS NAMED, NOT INFERRED. `decision` is a closed vocabulary and
   `decision_reason` names why. Nothing downstream may derive "approval
   required" from a null result.
2. AUTHORITY IS CHECKED WHERE AUTHORITY LIVES. The tool does not check its own
   permission -- a tool that authorises itself can be asked not to. The input
   here is the run's SEALED GRANT (runtoken's `sc`), never the request body,
   the prompt, or anything the model can influence.
3. THE AUTHORITY MUST BE ENUMERATED. `scope is None` means "no scope model is
   active", which the PDP reads as unrestricted for ordinary operations. It is
   NOT read that way here: a consequential production change requires a grant
   that names it. Otherwise every run in every deployment that has never used
   scopes would silently acquire the ability to roll back production the moment
   this module ships, which is a security regression delivered as a feature.
4. A RESULT IS AN OBSERVATION. `succeeded` means the cluster was read back and
   found changed, not that a dispatch returned 200. That half lives in
   `andyur.rollback`.
"""

from __future__ import annotations

import dataclasses

# The closed decision vocabulary. Anything outside it is a programming error
# rather than a decision, and callers pattern-match on these three.
DENIED = "denied"
ALLOWED = "allowed"
APPROVAL_REQUIRED = "approval_required"
DECISIONS = frozenset({DENIED, ALLOWED, APPROVAL_REQUIRED})

# Why, by name. Free text here would be the same defect as a free-text span
# attribute: unbounded, caller-influenced, and useless to aggregate.
REASON_NO_WRITE_AUTHORITY = "no_write_authority"
REASON_POLICY_DENIED = "policy_denied"
REASON_TARGET_NOT_PINNED = "target_not_pinned"
REASON_WRITE_AUTHORIZED = "write_authorized"
REASON_APPROVAL_POLICY = "approval_policy"
REASON_APPROVED = "approved"
REASON_RUN_INACTIVE = "run_inactive"
REASON_WORKFLOW_HALTED = "workflow_halted"
REASON_GRANT_EXPIRED = "grant_expired"
REASON_AUTHORITY_MISSING = "authority_missing"
REASONS = frozenset({REASON_NO_WRITE_AUTHORITY, REASON_POLICY_DENIED,
                     REASON_TARGET_NOT_PINNED, REASON_WRITE_AUTHORIZED,
                     REASON_APPROVAL_POLICY, REASON_APPROVED,
                     REASON_RUN_INACTIVE, REASON_WORKFLOW_HALTED,
                     REASON_GRANT_EXPIRED, REASON_AUTHORITY_MISSING})

# Results. `not_attempted` is a first-class outcome, not an absence: a denied
# request has a definite result and the console must not have to infer it.
SUCCEEDED = "succeeded"
FAILED = "failed"
NOT_ATTEMPTED = "not_attempted"
RESULTS = frozenset({SUCCEEDED, FAILED, NOT_ATTEMPTED})

# The one remediation this MVP admits. Not a family, not a generic executor: a
# generic `kubectl` passthrough would smuggle every other remediation in behind
# one grant, and the freeze plan names AWS, Datadog and ServiceNow as out.
ROLLBACK_DEPLOYMENT = "rollback_deployment"
TOOLS = frozenset({ROLLBACK_DEPLOYMENT})

# THE TWO GRANT TERMS, in the platform's existing scope vocabulary (`files:read`,
# `files:write`): one authority that may be exercised, and one that may only be
# exercised with a human's consent.
#
# Approval is expressed as a DIFFERENT GRANT rather than as a second input,
# because then the whole decision is a function of the one thing the agent
# cannot influence -- the authority sealed into the run at admission. A separate
# "does this need approval?" input would be a second source of truth about the
# same run, and the two would eventually disagree.
SCOPE_ROLLBACK = "deployments:rollback"
SCOPE_ROLLBACK_WITH_APPROVAL = "deployments:rollback:with-approval"

# The grant each tool requires, unconditional first. Kept beside the tool rather
# than inside it, so the check cannot be skipped by the thing being checked.
TOOL_GRANTS = {
    ROLLBACK_DEPLOYMENT: (SCOPE_ROLLBACK, SCOPE_ROLLBACK_WITH_APPROVAL),
}

# The pin keys a rollback target must be named by. The pin is `subject_context`
# on the run: sealed at creation, carried in the signed grant, never re-read
# from the prompt and never accepted from the model.
PIN_NAMESPACE = "namespace"
PIN_DEPLOYMENT = "deployment"


@dataclasses.dataclass(frozen=True)
class Decision:
    """What Andyur decided about one requested action, and why."""

    decision: str
    reason: str

    def __post_init__(self):
        if self.decision not in DECISIONS:
            raise ValueError(f"decision {self.decision!r} outside the closed set")
        if self.reason not in REASONS:
            raise ValueError(f"reason {self.reason!r} outside the closed set")


def grant_in_effect(tool: str, granted_scope) -> str | None:
    """WHICH of this tool's grants the run actually holds, or None.

    This is the term the PDP is asked about, and asking about the term IN EFFECT
    rather than about the unconditional one is the difference between a working
    approval outcome and a policy engine that denies every approval-gated run:
    the question is "may this run exercise the authority it holds", not "does it
    hold the strongest authority that exists".

    The unconditional grant wins when both are held -- a condition added to an
    authority cannot subtract from one already given without one.
    """
    if tool not in TOOLS:
        raise ValueError(f"tool {tool!r} is not a consequential action this MVP admits")
    held = set(granted_scope or ())
    for term in TOOL_GRANTS[tool]:
        if term in held:
            return term
    return None


def decide(tool: str, granted_scope, *, policy_permits: bool = True) -> Decision:
    """Decide one requested action from the run's OWN sealed authority.

    `granted_scope` is what the run holds, from the authority narrowed at
    admission and carried in the signed grant -- never from the request, never
    from the model, never from the prompt. That is the whole point: the agent
    asks, and something it cannot influence answers.

    `policy_permits` is the PDP's answer to "may this run perform this action".
    It can only NARROW: a policy engine that says yes cannot supply an authority
    the grant does not enumerate, and one that says no (including because it was
    unreachable, which `pdp` reads as a denial) refuses outright.

    THE ORDER IS DELIBERATE. Authority is checked FIRST, so a run with no
    rollback grant is denied outright rather than queued for an approval that
    could never make it legitimate. Approval is a second gate on an action the
    run is otherwise entitled to perform, not a way to acquire entitlement it
    was never granted -- otherwise an operator clicking approve would be
    GRANTING authority rather than consenting to its use.
    """
    if tool not in TOOLS:
        raise ValueError(f"tool {tool!r} is not a consequential action this MVP admits")
    unconditional, with_approval = TOOL_GRANTS[tool]
    # Rule 3: an ABSENT scope model is not an authority. `set(None or ())` is
    # empty, so a run with no scope, an empty scope, or a scope naming something
    # else all reach the same denial by the same path.
    held = set(granted_scope or ())
    if unconditional not in held and with_approval not in held:
        return Decision(DENIED, REASON_NO_WRITE_AUTHORITY)
    if not policy_permits:
        return Decision(DENIED, REASON_POLICY_DENIED)
    if unconditional in held:
        # Holding both terms is the stronger grant: the conditional one adds a
        # condition to an authority, and cannot subtract from one already given
        # unconditionally.
        return Decision(ALLOWED, REASON_WRITE_AUTHORIZED)
    return Decision(APPROVAL_REQUIRED, REASON_APPROVAL_POLICY)


def target_is_pinned(pin, namespace: str, deployment: str) -> bool:
    """Is the requested target the resource this run was pinned to?

    The pin (`subject_context`) is WHAT the work is about. It is sealed at
    creation and travels in the signed grant, so a run cannot be retargeted by
    anything it reads -- which is exactly the property a consequential action
    needs: an agent that ingests a malicious page still cannot aim the rollback
    at a deployment its grant does not name.

    An UNPINNED run fails this. Elsewhere in the platform an absent pin grants
    no narrowing and denies nothing, because denying on absence would break
    every existing run. Here there are no existing runs to break, and the freeze
    plan's scope is one deployment rollback against ONE PINNED RESOURCE -- so
    absence is refused rather than waved through.
    """
    if not isinstance(pin, dict):
        return False
    return (pin.get(PIN_NAMESPACE) == namespace
            and pin.get(PIN_DEPLOYMENT) == deployment)


def canonical_target(namespace: str, deployment: str) -> str:
    """`namespace/deployment`, validated, because this string names what gets
    rolled back and it arrives from an agent.

    Refused rather than sanitised: a target that needs cleaning is a target
    nobody reviewed. The charset is Kubernetes' own name charset, so anything
    outside it could not have named a real object anyway.
    """
    for part, label in ((namespace, "namespace"), (deployment, "deployment")):
        if not part or len(part) > 253:
            raise ValueError(f"{label} must be 1..253 characters")
        if not all(c.islower() or c.isdigit() or c in "-." for c in part):
            raise ValueError(
                f"{label} {part!r} is not a valid Kubernetes name: lowercase "
                "alphanumerics, '-' and '.' only")
    return f"{namespace}/{deployment}"


def split_target(target: str) -> tuple[str, str]:
    """The inverse of `canonical_target`, re-validated on the way out.

    The stored target is re-parsed rather than trusted when the approval path
    executes it, because between the request and the approval it has been at
    rest in a database, and a value read back from storage is an input again.
    """
    namespace, _, deployment = target.partition("/")
    canonical_target(namespace, deployment)
    return namespace, deployment
