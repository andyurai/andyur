"""Agent-to-agent delegation policy (R1, phase 5).

The single place that answers "may agent A hand work (a task or a waking message)
to agent B?" Before R1 this was unauthorized anywhere -- any run could wake any
agent. Now every run-originated task/message to a *different* agent is checked
here.

An allow-list, set by the operator:

    ANDYUR_DELEGATIONS="planner:triage,research; triage:research"

meaning planner may delegate to triage and research, triage may delegate to
research, and every other cross-agent delegation is denied. Self-delegation is
always allowed. The operator (no acting agent) is never restricted.

Why this matters more than it looks: delegation is how attacker-authored text
reaches an agent that never touched the attacker. Cross-agent WRITES are closed
(a run cannot touch another agent's mind), but cross-agent INFLUENCE is what
delegation is for -- a task title and detail land in the assignee's prompt. With
an open default, one compromised agent can wake every other agent on the platform
with text of its choosing, and the only thing standing in the way is a sentence
in the prompt telling the reader to treat it as data. That is a rate, not a
boundary.

    ANDYUR_DELEGATIONS="*"     every agent may delegate to every agent

is still available and is exactly as permissive as the old default. The
difference is that it is now a decision someone made. The production profile
refuses to start without one, because "unset" and "everyone" should not be the
same configuration.
"""

from __future__ import annotations

import os


class InvalidDelegationPolicy(RuntimeError):
    """The delegation spec could not be parsed. Refused rather than guessed."""


def _parse(spec: str) -> dict[str, set[str]]:
    """Parse the allow-list, REFUSING anything malformed.

    Silently dropping an unparseable clause is the worst available behaviour
    here. `ANDYUR_DELEGATIONS="planner,triage"` -- a comma where a
    semicolon-and-colon belongs, which is the likeliest typo -- parsed to
    nothing, and nothing means "no allow-list", which means every agent may
    delegate to every agent. The production profile then passed, because a spec
    was set. So a typo granted universal cross-agent delegation while the
    operator believed they had restricted it.

    "unset" and "everyone" were correctly made different configurations; this
    makes "typo" different from both, which matters more, because an operator
    who mistyped is not watching for the consequence. The sibling parser in
    broker.py already refuses a malformed allowlist for exactly this reason.
    """
    out: dict[str, set[str]] = {}
    for clause in spec.split(";"):
        clause = clause.strip()
        if not clause:
            continue
        if ":" not in clause:
            raise InvalidDelegationPolicy(
                f"ANDYUR_DELEGATIONS clause {clause!r} has no ':'. Expected "
                "\"planner:triage,research; triage:research\", or \"*\" to allow "
                "every agent to delegate to every agent. Refusing to guess: an "
                "unparseable policy would silently allow everything."
            )
        src, dsts = clause.split(":", 1)
        targets = {d.strip() for d in dsts.split(",") if d.strip()}
        if not src.strip() or not targets:
            raise InvalidDelegationPolicy(
                f"ANDYUR_DELEGATIONS clause {clause!r} names no delegator or no "
                "target"
            )
        out.setdefault(src.strip(), set()).update(targets)
    return out


SPEC = os.environ.get("ANDYUR_DELEGATIONS", "").strip()
# "*" is explicit permissiveness: the None sentinel below means "no policy", and
# those must be distinguishable so the production profile can refuse the second
# without refusing the first.
OPEN = SPEC == "*"
# Parsed once at import. Empty or "*" -> no allow-list (None sentinel).
_ALLOW = None if OPEN else (_parse(SPEC) or None)


def configured() -> bool:
    """Whether an operator has made a delegation decision at all."""
    return bool(SPEC)


def may_delegate(creator: str | None, assignee: str) -> bool:
    """Whether `creator` (the acting agent, or None for the operator) may delegate
    to `assignee`. Operator and self-delegation always allowed; with no allow-list
    configured, everything is allowed."""
    if creator is None or creator == assignee:
        return True
    if _ALLOW is None:
        return True
    return assignee in _ALLOW.get(creator, set())
