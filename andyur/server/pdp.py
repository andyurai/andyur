"""The authorization decision point (PDP).

Andyur's endpoints are the enforcement point (PEP): they ask a question and obey
the answer. This module is the thing that answers.

Today the answer is computed in-process from rules that used to sit inline in
`auth.py` and `app.py`. With `ANDYUR_PDP=authzen` the same questions go to an
external policy engine over the OpenID AuthZEN Authorization API (Final, Jan
2026), and Andyur stops knowing how the decision is made -- which is the point:
authorization can then change without a redeploy.

Andyur asks two questions, and both are modelled as AuthZEN *evaluations* so the
external PDP needs no Andyur-specific API:

  grant time        may a run for this user hold scope S?   one per requested scope
  enforcement time  may this run perform action A right now?

Modelling the grant as a batch of yes/no decisions rather than "return me the
permitted set" is deliberate. It keeps the question narrow (we ask only about
what the task declared it needs, never "what could this user do?"), it maps onto
AuthZEN's `/access/v1/evaluations` batch endpoint, and it means the intersection
of entitlements and request is no longer an operation Andyur implements -- it is
merely what the PDP happens to answer today.
"""

from __future__ import annotations

import dataclasses
import logging
from datetime import datetime, timezone


import httpx
from opentelemetry import trace

from .. import boundedhttp, config, observability, otel

log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Subject:
    """Who is asking. AuthZEN calls this the subject.

    Two kinds, matching the two questions:
      type="run"   an executing run, carrying the scope sealed into its grant
      type="user"  the human a run would act for, carrying their entitlements
    """

    type: str
    id: str | None = None
    is_operator: bool = False
    scope: list | None = None          # authority already granted to this run
    entitlements: list | None = None   # what the user is entitled to


def evaluate(subject: Subject, action: str) -> bool:
    """May `subject` perform `action`? The only question Andyur asks."""
    if config.PDP == "authzen":
        return _authzen(subject, [action])[0]
    return _builtin(subject, action)


def evaluate_all(subject: Subject, actions: list[str]) -> list[bool]:
    """Batch form: one decision per action, same subject, order preserved.

    The builtin PDP loops; an AuthZEN PDP answers all of them in one round trip.
    """
    if not actions:
        return []
    if config.PDP == "authzen":
        return _authzen(subject, actions)
    return [_builtin(subject, a) for a in actions]


# --- the external PDP (AuthZEN) --------------------------------------------

def _request(subject: Subject, action: str) -> dict:
    """One AuthZEN evaluation request. Subject attributes travel in the request
    rather than being looked up by the PDP, which keeps the PDP stateless and
    keeps Andyur's database out of the policy engine."""
    props: dict = {"is_operator": subject.is_operator}
    if subject.type == "run":
        # Always send the key, null included: the policy checks `scope == null`
        # explicitly, and an ABSENT key is undefined in Rego, which is a
        # different thing and would make that rule silently not fire.
        props["scope"] = subject.scope
    if subject.type == "user":
        props["entitlements"] = subject.entitlements or []
    return {
        "subject": {"type": subject.type, "id": subject.id or "", "properties": props},
        "action": {"name": action},
        "resource": {"type": "andyur", "id": "andyur"},
        # Request-time facts the policy may use but the caller does not control.
        # The spec's own example carries `time` here. Sending it rather than
        # letting the PDP read its own clock keeps decisions reproducible and
        # lets a policy reason about when a request was made without Andyur
        # knowing that any such policy exists.
        "context": {"time": datetime.now(timezone.utc).isoformat()},
    }


def _reason(decision: dict) -> str:
    """The decider's own explanation, if it gave one.

    AuthZEN returns it under `context.reason_admin` as a map of language tag to
    text. It is OPTIONAL, and a PDP that omits it is perfectly conformant, so
    every layer of this lookup tolerates absence rather than raising."""
    ctx = decision.get("context") or {}
    admin = ctx.get("reason_admin") or {}
    if isinstance(admin, dict):
        # any language is better than none; prefer English when offered
        return admin.get("en") or next(iter(admin.values()), "") or "(no reason given)"
    return str(admin) if admin else "(no reason given)"


def _decisions(payload: list[dict], actions: list[str]) -> list[bool]:
    """Read decisions out of AuthZEN responses and LOG the decider's reason for
    each denial.

    Why log it here rather than return it: the reason is written for an
    administrator, not for the caller. Andyur's endpoints answer a refused
    request with their own generic message, because a denial that explains what
    would have been sufficient is an oracle -- an attacker can walk the policy
    by reading its refusals. The explanation belongs in the operator's logs,
    where the audit question ("why did that fail at 03:00") gets answered."""
    out = []
    for action, decision in zip(actions, payload):
        if not isinstance(decision, dict) or not isinstance(decision.get("decision"), bool):
            raise ValueError("PDP returned no boolean decision")
        permitted = decision.get("decision") is True
        outcome, reason = ("success", "unknown") if permitted else ("denied", "refused")
        trace.get_current_span().add_event("pdp.decision", {
            "andyur.outcome": outcome, "andyur.reason": reason})
        otel.try_record_metric("andyur-server", "andyur.authorization.decisions", 1,
                              andyur__outcome=outcome, andyur__reason=reason)
        observability.event(log, "authorization.decision", outcome=outcome, reason=reason)
        if not permitted:
            log.info("PDP denied %s: %s", action, _reason(decision))
        out.append(permitted)
    return out


def _failure_reason(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, boundedhttp.Unbounded):
        return "exhausted"
    if isinstance(exc, httpx.HTTPStatusError):
        return "unavailable" if exc.response is None or exc.response.status_code >= 500 else "refused"
    if isinstance(exc, (ValueError, TypeError, AttributeError)):
        return "invalid"
    return "unavailable"


def _authzen(subject: Subject, actions: list[str]) -> list[bool]:
    """Ask an external PDP over the OpenID AuthZEN Authorization API.

    Fails CLOSED: any transport error, bad status, or malformed body denies
    every action in the request. An authorization service that fails open is
    worse than one that is down, because the failure is silent."""
    evaluations = [_request(subject, a) for a in actions]
    try:
        # Bounded in TOTAL, not per read. The PDP is the adopter's component and
        # may be slow or degraded; an httpx `timeout=` alone does not bound this
        # call, and each stalled one holds a thread on the request path. See
        # andyur/boundedhttp.py for the measurement.
        with otel.observe_dependency("andyur-server", "pdp", "authorize", _failure_reason):
            span = trace.get_current_span()
            if subject.type == "run" and subject.id:
                span.set_attribute("andyur.run_id", subject.id)
            parent = otel.current_traceparent()
            headers = {"traceparent": parent} if parent else {}
            if len(evaluations) == 1:
                body = boundedhttp.post_json(
                    f"{config.PDP_URL}/access/v1/evaluation", evaluations[0],
                    what="the PDP", headers=headers)
                return _decisions([body], actions)
            body = boundedhttp.post_json(
                f"{config.PDP_URL}/access/v1/evaluations",
                {"evaluations": evaluations}, what="the PDP", headers=headers)
            results = body.get("evaluations", [])
            if len(results) != len(actions):
                # A short or long batch cannot be aligned safely.
                raise ValueError("PDP returned the wrong number of decisions")
            return _decisions(results, actions)
    except Exception as exc:
        log.error("PDP unavailable or invalid (%s); denying %s", exc, actions)
        return [False] * len(actions)


def _builtin(subject: Subject, action: str) -> bool:
    """Today's rules, unchanged -- just moved out of the enforcement points.

    Default deny: every path that does not explicitly permit falls through to
    False. That instinct is load-bearing in slice 2, where an undefined Rego
    rule returns no result at all and must be read as a denial, not a crash.
    """
    if subject.is_operator:
        return True

    if subject.type == "run":
        # U2 enforcement. A run with no scope model active (scope is None) or
        # granted "*" is unrestricted; otherwise the sealed scope decides.
        if subject.scope is None or "*" in subject.scope:
            return True
        return action in subject.scope

    if subject.type == "user":
        # U2 grant. The user's entitlements decide what a run may be given.
        entitled = subject.entitlements or []
        return "*" in entitled or action in entitled

    return False
