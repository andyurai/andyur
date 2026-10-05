"""An OpenID AuthZEN front end for OPA.

OPA does not speak AuthZEN natively and has decided not to: the request for a
built-in endpoint (open-policy-agent/opa#8449) was closed "not planned", with
maintainers pointing at a plugin or sidecar as the right shape. So this is that
sidecar, and it is deliberately tiny.

    Andyur  --AuthZEN-->  this shim  --OPA Data API-->  OPA

Why bother, when Andyur could just call OPA's API directly? Because then Andyur
would be coupled to OPA. Speaking the standard instead means the engine is a
deployment choice: point ANDYUR_PDP_URL at a PDP that speaks AuthZEN natively
(Cerbos, Topaz, Keycloak 26.7+) and this shim is simply not deployed. That
swappability is the entire argument for externalising authorization, and it only
holds if the interface is the standard rather than a vendor's API.

Spec: OpenID AuthZEN Authorization API 1.0, Final, 11 January 2026.
https://openid.net/specs/authorization-api-1_0.html

DEPLOYMENT REQUIREMENT, because this file cannot enforce it. The shim answers
questions for anyone who can reach it. It cannot CHANGE any decision (OPA
refuses every write, see system-authz.rego) and it holds a token that can only
ask, but an attacker who can reach it can probe the policy: ask a thousand
questions and learn the shape of the rules. So run it as a sidecar bound to
loopback beside the enforcement point, or on an internal network, never exposed.
The privileged path -- changing policy -- is closed by design; this one is
closed by deployment, and saying which is which is the point.

Run:  OPA_URL=http://127.0.0.1:8181 OPA_TOKEN=... uvicorn authzen_shim:app --port 8282
"""

import logging
import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

OPA_URL = os.environ.get("OPA_URL", "http://127.0.0.1:8181")
# The bearer token OPA's own authorization policy expects from this shim. It
# grants exactly one capability, POST to the decision path; it cannot write
# policy or data, so leaking it does not let an attacker change any answer.
OPA_TOKEN = os.environ.get("OPA_TOKEN", "")
# The policy PACKAGE to evaluate: package andyur.authz. Querying the package
# rather than a single rule returns the decision AND the policy's own reason in
# one round trip, so a denial can be logged with the decider's explanation
# instead of the enforcement point's guess.
OPA_DECISION_PATH = os.environ.get("OPA_DECISION_PATH", "/v1/data/andyur/authz")

log = logging.getLogger("authzen_shim")

app = FastAPI(title="AuthZEN shim for OPA")


class Evaluation(BaseModel):
    """An AuthZEN evaluation request. All four fields are the spec's own shape;
    `subject`, `action` and `resource` are objects with a type/id and optional
    properties, `context` is free-form."""

    subject: dict
    action: dict
    resource: dict | None = None
    context: dict | None = None


class Batch(BaseModel):
    """AuthZEN batch request (spec section 6). `evaluations` carries the
    per-decision items; a real implementation also honours
    options.evaluations_semantic (execute_all / deny_on_first_deny /
    permit_on_first_permit). We implement the default, execute_all."""

    evaluations: list[Evaluation]
    options: dict | None = None


def _headers() -> dict:
    return {"Authorization": f"Bearer {OPA_TOKEN}"} if OPA_TOKEN else {}


def _decide(result) -> tuple[bool, str]:
    """Read OPA's result into (decision, reason). Every unexpected shape is a
    DENY, because this function is the last place a malformed answer can be
    mistaken for a permit.

    Two shapes are accepted, deliberately:
      dict  querying the package (the default): {"decision": bool, "reason_admin": str}
      bool  querying a single boolean rule, for deployments that point
            OPA_DECISION_PATH at their own rule instead of Andyur's package
    Anything else -- a string, a number, a null, a dict without a boolean
    `decision` -- is a policy that did not answer the question asked, which is
    not the same as an answer of "yes".
    """
    if isinstance(result, bool):
        return result, "policy returned a bare boolean (no reason available)"
    if isinstance(result, dict):
        decision = result.get("decision")
        reason = result.get("reason_admin")
        if isinstance(decision, bool):
            if not isinstance(reason, str):
                reason = "policy returned no reason_admin"
            return decision, reason
        return False, "policy document has no boolean `decision`"
    if result is None:
        # THE gotcha that motivated this whole function. OPA returns
        # {"result": <value>} for a defined rule and a bare {} for an UNDEFINED
        # one -- no result key at all. Absent is not false. A misspelled rule
        # name, a wrong package path, and a policy that genuinely did not match
        # are indistinguishable on the wire, so all three must deny. This is
        # also what an unloaded or failed-verification bundle looks like.
        return False, "policy is undefined at the queried path (unloaded, misnamed, or unmatched)"
    return False, f"policy returned an unusable {type(result).__name__}"


def _ask_opa(client: httpx.Client, ev: Evaluation) -> tuple[bool, str]:
    """One AuthZEN evaluation -> one OPA query.

    Raises on a transport or status failure rather than returning a denial. The
    distinction is deliberate and it matters:

      OPA answered, but no rule matched    -> a real decision: deny (200)
      OPA could not be asked at all        -> no decision exists: 503

    Returning `decision: false` for the second case would be a lie -- claiming
    a policy said no when no policy was consulted -- and it would hide a broken
    PDP behind a plausible-looking stream of denials. The enforcement point
    fails closed on the 503 anyway, so the outcome is identical and the cause
    stays visible.
    """
    body = {"input": ev.model_dump(exclude_none=False)}
    r = client.post(OPA_URL + OPA_DECISION_PATH, json=body,
                    headers=_headers(), timeout=5.0)
    r.raise_for_status()
    return _decide(r.json().get("result"))


def _response(decision: bool, reason: str) -> dict:
    """An AuthZEN decision. The reason travels in `context.reason_admin`, which
    the spec reserves for the administrator-facing explanation. There is
    deliberately no `reason_user`: the enforcement point must not hand a policy
    explanation to the caller it just refused."""
    return {"decision": decision, "context": {"reason_admin": {"en": reason}}}


@app.post("/access/v1/evaluation")
def evaluation(ev: Evaluation) -> dict:
    """Single decision. AuthZEN section 5."""
    try:
        with httpx.Client() as client:
            decision, reason = _ask_opa(client, ev)
    except Exception as exc:
        log.error("PDP unreachable or refused: %s", exc)
        raise HTTPException(status_code=503, detail="policy engine unavailable") from exc
    return _response(decision, reason)


@app.post("/access/v1/evaluations")
def evaluations(batch: Batch) -> dict:
    """Batch decisions, order preserved. AuthZEN section 6.

    This is what Andyur's grant-time question uses: one evaluation per scope the
    task declared, in a single round trip instead of N.

    One failed evaluation fails the WHOLE batch. A partial batch would force the
    caller to guess which positions are missing, and a caller that guesses wrong
    about an authorization result guesses in the permissive direction sooner or
    later."""
    try:
        with httpx.Client() as client:
            decided = [_ask_opa(client, ev) for ev in batch.evaluations]
    except Exception as exc:
        log.error("PDP unreachable or refused: %s", exc)
        raise HTTPException(status_code=503, detail="policy engine unavailable") from exc
    return {"evaluations": [_response(d, r) for d, r in decided]}


@app.get("/.well-known/authzen-configuration")
def configuration() -> dict:
    """Discovery metadata. A PDP advertises which sub-APIs it supports by which
    endpoint fields it publishes; we implement evaluation and evaluations, and
    deliberately do NOT claim the search endpoints."""
    base = os.environ.get("SHIM_PUBLIC_URL", "http://127.0.0.1:8282")
    return {
        "policy_decision_point": base,
        "access_evaluation_endpoint": f"{base}/access/v1/evaluation",
        "access_evaluations_endpoint": f"{base}/access/v1/evaluations",
    }
