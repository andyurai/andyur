"""Run tokens: a per-run capability that names WHICH agent is acting (R1).

The control plane authorizes tool calls by SPIFFE *role* (runner/worker/
operator), which cannot tell one agent's run from another's -- every runner
shares the same role. A run token closes that: when a run is assigned, the
server mints a short-lived signed token carrying {agent, run_id, workflow_id}.
It is delivered to the runner through the trusted spawn channel (server ->
daemon -> runner env), never an API the agent can call, and the runner presents
it on every run-scoped request. The server verifies it and authorizes on its
`agent`, so a run can only touch its own namespace.

The agent does NOT hold this token. `identity.seal_run_token` moves it out of
the environment into the runner's own memory at startup, and the runner blanks
`ANDYUR_RUN_TOKEN` in the environment it gives the agent subprocess, so it is
not inherited by a spawn the runner did not arrange. This paragraph used to say
the agent could read it, which was true before S4 and has been false since;
a stale comment about who holds a credential is worth correcting loudly.

It cannot be forged for another agent (server-signed), and `require_run` binds
it to the caller's attested SVID, so a copy replayed from a different container
is refused. The eventual upgrade is a per-run *attested* SVID via the
launch-token bridge; the enforcement is identical, only the credential gets
stronger.

Expiry is not the revocation boundary. `require_run` checks run liveness on
every call, so a halted, finished or reaped run's token stops working
immediately whatever its `exp` says. A token is therefore minted to cover its
run and never refreshed: there is no rotation endpoint to attack, and a run can
never outlive the credential it was issued.

Format (compact, stdlib only): base64url(payload_json).base64url(HMAC-SHA256).
Only the server holds the secret and mints/verifies; the daemon and runner carry
the opaque string.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

from ..config import RUN_TOKEN_SECRET, RUN_TOKEN_TTL


class InvalidRunToken(Exception):
    """A presented run token failed verification: bad signature, expired, or
    malformed."""


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(payload_b64: str) -> str:
    mac = hmac.new(
        RUN_TOKEN_SECRET.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
    ).digest()
    return _b64u(mac)


# A token says what it is FOR, and verification requires the purpose to match.
#
# Andyur issues two credentials to the same run, and they must not substitute
# for one another. The control-plane token is kept out of the agent's reach; the
# broker token has to be IN it, because the model client sends it on every call.
# Without a purpose claim, the credential the agent legitimately holds would be
# a valid control-plane credential, and R2's whole point -- scrub the agent's
# environment of anything that acts on the platform -- would be undone by the
# thing meant to protect it.
#
# This is audience binding, the same property the RFC 8693 exchange gives
# downstream tokens: a credential is usable at exactly one place.
PURPOSE_RUN = "run"        # authorize run-scoped control-plane calls
PURPOSE_BROKER = "broker"  # authorize model calls at the broker, and nothing else

# HOW a run's user was established. Carried with the subject everywhere it goes,
# because `sub` alone answers "who" and a resource server also needs "says who".
SUB_SRC_IDP = "idp"        # authenticated by the configured identity provider
SUB_SRC_ASSERTED = "asserted"   # an authenticated API client said so; nobody
                                # authenticated the user themselves


def mint(agent: str, run_id: str, workflow_id: str | None,
         sub: str | None = None, scope: list | None = None, ttl: int | None = None,
         purpose: str = PURPOSE_RUN, pin: dict | None = None,
         sub_src: str | None = None, audiences: list | None = None) -> str:
    """Sign a run grant. `sub` (U1) is the user the run acts for; `scope` (U2) is the
    narrowed authority granted to this run; `pin` is the subject context -- WHAT the
    work is about, e.g. {"account": "447"}. All three live in the signed grant so
    they cannot be forged, swapped, or widened by the run.

    The pin travels HERE, in the grant, rather than in the prompt, because the
    prompt is the one place the model can rewrite. A run that reads its target
    account out of its own instructions is a run that can be told to work on a
    different account by any text it ingests; a run whose target is a signed
    claim cannot be retargeted by anything it reads."""
    payload = {
        "a": agent,
        "r": run_id,
        "w": workflow_id,
        "p": purpose,
        "exp": int(time.time()) + (ttl or RUN_TOKEN_TTL),
    }
    if sub is not None:
        payload["s"] = sub
    if sub_src is not None:
        # Beside the subject, never apart from it: a `sub` says who, and a party
        # deciding whether to honour it needs to know whether anyone
        # authenticated them.
        payload["ss"] = sub_src
    if scope is not None:
        payload["sc"] = list(scope)
    if audiences is not None:
        payload["au"] = list(audiences)
    if pin is not None:
        # sorted keys so one pin has one byte representation: the delegation
        # check compares canonical forms, and two spellings of the same pin
        # must not look like a retarget
        payload["pn"] = dict(sorted(dict(pin).items()))
    payload_b64 = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64)}"


def verify(token: str, purpose: str = PURPOSE_RUN) -> dict:
    """Return {agent, run_id, workflow_id, sub, scope, pin} or raise InvalidRunToken.

    `purpose` must match what the token was minted for. Tokens issued before
    this claim existed carry no purpose and are read as control-plane tokens,
    which is the safe direction: an old token keeps working where it always
    worked, and is refused at the broker rather than silently accepted.
    """
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError:
        raise InvalidRunToken("malformed token")
    if not hmac.compare_digest(sig, _sign(payload_b64)):
        raise InvalidRunToken("bad signature")
    try:
        payload = json.loads(_b64u_decode(payload_b64))
    except Exception:
        raise InvalidRunToken("malformed payload")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise InvalidRunToken("expired")
    if payload.get("p", PURPOSE_RUN) != purpose:
        raise InvalidRunToken(
            f"token is for '{payload.get('p')}', not '{purpose}'")
    # Every legitimate mint names both; a token without them identifies no run,
    # and downstream checks (liveness, SVID binding) key on these values, so an
    # empty one must die here rather than probe what those checks do with "".
    # Whitespace-only is treated as empty: the server never mints such a value,
    # and an identifier that is all spaces names nothing a later check can match.
    if not str(payload.get("a") or "").strip() or \
            not str(payload.get("r") or "").strip():
        raise InvalidRunToken("token names no agent or no run")
    return {
        "agent": payload.get("a"),
        "run_id": payload.get("r"),
        "workflow_id": payload.get("w"),
        "expires_at": int(payload["exp"]),
        "sub": payload.get("s"),
        # Absent on grants minted before this claim existed, and read as "idp"
        # there -- an IdP login was the only way to get a subject at all then, so
        # an old grant keeps meaning exactly what it meant.
        "sub_src": (payload.get("ss", SUB_SRC_IDP) if payload.get("s") else None),
        "scope": payload.get("sc"),
        "audiences": payload.get("au"),
        # None means UNPINNED (the pre-pin behaviour), not "pinned to nothing":
        # a grant minted before this claim existed keeps working exactly as it
        # did, and an empty pin is refused at the seal so the two can never be
        # confused here.
        "pin": payload.get("pn"),
    }
