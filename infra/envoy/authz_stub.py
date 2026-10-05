"""Run the REAL ext_authz decision service for the spike gate.

Uses andyur.dataplane.extauthz.build_app unchanged (so the live gate exercises
the real service code and its fail-closed logic), with identity PROVISIONED
from env (one Envoy per run) and the per-tool POLICY provisioned from a REAL
registry manifest: ANDYUR_SPIKE_MANIFEST is parsed by the real
ManifestAgentRegistry, and the audience's ToolBinding.mcp_tools grants drive
the tools/call decision and the tools/list rewrite -- no tool list lives in
this stub or its environment.

What remains INJECTED (and is unit tested against the real sources instead):
the run's GRANTED ACTIONS (production reads scope/pin from the sealed run row
and intersects via registry.authority_for; here ANDYUR_SPIKE_ACTIONS supplies
the already-narrowed result, "*" = unrestricted) and liveness
(ANDYUR_SPIKE_LIVE=0 marks the run terminated). ANDYUR_SPIKE_ALLOW=0 is the
audience-level deny.
"""
from __future__ import annotations

import os

import uvicorn

from andyur.dataplane import extauthz
from andyur.registry.manifest_registry import ManifestAgentRegistry

AUD = os.environ.get("ANDYUR_SPIKE_AUDIENCE", "resource:calendar")
AGENT_ID = os.environ.get("ANDYUR_SPIKE_AGENT_ID", "agt_scout")
RUN_ID = os.environ.get("ANDYUR_SPIKE_RUN_ID", "r1")
ALLOW = os.environ.get("ANDYUR_SPIKE_ALLOW", "1") == "1"
LIVE = os.environ.get("ANDYUR_SPIKE_LIVE", "1") == "1"
_ACTIONS_RAW = os.environ.get("ANDYUR_SPIKE_ACTIONS", "calendar:read")
ACTIONS = None if _ACTIONS_RAW == "*" else \
    sorted(filter(None, _ACTIONS_RAW.split(",")))

_resolution = ManifestAgentRegistry(
    os.environ["ANDYUR_SPIKE_MANIFEST"]).resolve(AGENT_ID)
_binding = next(t for t in _resolution.tools if t.resource_id == AUD)


def _authority(agent, run_id, audience, method=None, tool=None):
    if not ALLOW:
        return {"actions": [], "pin": None, "audience": None}  # audience deny
    return {"actions": ACTIONS, "pin": None, "audience": audience}


# F-02 sender binding, the A-side half of the exchange seam. The token must
# bind (cnf.x5t#S256) to the EXACT certificate Envoy presents to the tool. In
# production that thumbprint comes from the run's X509-SVID leaf that the
# co-located decision service and Envoy share via SDS; a SEPARATE SPIRE fetch
# would mint a distinct key and a non-matching thumbprint, so the spike takes
# the value the gate captured from the presented cert (ANDYUR_SPIKE_CNF_THUMB)
# -- standing in for that co-located material while B wires the real AS. The
# exchange is a STUB AS: it mints a real JWT carrying cnf.x5t#S256 = the
# binding. Signature strength is pep.verify_token's property (proven
# separately); the gate proves the BINDING is enforced against the live cert.
_CNF_ON = os.environ.get("ANDYUR_SPIKE_CNF", "0") == "1"
_CNF_THUMB = os.environ.get("ANDYUR_SPIKE_CNF_THUMB", "")


def _cnf_thumb():
    if os.environ.get("ANDYUR_SPIKE_CNF_WRONG", "0") == "1":
        # The stolen-token negative: bound to a certificate OTHER than the one
        # presented on the wire.
        import base64
        import hashlib
        return base64.urlsafe_b64encode(hashlib.sha256(
            b"not the presented certificate").digest()).rstrip(b"=").decode()
    return _CNF_THUMB or None


def _exchange(agent, run_id, scope, pin, aud, cnf=None):
    import time as _time
    import jwt as _jwt
    claims = {"sub": "spike", "aud": aud, "iat": int(_time.time()),
              "exp": int(_time.time()) + 300}
    if cnf is not None:
        claims["cnf"] = {"x5t#S256": cnf}
    return _jwt.encode(claims, "spike-stub-secret", algorithm="HS256")


app = extauthz.build_app(
    run_agent=_resolution.name, run_id=RUN_ID, audience=AUD,
    exchange_fn=_exchange,
    authority_fn=_authority,
    liveness_fn=lambda run_id: LIVE,
    mcp_tools=_binding.mcp_tools,
    cnf_fn=_cnf_thumb if _CNF_ON else None)


if __name__ == "__main__":
    uds = os.environ.get("ANDYUR_SPIKE_UDS")
    if uds:
        # Production shape: reachable ONLY over a same-Pod Unix socket, so the
        # token-dispensing decision service is not a network Service any
        # workload could call directly.
        uvicorn.run(app, uds=uds, log_level="info")
    else:
        uvicorn.run(app, host="0.0.0.0", port=9000, log_level="info")
