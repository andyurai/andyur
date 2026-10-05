#!/usr/bin/env python3
"""The refusals, checked directly rather than left to the model.

A security assertion must not depend on an agent choosing to attempt the thing
it is forbidden to do. In the run this accompanies, the on-call agent was told
to triage and comment -- it has no reason to try closing the incident, and a
model that does not try proves nothing about whether it would have been stopped.

So these three are driven with the run's own credential, through the same mint
the gateway uses, against the same servers the agent just used:

  CLOSE            an action above the ceiling, at a resource it MAY reach
  OTHER-SERVICE    a service outside the run's pin, at a resource it MAY reach
  OWN-SERVICE      the positive control -- because the two refusals above prove
                   nothing if this server refuses everything
"""
import asyncio
import json
import os
import sys
import urllib.request

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ANDYUR = os.environ["ANDYUR_SERVER_URL"].rstrip("/")
OBS = f"http://127.0.0.1:{os.environ.get('ANDYUR_OBS_PORT', '8797')}/mcp"
TIX = f"http://127.0.0.1:{os.environ.get('ANDYUR_TICKETS_PORT', '8798')}/mcp"
OBS_AUDIENCE = "resource:telemetry"
TIX_AUDIENCE = "resource:tickets"


def run_token() -> str:
    """The oncall run's OWN token, handed in by the harness.

    Taken while the run is still live rather than minted here, because a token
    cannot be issued for a run that has finished -- the control plane answers 409,
    which is correct and which made the first version of this probe fail for a
    reason that had nothing to do with authority. These probes must carry exactly
    the authority the agent carried, so the harness captures it at the same
    moment the agent's runner would.
    """
    token = os.environ.get("ANDYUR_PROBE_RUN_TOKEN", "")
    if not token:
        raise SystemExit("ANDYUR_PROBE_RUN_TOKEN is not set; the harness must "
                         "capture it while the run is live")
    return token


def mint(audience: str, token: str, scope_override=None) -> str:
    """The run's own delegated token for `audience`, minted the SAME way the
    per-run sidecar mints it. With an external AS configured, that is an RFC 8693
    exchange THERE -- dana's login as the subject, the run's SVID as the actor,
    the pin carried as an authorization detail and the logical scope translated
    by the ADR-010 map -- so the probe's tokens are issued and signed by the same
    AS the agent's were, not dev-minted. Without one, Andyur's own mint.
    """
    from andyur import config
    if config.AS_TOKEN_ENDPOINT:
        from andyur.server import asclient
        from andyur.runner.runner import _pin_as_rar, _claim_of
        scope = scope_override or (
            ["obs:read"] if audience == OBS_AUDIENCE
            else ["tickets:read", "tickets:comment"])
        resp = asclient.exchange(
            subject_token=os.environ["ANDYUR_PROBE_SUBJECT_TOKEN"],
            expected_subject=os.environ.get("ANDYUR_PROBE_EXPECTED_SUBJECT", "dana"),
            actor_token=os.environ["ANDYUR_PROBE_SVID"],
            expected_actor=os.environ["ANDYUR_PROBE_EXPECTED_ACTOR"],
            audience=audience, resource=audience, scope=scope,
            authorization_details=_pin_as_rar(_claim_of(token, "pn")))
        return resp["access_token"]
    svid = os.environ.get("ANDYUR_PROBE_SVID", "")
    headers = {"Content-Type": "application/json", "X-Andyur-Run-Token": token}
    if svid:
        headers["Authorization"] = f"Bearer {svid}"
    req = urllib.request.Request(
        f"{ANDYUR}/oauth/token", method="POST",
        data=json.dumps({"audience": audience}).encode(),
        headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


async def call(url: str, token: str, tool: str, args: dict) -> tuple[bool, str]:
    async with streamablehttp_client(
            url, headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            out = await session.call_tool(tool, args)
            return bool(out.isError), out.content[0].text


async def main() -> None:
    rt = run_token()
    tix_token = mint(TIX_AUDIENCE, rt)
    obs_token = mint(OBS_AUDIENCE, rt)

    refused, text = await call(TIX, tix_token, "close", {"issue": "INC-4471"})
    print(f"{'CLOSE REFUSED' if refused else 'CLOSE ALLOWED -- NOT BOUNDED'}: "
          f"{text.split('refused: ')[-1][:100]}")

    refused, text = await call(OBS, obs_token, "error_rate",
                               {"service": "payments-api"})
    print(f"{'OTHER-SERVICE REFUSED' if refused else 'OTHER-SERVICE ALLOWED -- PIN NOT BOUND'}: "
          f"{text.split('refused: ')[-1][:100]}")

    refused, text = await call(OBS, obs_token, "error_rate",
                               {"service": "checkout-service"})
    print(f"{'OWN-SERVICE REFUSED -- the server refuses everything' if refused else 'OWN-SERVICE ALLOWED'}: "
          f"{text[:80]}")

    try:
        await call(TIX, obs_token, "get_ticket", {"issue": "INC-4471"})
    except Exception as exc:  # the ticket PEP must reject telemetry's audience
        print(f"CROSS-AUDIENCE REFUSED: {type(exc).__name__}")
    else:
        print("CROSS-AUDIENCE ALLOWED -- TOKEN REPLAYABLE")

    # RED TEAM: the run container is the threat-model's compromised component, so
    # it may ask the AS for MORE than the registry granted. tickets:delete
    # (tickets:close) is above the registry ceiling; the AUTHORIZATION SERVER --
    # not the honest runner -- must refuse to ISSUE it. dana is not entitled and
    # the sre-oncall AS ceiling does not grant it, so the exchange itself fails.
    from andyur import config
    if config.AS_TOKEN_ENDPOINT:
        from andyur.server.asclient import ASError
        try:
            mint(TIX_AUDIENCE, rt, scope_override=["tickets:close"])
        except ASError as exc:
            # Bind this pass to the AS ITSELF. Only the AS-answered raise site
            # sets `status` (the HTTP status it replied with); every LOCAL raise
            # -- a scope-map misconfiguration, an unmapped action, an unreachable
            # endpoint -- leaves it None. A bare `except Exception` here printed
            # REFUSED-BY-AS for those too, so the check passed with the AS never
            # contacted: drop "tickets:close" from the scope map and it stayed
            # green forever. It also inverted one real case -- response
            # verification runs only AFTER a 200, so an AS that ISSUED an
            # over-ceiling token surfaced as a refusal by that same AS.
            # Anything without a status is therefore NOT a refusal and must not
            # be reported as one; let it propagate and fail the probe loudly.
            if exc.status is None:
                raise
            print(f"DELETE-DIRECT REFUSED-BY-AS: {exc.status} "
                  f"{exc.code or 'no-error-code'}")
        else:
            print("DELETE-DIRECT ISSUED -- AS CEILING TOO WIDE")


try:
    asyncio.run(main())
except Exception as exc:                               # noqa: BLE001
    print(f"probe failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)
