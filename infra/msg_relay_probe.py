#!/usr/bin/env python3
"""The relay demo's refusals, checked directly rather than left to the models.

Same principle as sre_probe.py: a security assertion must not depend on an agent
choosing to attempt the thing it is forbidden to do. The relay demo has TWO
agents, so it has two sides to freeze, each driven with that run's own live
credential through the same mint the gateway uses (--role picks the side):

  oncall    TELEMETRY-MINT is the positive control (its ceiling allows it);
            CAPACITY-MINT must be REFUSED -- the on-call agent's ceiling has no
            capacity resource, which is exactly why the delegation must happen
  capacity  CAPACITY-READ is the positive control; TICKETS-MINT must be REFUSED
            (its ceiling holds nothing but capacity work); PIN-SCALE must be
            REFUSED (the run inherited the incident's service pin, so another
            team's service is out of reach); CEILING-SCALE must be REFUSED (the
            resource's own hard ceiling binds even an entitled, pinned caller)

Every REFUSED line is paired with an ALLOWED control on the same credential,
because a refusal proves nothing when a broken server refuses everything.
"""
import asyncio
import json
import os
import sys
import urllib.error
import urllib.request

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ANDYUR = os.environ["ANDYUR_SERVER_URL"].rstrip("/")
CAP = f"http://127.0.0.1:{os.environ.get('ANDYUR_CAPACITY_PORT', '8799')}/mcp"


def run_token() -> str:
    token = os.environ.get("ANDYUR_PROBE_RUN_TOKEN", "")
    if not token:
        raise SystemExit("ANDYUR_PROBE_RUN_TOKEN is not set; the harness must "
                         "capture it while the run is live")
    return token


def mint(audience: str, token: str) -> str:
    """Exchange the run's credential for a resource token; raises HTTPError on
    a refused audience, which for these probes is a result, not a failure."""
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


def mint_refused(audience: str, token: str) -> tuple[bool, str]:
    try:
        mint(audience, token)
    except urllib.error.HTTPError as exc:
        return True, f"HTTP {exc.code}"
    return False, "minted"


async def call(url: str, token: str, tool: str, args: dict) -> tuple[bool, str]:
    async with streamablehttp_client(
            url, headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            out = await session.call_tool(tool, args)
            return bool(out.isError), out.content[0].text


async def probe_oncall() -> None:
    rt = run_token()
    try:
        mint("resource:telemetry", rt)
        print("ONCALL-TELEMETRY-MINT ALLOWED")
    except urllib.error.HTTPError as exc:
        print(f"ONCALL-TELEMETRY-MINT REFUSED -- the mint refuses everything: "
              f"HTTP {exc.code}")
    refused, why = mint_refused("resource:capacity", rt)
    print(f"ONCALL-CAPACITY-MINT {'REFUSED' if refused else 'ALLOWED -- CEILING NOT BOUND'}: {why}")


async def probe_capacity() -> None:
    rt = run_token()
    cap_token = mint("resource:capacity", rt)

    refused, text = await call(CAP, cap_token, "get_allocation",
                               {"service": "checkout-service"})
    print(f"{'CAPACITY-READ REFUSED -- the server refuses everything' if refused else 'CAPACITY-READ ALLOWED'}: "
          f"{text[:80]}")

    refused, why = mint_refused("resource:tickets", rt)
    print(f"CAPACITY-TICKETS-MINT {'REFUSED' if refused else 'ALLOWED -- CEILING NOT BOUND'}: {why}")

    refused, text = await call(CAP, cap_token, "scale_pool",
                               {"service": "payments-api", "redis_pool_max": 16})
    print(f"{'PIN-SCALE REFUSED' if refused else 'PIN-SCALE ALLOWED -- PIN NOT BOUND'}: "
          f"{text.split('refused: ')[-1][:100]}")

    refused, text = await call(CAP, cap_token, "scale_pool",
                               {"service": "checkout-service", "redis_pool_max": 9999})
    print(f"{'CEILING-SCALE REFUSED' if refused else 'CEILING-SCALE ALLOWED -- RESOURCE NOT BOUNDED'}: "
          f"{text.split('refused: ')[-1][:100]}")


try:
    role = sys.argv[sys.argv.index("--role") + 1]
except (ValueError, IndexError):
    raise SystemExit("usage: msg_relay_probe.py --role oncall|capacity")
try:
    asyncio.run({"oncall": probe_oncall, "capacity": probe_capacity}[role]())
except KeyError:
    raise SystemExit(f"unknown role {role!r}")
except Exception as exc:                               # noqa: BLE001
    print(f"probe failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)
