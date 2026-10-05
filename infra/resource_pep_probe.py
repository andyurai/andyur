#!/usr/bin/env python3
"""Drive real Andyur-minted tokens at a real MCP resource server.

Called by verify-resource-pep.sh. Prints one line per case with a stable marker
the shell asserts on, so a case that silently stops running fails the harness
rather than quietly disappearing from it.
"""
import asyncio
import json
import os
import sys
import urllib.error
import urllib.request

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ANDYUR = os.environ["B"].rstrip("/")
RUN_TOKEN = os.environ["TOK_SPECIALIST"]
URL = f"http://127.0.0.1:{os.environ.get('ANDYUR_TOOL_PORT', '8795')}/mcp"
AUDIENCE = os.environ.get("ANDYUR_TOOL_AUDIENCE", URL)


def mint(audience: str, scope=None) -> str:
    body = {"audience": audience}
    if scope is not None:
        body["scope"] = scope
    req = urllib.request.Request(
        f"{ANDYUR}/oauth/token", method="POST", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "X-Andyur-Run-Token": RUN_TOKEN})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


async def call(token: str, tool: str, args: dict) -> tuple[bool, str]:
    """(refused, text). `refused` comes from MCP's isError, not from matching a
    substring in the text -- a denial has to be structurally distinguishable from
    data, or a model cannot act on it and nor can this harness."""
    async with streamablehttp_client(
            URL, headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
            return bool(result.isError), result.content[0].text


async def main() -> None:
    good = mint(AUDIENCE)
    # Same run, same user, different target. Valid there, useless here.
    # A real, well-formed resource identifier -- just not this one. Under ADR 002
    # a wrong audience is a wrong URL, which is what a confused client would
    # actually send.
    wrong = mint("http://127.0.0.1:9/mcp")
    # Correctly audienced but granted only a read, so the transfer must refuse
    # for a DIFFERENT reason than the audience -- an operator has to be able to
    # tell those two refusals apart.
    read_only = mint(AUDIENCE, scope=["files:read"])

    _, text = await call(good, "whoami", {})
    print(f"ACCEPTED whoami -> {text}")

    refused, text = await call(good, "balance", {"account": "447"})
    print(f"{'REFUSED' if refused else 'ALLOWED'} balance(447) -> {text}")

    refused, text = await call(good, "balance", {"account": "999"})
    print(f"{'REFUSED' if refused else 'ALLOWED'} balance(999) -> {text}")

    refused, text = await call(read_only, "transfer",
                               {"account": "447", "amount": "10"})
    print(f"{'REFUSED' if refused else 'ALLOWED'} transfer -> {text}")

    for token, label in ((wrong, "wrong-audience"), ("not-a-token", "garbage")):
        try:
            await call(token, "whoami", {})
            print(f"ACCEPTED {label} -- THE RESOURCE FAILED TO REFUSE IT")
        except Exception as exc:                       # noqa: BLE001
            print(f"REJECTED {label} at the transport ({type(exc).__name__})")


try:
    asyncio.run(main())
except Exception as exc:                               # noqa: BLE001
    print(f"probe failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)
