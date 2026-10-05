#!/usr/bin/env python3
"""Put SPIFFE TLS in front of a plain-HTTP MCP server.

WHY THIS EXISTS, and why a normal certificate will not do. On an https
reach_url the run's sidecar builds its outbound context as

    ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=<trust bundle>)

where the bundle is the SPIFFE TRUST DOMAIN bundle, with `check_hostname` off
because SPIFFE identifies by URI SAN (andyur/proxy/app.py). So the tool server
is trusted by trust-domain membership -- not by a public CA, and not by a
self-signed cert somebody added to a store. A tool server speaking https must
therefore present an X509-SVID issued by the SAME SPIRE the runner trusts.

Most tool servers cannot do that. `osv-mcp` is a Go binary that serves plain
HTTP and knows nothing about SPIFFE. This front holds the SVID on its behalf:
it fetches one from the workload API, terminates TLS with it, and forwards to
the upstream over loopback-shaped plain HTTP.

WHY IT RUNS AS A CONTAINER. The SVID comes from the workload API socket, and in
the Docker deployment that socket lives in a docker volume the host cannot
reach. The front must therefore run where the socket is, and publish a port so
the sidecar reaches it exactly as it reaches any other tool.

WHAT IT IS NOT. It is not a policy enforcement point. It adds transport
identity and nothing else -- no authorization, no token checking, no scope. The
PEP is the tool server's job (see demos/authority-tool/pep.py); this only makes
the hop something production will accept.

    python tls_front.py --upstream http://host.docker.internal:8810/mcp --port 8443
"""
from __future__ import annotations

import argparse
import os
import sys

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.routing import Route

# Hop-by-hop headers are meaningless to forward and actively wrong to copy:
# they describe THIS connection, not the message.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
}


def _forwardable(headers) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP}


def build(upstream: str) -> Starlette:
    client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0))

    async def forward(request: Request):
        """Streamed, not buffered.

        MCP's streamable HTTP holds the response open and delivers events as
        they happen. Reading the upstream to completion before replying would
        turn every tool call into a stall that ends in one burst, and a
        long-lived session into a timeout.
        """
        upstream_request = client.build_request(
            request.method,
            upstream,
            headers=_forwardable(request.headers),
            content=request.stream(),
            params=request.query_params,
        )
        response = await client.send(upstream_request, stream=True)
        return StreamingResponse(
            response.aiter_raw(),
            status_code=response.status_code,
            headers=_forwardable(response.headers),
            background=BackgroundTask(response.aclose),
        )

    return Starlette(routes=[
        Route("/{path:path}", forward,
              methods=["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"]),
    ])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True,
                        help="the plain-HTTP MCP server to front")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--role", default="tool",
                        help="label for the exported SVID material on disk")
    args = parser.parse_args()

    # Imported here so `--help` works without a workload API socket.
    from andyur import identity

    try:
        material = identity.export_tls_pems(args.role)
    except Exception as exc:                       # noqa: BLE001 - surface it
        print(f"could not obtain an X509-SVID: {exc}\n\n"
              "This front is only useful with one: the run's sidecar verifies "
              "the tool server against the SPIFFE trust bundle, so a cert from "
              "anywhere else is refused. Check that this process matches a "
              "SPIRE registration entry and can reach the workload API socket.",
              file=sys.stderr)
        raise SystemExit(1)

    print(f"fronting {args.upstream}")
    print(f"serving https on {args.host}:{args.port} with an X509-SVID")
    uvicorn.run(
        build(args.upstream), host=args.host, port=args.port,
        ssl_certfile=material["cert"], ssl_keyfile=material["key"],
        # The bundle is loaded so the front COULD verify a client cert; it does
        # not require one. The runner presents its SVID on this leg, but
        # sender-binding is a two-party property no Andyur tool PEP asserts yet
        # (proxy/app.py says so plainly), and requiring it here would refuse
        # every caller while proving nothing.
        ssl_ca_certs=material["bundle"],
        log_level=os.environ.get("ANDYUR_TLS_FRONT_LOG", "warning"),
    )


if __name__ == "__main__":
    main()
