"""A minimal mTLS MCP-shaped tool for the Envoy data-plane spike.

Fetches its OWN X509-SVID from the SPIRE Workload API (py-spiffe), presents it,
and REQUIRES a client certificate. On each request it records the URI SAN of
the client certificate it saw -- so the gate can prove Envoy presented the
run's X509-SVID on the wire -- and returns 200. Not production; a spike probe.
"""
from __future__ import annotations

import http.server
import json
import os
import ssl
import sys
import threading
import time

from cryptography import x509
from spiffe import TrustDomain, X509Source

# The REAL enforcement function for F-02 (RFC 8705 sender binding), mounted
# from demos/authority-tool/pep.py: the gate must prove the property at the
# actual enforcement point against the LIVE presented client certificate, not
# in a helper reimplementation.
if os.path.exists("/pep.py"):
    sys.path.insert(0, "/")
    import pep as _pep
else:
    _pep = None


def _write_pems(source: X509Source, trust_domain: str):
    from cryptography.hazmat.primitives import serialization
    svid = source.get_x509_context().default_svid
    bundle = source.get_bundle_for_trust_domain(TrustDomain(trust_domain))
    cert_pem = b"".join(c.public_bytes(serialization.Encoding.PEM)
                        for c in svid.cert_chain)
    key_pem = svid.private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    bundle_pem = b"".join(a.public_bytes(serialization.Encoding.PEM)
                          for a in bundle.x509_authorities)
    for name, blob in (("tool.crt", cert_pem), ("tool.key", key_pem),
                       ("bundle.pem", bundle_pem)):
        open("/tmp/" + name, "wb").write(blob)
    return str(svid.spiffe_id)


def _peer_uri_san(der: bytes) -> str:
    cert = x509.load_der_x509_certificate(der)
    sans = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(
        x509.UniformResourceIdentifier)
    return sans[0] if sans else ""


def main():
    socket_path = sys.argv[1] if len(sys.argv) > 1 else \
        "unix:/run/spire/sockets/api.sock"
    trust_domain = sys.argv[2] if len(sys.argv) > 2 else "andyur.local"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8443

    src = X509Source(socket_path=socket_path, timeout_in_seconds=30)
    my_id = _write_pems(src, trust_domain)
    print(f"[tool] presenting {my_id}", flush=True)

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _handle(self):
            der = self.connection.getpeercert(True)
            peer = _peer_uri_san(der) if der else ""
            n = int(self.headers.get("content-length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                method = json.loads(raw or b"{}").get("method", "")
            except Exception:
                method = ""
            # Record EVERY header the tool actually received, so the gate can
            # prove no platform credential (run token, subject/actor tokens,
            # cookie, api key) reached it and the Authorization is only the
            # injected delegated token.
            got = {k.lower(): v for k, v in self.headers.items()}
            leaked = [h for h in ("x-andyur-run-token", "x-andyur-subject-token",
                                  "x-andyur-actor-token", "cookie", "x-api-key")
                      if h in got]
            # F-02: when the presented token carries a cnf binding, the REAL
            # pep.verify_cnf must accept it against the DER of the live client
            # certificate on THIS connection, or the call is refused. Claims
            # are decoded unverified because the property under test is the
            # BINDING; signature/audience/issuer verification is
            # pep.verify_token's job, proven in its own suite.
            cnf_state = "absent"
            require_cnf = os.environ.get("TOOL_REQUIRE_CNF") == "1"
            auth = got.get("authorization", "")
            if _pep is not None and auth.startswith("Bearer "):
                import jwt as _jwt
                try:
                    claims = _jwt.decode(auth[len("Bearer "):],
                                         options={"verify_signature": False})
                except Exception:                              # noqa: BLE001
                    claims = {}
                # With require_cnf, a plain bearer (no cnf) is REFUSED -- the
                # strict F-02 posture where an AS-stripped-cnf token cannot
                # degrade to a bearer at the resource.
                if "cnf" in claims or require_cnf:
                    try:
                        _pep.verify_cnf(claims, der, require_cnf=require_cnf)
                        cnf_state = "bound" if "cnf" in claims else "bearer-ok"
                    except _pep.Refused as why:
                        body = json.dumps({"ok": False, "cnf": "refused",
                                           "why": str(why)}).encode()
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
            if method == "tools/list":
                # The FULL menu, deliberately including the tool this run is
                # never granted: the gate proves the data plane filters it out
                # before the agent sees it (negative #9, no ghost tools). Both
                # streamable-HTTP response shapes are served, chosen by the
                # client's Accept, so the rewrite is proven on each.
                msg = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                    "tools": [
                        {"name": "read_calendar", "description": "read"},
                        {"name": "delete_calendar", "description": "delete"},
                    ]}})
                if os.environ.get("TOOL_GZIP_LIST") == "1":
                    # Force an unreadable (compressed) tools/list to prove the
                    # rewrite fails CLOSED: the agent must get a JSON-RPC error,
                    # never this raw list.
                    import gzip
                    body = gzip.compress(msg.encode())
                    ctype = "application/json"
                elif "text/event-stream" in got.get("accept", ""):
                    body = ("event: message\ndata: " + msg + "\n\n").encode()
                    ctype = "text/event-stream"
                else:
                    body = msg.encode()
                    ctype = "application/json"
            else:
                # The thumbprint of the cert THIS connection presented, so the
                # gate can mint a token bound to the exact cert Envoy presents
                # (the co-located-SDS material the spike stands in for).
                presented_x5t = _pep.x5t_s256(der) if (_pep and der) else ""
                body = json.dumps({"tool": my_id, "client_svid": peer,
                                   "authorization": got.get("authorization", ""),
                                   "leaked_credentials": leaked,
                                   "mcp_method": method,
                                   "cnf": cnf_state,
                                   "presented_x5t": presented_x5t,
                                   # echoed so the gate can prove Envoy set XFF
                                   # from the real peer, overriding the agent's.
                                   "xff": got.get("x-forwarded-for", ""),
                                   "seen_headers": sorted(got),
                                   "ok": True}).encode()
                ctype = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _handle
        do_POST = _handle
        do_DELETE = _handle

    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/tmp/tool.crt", "/tmp/tool.key")
    ctx.load_verify_locations("/tmp/bundle.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED  # mTLS: the caller must present a cert
    ctx.check_hostname = False
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[tool] mTLS listening on :{port}", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
