"""The per-run proxy sidecar.

Per `spire-registry-design-v2.md`, the sidecar is the run's own process and the
only holder of the run's identity. The agent talks to it over loopback holding
no credential; the sidecar presents the run's X509-SVID (mTLS) plus the delegated
token to tools directly, and forwards to a shared, identity-less agentgateway for
LLM/REST.

This is a deliberately THIN Andyur-owned proxy over OSS (httpx + py-spiffe), a
stopgap chosen to get the end-to-end demo working. The committed follow-up is to
replace this data plane with Envoy (SPIRE SDS for the mTLS cert, ext_authz for
this module's credential logic) once the demo is green, so Andyur stops owning
proxy code at all -- see the module docstring in `sidecar.py`.
"""
