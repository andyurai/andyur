"""The complete environment contract for the untrusted agent process.

This is an allowlist intentionally shared by the sidecar launcher and the
agent's defensive startup scrub. Adding a platform secret elsewhere cannot
silently make it cross this boundary.
"""

from __future__ import annotations

from collections.abc import Mapping


_HOST_RUNTIME = frozenset({
    "HOME", "LANG", "LC_ALL", "LC_CTYPE", "PATH", "PYTHONPATH",
    "SSL_CERT_DIR", "SSL_CERT_FILE", "TMPDIR", "TZ", "VIRTUAL_ENV",
})

_EXECUTION_CONTEXT = frozenset({
    "ANDYUR_AGENT_MODEL", "ANDYUR_LLM", "ANDYUR_MAX_TURNS",
    "ANDYUR_OTEL", "ANDYUR_PROFILE",
})


def allowed(source: Mapping[str, str], *, channel_token: str | None = None) -> dict[str, str]:
    """Return only OS runtime and documented non-secret execution context."""
    names = _HOST_RUNTIME | _EXECUTION_CONTEXT
    out = {name: source[name] for name in names if name in source}
    if channel_token:
        out["ANDYUR_CHANNEL_TOKEN"] = channel_token
    return out

