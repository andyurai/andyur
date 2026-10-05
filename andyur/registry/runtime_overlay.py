"""Strict parser for governed BYOA executable identities.

Authority resolution files predate BYOA and remain valid. A governed OCI
snapshot may additionally contain ``runtime-resolutions.json`` whose keys are
immutable agent ids and whose values are the executable portion of the same
approved snapshot. GovernedAgentRegistry joins the two after signature
verification; no worker-local image setting participates in the decision.
"""

from __future__ import annotations

import json
from pathlib import Path

from .manifest_registry import _AGENT_ID_RE
from .models import (
    SUPPORTED_PROTOCOLS,
    InvalidAgentManifest,
    RuntimeResolution,
)
from .runtime_wire import decode_runtime

RUNTIME_OVERLAY = "runtime-resolutions.json"
# Both served interfaces. The overlay is the registry's own boundary, so it has
# to admit every protocol the platform serves or a valid manifest compiles into
# a snapshot the publisher's readback then refuses -- which is how exec/v1 was
# unpackageable while parsing and compiling cleanly.

_MAX_OVERLAY_BYTES = 1024 * 1024


def _parse_runtime(agent_id: str, raw) -> RuntimeResolution:
    """Parse one overlay entry at the REGISTRY boundary.

    Both served protocols are admitted here because the overlay is what the
    publisher writes: a manifest that parses and compiles must be packageable,
    or exec/v1 is unpublishable while looking valid. Whether a given protocol
    can actually be LAUNCHED is the launcher's question, asked with its own
    protocol set. The command is optional at this boundary and mandatory at the
    worker; see governed_kubernetes for why.
    """
    return decode_runtime(
        raw,
        where=f"runtime overlay for {agent_id!r}",
        error=InvalidAgentManifest,
        protocols=SUPPORTED_PROTOCOLS,
        require_command=False,
    )


def load_runtime_overlay(directory: str | Path) -> dict[str, RuntimeResolution]:
    """Load an optional runtime overlay from an already verified artifact."""
    path = Path(directory) / RUNTIME_OVERLAY
    if not path.exists():
        return {}
    try:
        if path.stat().st_size > _MAX_OVERLAY_BYTES:
            raise InvalidAgentManifest(
                f"{path}: runtime overlay exceeds {_MAX_OVERLAY_BYTES} bytes")
        raw = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InvalidAgentManifest(f"{path}: invalid runtime overlay: {exc}") from exc
    if not isinstance(raw, dict) or len(raw) > 1024:
        raise InvalidAgentManifest(f"{path}: must be an object with at most 1024 agents")
    result: dict[str, RuntimeResolution] = {}
    for agent_id, value in raw.items():
        if not isinstance(agent_id, str) or not _AGENT_ID_RE.fullmatch(agent_id):
            raise InvalidAgentManifest(f"{path}: invalid agent id {agent_id!r}")
        result[agent_id] = _parse_runtime(agent_id, value)
    return result
