"""Governed registry: signature-verified, digest-pinned agent snapshots.

The configured OCI reference must be immutable, cosign verification happens
before parsing, deny-listed snapshots are refused, and every resolution carries
the verified registry digest. C2 additionally joins an optional, strictly parsed
``runtime-resolutions.json`` from the SAME verified artifact so executable bytes
and authority cannot come from different trust roots.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from .manifest_registry import ManifestAgentRegistry
from .models import AgentResolution, InvalidAgentManifest, RegistryUnavailable
from .runtime_overlay import RUNTIME_OVERLAY, load_runtime_overlay

_REF_RE = re.compile(r"[A-Za-z0-9][\w./:-]*@(sha256:[0-9a-f]{64})")
_DIGEST_ONLY_RE = re.compile(r"sha256:[0-9a-f]{64}")


def _tool_timeout_seconds() -> int:
    raw = os.environ.get("ANDYUR_REGISTRY_TOOL_TIMEOUT", "60")
    try:
        return int(raw)
    except ValueError as exc:
        raise RegistryUnavailable(
            f"ANDYUR_REGISTRY_TOOL_TIMEOUT must be an integer, got {raw!r}") from exc


def _run_tool(argv: list[str]) -> None:
    timeout = _tool_timeout_seconds()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise RegistryUnavailable(
            f"governed registry needs {argv[0]!r} on PATH: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RegistryUnavailable(f"{argv[0]} timed out after {timeout}s") from exc
    if proc.returncode != 0:
        raise RegistryUnavailable(
            f"{' '.join(argv[:2])} failed (rc={proc.returncode}): "
            f"{proc.stderr.strip()[:500]}")


def _flag_on(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "on", "true")


def _default_verify(ref: str, key_path: str) -> None:
    argv = ["cosign", "verify", "--key", key_path]
    if _flag_on("ANDYUR_REGISTRY_COSIGN_IGNORE_TLOG"):
        argv.append("--insecure-ignore-tlog=true")
    if _flag_on("ANDYUR_REGISTRY_ALLOW_HTTP"):
        argv.append("--allow-http-registry")
    argv.append(ref)
    _run_tool(argv)


def _default_pull(ref: str, dest: str) -> None:
    argv = ["oras", "pull", ref, "-o", dest]
    if _flag_on("ANDYUR_REGISTRY_ALLOW_HTTP"):
        argv.append("--plain-http")
    _run_tool(argv)


class GovernedAgentRegistry:
    """AgentRegistry serving one verified, digest-pinned OCI snapshot."""

    def __init__(
        self,
        ref: str,
        key_path: str,
        deny_digests: frozenset[str] = frozenset(),
        *,
        verify: Callable[[str, str], None] = _default_verify,
        pull: Callable[[str, str], None] = _default_pull,
    ):
        match = _REF_RE.fullmatch(ref)
        if not match:
            raise RegistryUnavailable(
                "ANDYUR_REGISTRY_REF must be an OCI reference pinned to an exact "
                "digest (registry/repo@sha256:<64 hex>); tags and leading '-' are refused")
        self._digest = match.group(1)
        for digest in deny_digests:
            if not _DIGEST_ONLY_RE.fullmatch(digest):
                raise RegistryUnavailable(
                    f"ANDYUR_REGISTRY_DENY_DIGESTS entry {digest!r} is not a "
                    "sha256:<64 hex> digest")
        if self._digest in deny_digests:
            raise RegistryUnavailable(
                f"registry snapshot {self._digest} is deny-listed; refusing revoked snapshot")
        if not Path(key_path).is_file():
            raise RegistryUnavailable(f"cosign public key not found at {key_path!r}")

        verify(ref, key_path)
        workdir = tempfile.mkdtemp(prefix="andyur-registry-")
        try:
            pull(ref, workdir)
            # Runtime is loaded only after signature verification and from the
            # same pulled bytes as the authority manifests.
            self._runtime = load_runtime_overlay(workdir)
            # ManifestAgentRegistry intentionally treats every ``*.json`` in
            # its directory as an authority manifest.  Remove the already
            # parsed overlay from this disposable verified-snapshot copy so it
            # cannot be mistaken for one.  The source artifact is immutable;
            # only this temporary post-verification extraction is changed.
            overlay_path = Path(workdir) / RUNTIME_OVERLAY
            if overlay_path.exists():
                overlay_path.unlink()
            self._inner = ManifestAgentRegistry(workdir)
            known = {r.agent_id for r in self._inner.list_agents()}
            unknown = set(self._runtime) - known
            if unknown:
                raise InvalidAgentManifest(
                    "runtime overlay names agent(s) absent from the authority snapshot: "
                    + ", ".join(sorted(unknown)))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @property
    def digest(self) -> str:
        return self._digest

    def _decorate(self, resolution: AgentResolution) -> AgentResolution:
        return replace(
            resolution,
            registry_digest=self._digest,
            runtime=self._runtime.get(resolution.agent_id),
        )

    def resolve(self, agent_id: str) -> AgentResolution:
        return self._decorate(self._inner.resolve(agent_id))

    def list_agents(self) -> list[AgentResolution]:
        return [self._decorate(r) for r in self._inner.list_agents()]


def governed_registry_from_env() -> GovernedAgentRegistry:
    ref = os.environ.get("ANDYUR_REGISTRY_REF", "")
    if not ref:
        raise RegistryUnavailable(
            "ANDYUR_REGISTRY=governed requires ANDYUR_REGISTRY_REF "
            "(an OCI reference pinned @sha256:…)")
    key = os.environ.get("ANDYUR_REGISTRY_COSIGN_KEY", "")
    if not key:
        raise RegistryUnavailable(
            "ANDYUR_REGISTRY=governed requires ANDYUR_REGISTRY_COSIGN_KEY "
            "(path to the cosign public key)")
    deny = frozenset(
        d.strip() for d in os.environ.get("ANDYUR_REGISTRY_DENY_DIGESTS", "").split(",")
        if d.strip())
    return GovernedAgentRegistry(ref, key, deny)
