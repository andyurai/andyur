"""Process configuration for the manifest-backed reference registry."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable

from ..config import PROJECT_ROOT
from .manifest_registry import ManifestAgentRegistry
from .models import AgentCatalog, InvalidAgentManifest, RegistryUnavailable


_lock = threading.Lock()
RegistryFactory = Callable[[], AgentCatalog]


def _manifest_factory() -> AgentCatalog:
    # governed: a cosign-verified, digest-pinned OCI snapshot (see governed.py).
    # manifest (default): a plain directory, so getting started needs no
    # registry, no keys and no external tools.
    if os.environ.get("ANDYUR_REGISTRY", "manifest") == "governed":
        from .governed import governed_registry_from_env
        return governed_registry_from_env()
    directory = os.environ.get(
        "ANDYUR_AGENT_REGISTRY_DIR", str(PROJECT_ROOT / "demos" / "agent-registry")
    )
    return ManifestAgentRegistry(directory)


_factory: RegistryFactory = _manifest_factory
_configured: AgentCatalog | None = None


def configured_registry() -> AgentCatalog:
    """The process registry, constructed once as an immutable snapshot.

    Lazy construction keeps imports side-effect free and lets tests select a
    fixture directory without reloading the application module.
    """
    global _configured
    with _lock:
        if _configured is None:
            try:
                _configured = _factory()
            except (InvalidAgentManifest, OSError) as exc:
                raise RegistryUnavailable(str(exc)) from exc
        return _configured


def reload_registry() -> AgentCatalog:
    """Rebuild the snapshot after an install, keeping the old one on failure.

    NOT `reset_configured_registry`, though it is tempting: that drops the cache
    and lets the next caller rebuild lazily, so a bundle that lands broken turns
    into a RegistryUnavailable for whoever asks next -- an outage attributed to
    an unrelated request, minutes later, by someone who did not install
    anything. Building the replacement FIRST means a failed reload costs the
    reload and nothing else, and the caller who caused it is the one who hears
    about it.
    """
    global _configured
    with _lock:
        try:
            rebuilt = _factory()
        except (InvalidAgentManifest, OSError) as exc:
            raise RegistryUnavailable(str(exc)) from exc
        _configured = rebuilt
        return rebuilt


def configure_registry_factory(factory: RegistryFactory) -> None:
    """Install an enterprise registry adapter before application startup."""
    global _factory, _configured
    with _lock:
        _factory = factory
        _configured = None


def reset_configured_registry() -> None:
    """Test seam: forget the immutable process snapshot, keeping the factory.

    This is what a caller wants after swapping `_factory`: drop the cache so the
    newly installed factory is the one that gets built. It deliberately does NOT
    restore the default factory; use `restore_default_registry` for that.
    """
    global _configured
    with _lock:
        _configured = None


def restore_default_registry() -> None:
    """Test seam: the inverse of `configure_registry_factory`.

    `configure_registry_factory` mutates process state with no way to undo it,
    and `reset_configured_registry` only drops the snapshot. So an installed
    factory outlived every reset: running test_registry_digest_stamping before
    test_registry_binding turned 14 tests red with "unknown registry agent id",
    because the leaked factory rebuilt that module's fixture catalog over a
    tmp_path pytest had already deleted. The two operations read alike and mean
    opposite things, which is why one function could not serve both.

    Restoring the default is safe: `configure_registry_factory` has no
    production callers, so no shipped path relies on an installed factory
    surviving teardown.
    """
    global _factory, _configured
    with _lock:
        _factory = _manifest_factory
        _configured = None
