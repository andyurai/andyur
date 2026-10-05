"""Installing a bundle into a running platform.

A bundle is a directory of agent definitions, and installing one adds agents
that may hold authority. That makes this a privileged operation with a small
number of properties it must not get wrong, each of which is a test:

  * It is REFUSED in governed mode. A governed registry is a cosign-verified,
    digest-pinned OCI snapshot; writing files into the directory beside it would
    put unsigned agents in a deployment whose whole premise is that every agent
    came from a signed artifact. There is no --force for this.
  * A bundle NAME is a single path segment, matched against a pattern that
    admits no dot and no separator, and the resolved destination is checked to
    still be inside the registry. Two independent checks, because a path
    traversal here writes agent definitions anywhere the server can reach.
  * NOTHING MOVES until every document parses. A half-installed bundle is a
    registry that will not load, which is an outage caused by an install.
  * The rebuilt registry replaces the live one only once it has CONSTRUCTED.
    Dropping the snapshot and rebuilding lazily would turn one bad file into a
    RegistryUnavailable for every caller, discovered later, somewhere else.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from ..config import PROJECT_ROOT
from .manifest_registry import ManifestAgentRegistry, _parse_manifest
from .models import InvalidAgentManifest

# The same shape as an agent name: lowercase, no dot, no separator. `..` cannot
# match it, which is the first of the two traversal defences.
BUNDLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
MAX_AGENTS_PER_BUNDLE = 64
MAX_DOCUMENT_BYTES = 256 * 1024


class BundleRefused(Exception):
    """An install or uninstall the platform declines to perform."""


def registry_directory() -> Path:
    """Where bundles live, or a refusal explaining why they cannot."""
    if os.environ.get("ANDYUR_REGISTRY", "manifest") == "governed":
        raise BundleRefused(
            "this deployment runs a GOVERNED registry, which serves a "
            "cosign-verified, digest-pinned OCI snapshot. Bundles are installed "
            "there by publishing a new signed snapshot "
            "(`andyur agents package --publish-ref ... --cosign-key ...`), not "
            "by uploading files, because an uploaded agent would carry no "
            "signature in a deployment where that is the whole guarantee.")
    return Path(os.environ.get(
        "ANDYUR_AGENT_REGISTRY_DIR", str(PROJECT_ROOT / "demos" / "agent-registry")))


def _bundle_path(directory: Path, name: str) -> Path:
    if not BUNDLE_NAME_RE.fullmatch(name):
        raise BundleRefused(
            f"bundle name {name!r} must be lowercase letters, digits, "
            "underscore or hyphen, 2-64 characters, and cannot contain a path "
            "separator or a dot")
    destination = (directory / name).resolve()
    # The regex already excludes `..` and `/`. This is the second check, and it
    # is here because the first one protects the NAME while this protects the
    # PATH -- a symlinked registry directory could otherwise resolve outside.
    if directory.resolve() not in destination.parents:
        raise BundleRefused(
            f"bundle {name!r} resolves outside the registry directory")
    return destination


def list_bundles(directory: Path) -> list[dict]:
    """What is installed, and how much of it. Never raises on a bad bundle: a
    listing that dies on one unparseable directory cannot be used to find it."""
    if not directory.is_dir():
        return []
    found = []
    for sub in sorted(p for p in directory.iterdir() if p.is_dir()):
        found.append({"bundle": sub.name,
                      "agents": len(sorted(sub.glob("*.json")))})
    loose = len(sorted(directory.glob("*.json")))
    if loose:
        found.append({"bundle": None, "agents": loose})
    return found


def _validate(documents: list[dict], staged: Path) -> list:
    """Parse every document before anything is written anywhere."""
    if not documents:
        raise BundleRefused("a bundle must contain at least one agent")
    if len(documents) > MAX_AGENTS_PER_BUNDLE:
        raise BundleRefused(
            f"a bundle may contain at most {MAX_AGENTS_PER_BUNDLE} agents, "
            f"got {len(documents)}")
    parsed = []
    for index, document in enumerate(documents):
        rendered = json.dumps(document, indent=2) + "\n"
        if len(rendered.encode()) > MAX_DOCUMENT_BYTES:
            raise BundleRefused(
                f"agent #{index + 1} is larger than {MAX_DOCUMENT_BYTES} bytes")
        try:
            resolution = _parse_manifest(f"agent #{index + 1}", document)
        except InvalidAgentManifest as exc:
            raise BundleRefused(str(exc)) from exc
        parsed.append(resolution)
        # The agent's own validated name becomes the filename, so an installer
        # never chooses a path. It is already constrained to a safe pattern.
        (staged / f"{resolution.name}.json").write_text(rendered)
    return parsed


def install_bundle(directory: Path, name: str, documents: list[dict], *,
                   replace: bool = False) -> dict:
    """Stage, validate, then move into place. Returns what was installed."""
    destination = _bundle_path(directory, name)
    if destination.exists() and not replace:
        raise BundleRefused(
            f"bundle {name!r} is already installed; pass replace to overwrite it")

    directory.mkdir(parents=True, exist_ok=True)
    # Staged as a sibling, NOT inside the registry: a partially written bundle
    # under the registry directory would be picked up as a bundle by the very
    # next scan, which is the race this avoids rather than narrows.
    staging = Path(tempfile.mkdtemp(prefix=f".andyur-install-{name}-",
                                    dir=directory.parent))
    previous = None
    try:
        parsed = _validate(documents, staging)
        # In isolation first: a bundle that cannot load alone is this install's
        # fault, and saying so is more useful than a collision message.
        ManifestAgentRegistry(staging)

        if destination.exists():
            previous = staging.parent / f"{staging.name}.replaced"
            os.replace(destination, previous)
        os.replace(staging, destination)
        staging = None  # moved; the finally clause must not delete it

        try:
            from .service import reload_registry
            reload_registry()
        except Exception:
            # The registry did not come back. Put the old bundle where it was
            # and reload again, so the failure costs the install and not the
            # running platform.
            shutil.rmtree(destination, ignore_errors=True)
            if previous is not None:
                os.replace(previous, destination)
                previous = None
            from .service import reload_registry as _reload
            try:
                _reload()
            except Exception:                     # pragma: no cover - defensive
                pass
            raise
        return {"bundle": name,
                "agents": sorted(item.name for item in parsed),
                "replaced": previous is not None}
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if previous is not None:
            shutil.rmtree(previous, ignore_errors=True)


def uninstall_bundle(directory: Path, name: str) -> dict:
    """Remove an installed bundle. Agents already CREATED from it keep running:
    the registry is a catalogue of what may be launched, not a leash on what
    was. Deleting a bundle to stop an agent is the wrong instrument, and
    `andyur agents pause` is the right one."""
    destination = _bundle_path(directory, name)
    if not destination.is_dir():
        raise BundleRefused(f"no bundle named {name!r} is installed")
    removed = sorted(p.stem for p in destination.glob("*.json"))
    shutil.rmtree(destination)
    from .service import reload_registry
    reload_registry()
    return {"bundle": name, "removed": removed}
