"""Where this copy of Andyur lives, and where its state goes by default.

Andyur runs from two layouts. In a SOURCE CHECKOUT -- a clone, an editable
install, or an image that copies the tree to /app -- the directory above the
package is the project: `run.sh`, `infra/`, `demos/` and `.env` sit beside it,
and state defaults to `data/` there. INSTALLED by a package installer, the
directory above the package is a library, which is not a project and must
never be written to or configured from: there is no `run.sh` to point a user
at, a `.env` found there is somebody else's file, and state defaults to the
per-user state directory instead.

The root, the data directory, whether `.env` is read and what the command
advises all come from here. The data directory used to be derived from
`__file__` in three places, which agreed only because all three were wrong in
the same way on an installed copy.

What still resolves against the root on an installed copy is the server-side
material a wheel does not carry -- the demo registry, the conformance gates,
the per-role executables. An installed copy operates a deployment and does not
run one, so those are absent there rather than relocated.

This module imports nothing from Andyur and reads no `.env`, so the identity
layer can use it without pulling configuration in.
"""
from __future__ import annotations

import os
from pathlib import Path

PACKAGE_PARENT = Path(__file__).resolve().parent.parent

# An installer leaves the distribution's metadata directory beside the package
# it unpacked, wherever that is: a virtualenv, the user site, a `--target`
# directory, a distribution's dist-packages. Asking the interpreter for its
# library instead named two directories and missed the rest. A clone has none
# beside it, an editable install keeps its metadata in the library and its
# package in the clone, and the images copy the package alone.
SOURCE_CHECKOUT = not any(PACKAGE_PARENT.glob("andyur-*.dist-info"))


def default_data_dir() -> Path:
    if SOURCE_CHECKOUT:
        return PACKAGE_PARENT / "data"
    # XDG Base Directory: state that persists between runs but is not
    # configuration. An unset or relative XDG_STATE_HOME means the default.
    configured = os.environ.get("XDG_STATE_HOME", "")
    base = Path(configured) if os.path.isabs(configured) else Path.home() / ".local" / "state"
    return base / "andyur"


def data_dir() -> Path:
    """ANDYUR_DATA_DIR when the operator set it, otherwise the layout's default.

    An empty value means unset. It used to mean the working directory, which
    is what `VAR=` in a shell or an env file produces by accident."""
    return Path(os.environ.get("ANDYUR_DATA_DIR") or default_data_dir())


def create_data_dir(path: Path) -> None:
    """Create a state directory that does not exist yet.

    Under the per-user state directory it is created private, as the XDG
    specification asks of a directory an application makes for itself. A
    checkout's `data/` and an operator-chosen directory keep the process
    umask: several roles share them under different uids, and narrowing them
    here would lock those roles out of each other's subdirectories."""
    private = not SOURCE_CHECKOUT and path == default_data_dir()
    path.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o777)
