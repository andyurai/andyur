"""`pip install andyur` is a supported install, so what an installed copy does
on a machine with nothing running is a contract.

The package is the command and its modules; it operates a deployment and does
not contain one. An installed copy therefore keeps no state beside the package,
reads no `.env` from there, and never tells its reader to run `run.sh`, which
the wheel does not ship.

These tests lay the package out the way an installer leaves it -- the package
directory with its `.dist-info` beside it -- in a fresh interpreter's library
and in a bare directory, which is what `--user` and `--target` produce, and
run the real code there. The wheel pip actually builds is the `install-gate`
job in CI.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess
import sysconfig
import tomllib
import venv

import pytest

from andyur import cli, layout

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _lay_out(directory: pathlib.Path, *, installer: bool) -> None:
    shutil.copytree(ROOT / "andyur", directory / "andyur",
                    ignore=shutil.ignore_patterns("__pycache__"))
    if installer:
        info = directory / "andyur-0.1.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_text("Metadata-Version: 2.4\nName: andyur\n")


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    """One fresh interpreter and three copies of the package.

    `venv`    in the interpreter's own library, with installer metadata
    `target`  in a bare directory, with installer metadata (--user, --target)
    `copied`  in a bare directory, with none -- how the images carry it

    Dependencies come from the interpreter running the tests, through a .pth
    file, which appends AFTER the fresh library: PYTHONPATH would go in front
    of it, and where the test interpreter has Andyur installed too, that copy
    would be the one imported."""
    home = tmp_path_factory.mktemp("installed")
    venv.create(home / "venv", with_pip=False)
    python = home / "venv" / "bin" / "python"
    purelib = pathlib.Path(subprocess.run(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        check=True, capture_output=True, text=True).stdout.strip())
    assert purelib != pathlib.Path(sysconfig.get_paths()["purelib"]), (
        "the fresh interpreter reports the test interpreter's library, so the "
        "copy would land beside the code under test and prove nothing")
    paths = sysconfig.get_paths()
    (purelib / "dependencies.pth").write_text(
        "\n".join(sorted({paths["purelib"], paths["platlib"]})) + "\n")
    _lay_out(purelib, installer=True)
    for name, installer in (("target", True), ("copied", False)):
        (home / name).mkdir()
        _lay_out(home / name, installer=installer)
    return {"python": python, "home": home, "venv": purelib,
            "target": home / "target", "copied": home / "copied"}


def _run(world, where, *argv, unset=(), **extra):
    # A closed socket and a closed port: a developer machine with a stack up
    # would otherwise answer, and the test would be about that stack.
    env = {"PATH": os.environ["PATH"], "HOME": str(world["home"]),
           "SPIFFE_ENDPOINT_SOCKET": f"unix:{world['home']}/absent.sock",
           "ANDYUR_SERVER_URL": "http://127.0.0.1:1", **extra}
    if where != "venv":
        env["PYTHONPATH"] = str(world[where])
    for name in unset:
        env.pop(name, None)
    return subprocess.run([str(world["python"]), *argv], cwd=world["home"],
                          env=env, capture_output=True, text=True, timeout=90)


def _eval(world, where, expression, **kwargs):
    """Evaluate one expression in the copy at `where`, proving it IS that copy."""
    out = _run(world, where, "-c",
               "import andyur, pathlib; "
               "print(pathlib.Path(andyur.__file__).resolve().parent.parent); "
               f"from andyur import layout, config, identity; print({expression})",
               **kwargs)
    assert out.returncode == 0, out.stderr
    imported_from, value = out.stdout.strip().split("\n")[-2:]
    assert pathlib.Path(imported_from) == world[where].resolve(), (
        f"asked for the {where} copy and imported {imported_from}")
    return value


STATE = pathlib.Path(".local") / "state" / "andyur"


def test_the_checkout_is_a_checkout_and_keeps_state_beside_itself(monkeypatch):
    """The positive control: the tree these tests run from is the other layout,
    so a rule that called everything installed would fail here."""
    monkeypatch.delenv("ANDYUR_DATA_DIR", raising=False)
    assert layout.SOURCE_CHECKOUT
    assert layout.default_data_dir() == ROOT / "data"
    assert any("./run.sh" in line for line in cli._how_to_get_a_deployment())


def test_a_copied_package_with_no_installer_metadata_is_a_checkout(world):
    """The images copy the package to /app and nothing else. That is a checkout
    layout, and its state stays beside it as it always has."""
    assert _eval(world, "copied", "layout.SOURCE_CHECKOUT") == "True"
    assert _eval(world, "copied", "config.DATA_DIR") == str(world["copied"].resolve() / "data")


@pytest.mark.parametrize("where", ["venv", "target"])
def test_every_way_of_installing_is_recognised(world, where):
    """A virtualenv is one place an installer puts a package. The user site and
    a --target directory are others, and pip picks the user site by itself when
    the system library is not writable."""
    assert _eval(world, where, "layout.SOURCE_CHECKOUT") == "False"
    state = str(world["home"] / STATE)
    assert _eval(world, where, "layout.data_dir()") == state
    # The three things that used to be derived from __file__ separately.
    assert _eval(world, where, "config.DATA_DIR") == state
    assert _eval(world, where, "config.DB_PATH") == state + "/andyur.db"
    assert _eval(world, where, "identity._project_data()") == state
    assert _eval(world, where, "identity.socket_path()",
                 unset=["SPIFFE_ENDPOINT_SOCKET"]) == (
        f"unix:{state}/spire/agent/api.sock")


def test_the_state_directory_follows_xdg_and_the_operator(world, tmp_path):
    state = str(world["home"] / STATE)
    assert _eval(world, "venv", "config.DATA_DIR",
                 XDG_STATE_HOME=str(tmp_path)) == str(tmp_path / "andyur")
    # The specification says a relative value is invalid and must be ignored.
    assert _eval(world, "venv", "config.DATA_DIR", XDG_STATE_HOME="state") == state
    chosen = str(tmp_path / "chosen")
    assert _eval(world, "venv", "config.DATA_DIR", XDG_STATE_HOME=str(tmp_path),
                 ANDYUR_DATA_DIR=chosen) == chosen
    assert _eval(world, "venv", "identity._project_data()",
                 ANDYUR_DATA_DIR=chosen) == chosen
    # Empty is what `VAR=` produces by accident. It used to mean the working
    # directory.
    assert _eval(world, "venv", "config.DATA_DIR", ANDYUR_DATA_DIR="") == state


def test_the_default_socket_does_not_follow_the_state_directory(world, tmp_path):
    """run.sh starts the SPIRE agent on the layout's own data directory whatever
    ANDYUR_DATA_DIR says, so the default socket stays there too."""
    assert _eval(world, "venv", "identity.socket_path()",
                 unset=["SPIFFE_ENDPOINT_SOCKET"],
                 ANDYUR_DATA_DIR=str(tmp_path)) == (
        f"unix:{world['home'] / STATE}/spire/agent/api.sock")


@pytest.mark.parametrize("where", ["venv", "target"])
def test_an_installed_command_names_only_things_the_reader_has(world, where):
    out = _run(world, where, "-m", "andyur.cli", "status")
    assert out.returncode == 1, (out.stdout, out.stderr)
    assert "Traceback" not in out.stderr
    assert "installed as a package" in out.stderr
    assert cli.REPOSITORY_URL in out.stderr
    assert "SPIFFE_ENDPOINT_SOCKET" in out.stderr
    assert "run.sh" not in out.stderr, (
        "an installed copy was told to run a script the wheel does not ship:\n"
        + out.stderr)
    assert not (world[where] / "data").exists(), (
        "running the command created a data directory beside the package")


UNREACHABLE = ("import httpx; from andyur import cli; "
               "cli._die_if_down(httpx.ConnectError('refused'))")


def test_the_unreachable_server_message_follows_the_layout_too(world):
    """The identity check comes first on a machine with nothing running, so the
    real command never reaches this message there. It is called directly."""
    out = _run(world, "venv", "-c", UNREACHABLE)
    assert out.returncode == 1
    assert "cannot reach the andyur server at http://127.0.0.1:1" in out.stderr
    assert "installed as a package" in out.stderr
    assert "run.sh" not in out.stderr and "Traceback" not in out.stderr

    control = _run(world, "copied", "-c", UNREACHABLE)
    assert control.returncode == 1
    assert "./run.sh docker-up" in control.stderr

    debug = _run(world, "venv", "-c", UNREACHABLE, ANDYUR_DEBUG="1")
    assert debug.returncode == 1
    assert "httpx.ConnectError: refused" in debug.stderr


def test_a_dotenv_beside_an_installed_package_is_not_read(world):
    """Beside an installed copy is a library directory. A file there must not
    choose which server the command talks to. Beside a checkout it is the
    project's own file and is read, which is the control."""
    planted = "ANDYUR_AUDIENCE=planted-by-a-file\n"
    for where in ("venv", "target", "copied"):
        (world[where] / ".env").write_text(planted)
    try:
        import_config = "__import__('os').environ.get('ANDYUR_AUDIENCE')"
        assert _eval(world, "venv", import_config) == "None"
        assert _eval(world, "target", import_config) == "None"
        assert _eval(world, "copied", import_config) == "planted-by-a-file"
    finally:
        for where in ("venv", "target", "copied"):
            (world[where] / ".env").unlink()


def test_a_configured_process_needs_no_home_directory(world, tmp_path):
    """A container uid may have no passwd entry and no HOME. A process that
    names its socket and its data directory must still start: the default it
    is not using is the only thing that needs a home."""
    script = (
        "import pwd\n"
        "def nobody(uid): raise KeyError(uid)\n"
        "pwd.getpwuid = nobody\n"
        "import pathlib\n"
        "try: pathlib.Path.home()\n"
        "except RuntimeError: print('no home')\n"
        "from andyur import config, identity\n"
        "print(config.DATA_DIR); print(identity.socket_path())\n")
    out = _run(world, "venv", "-c", script, unset=["HOME"],
               ANDYUR_DATA_DIR=str(tmp_path))
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == [
        "no", "home", str(tmp_path), f"unix:{world['home']}/absent.sock"]


def test_the_state_directory_an_installed_copy_creates_is_private(world, tmp_path):
    """The XDG specification asks for 0700 on a directory an application
    creates for itself. An operator's own directory keeps the umask, because
    several roles share it under different uids."""
    make = ("from andyur import config, layout; "
            "layout.create_data_dir(config.DATA_DIR); print(config.DATA_DIR)")
    out = _run(world, "venv", "-c", "import os; os.umask(0o022); " + make,
               XDG_STATE_HOME=str(tmp_path / "xdg"))
    assert out.returncode == 0, out.stderr
    created = tmp_path / "xdg" / "andyur"
    assert stat.S_IMODE(created.stat().st_mode) == 0o700

    out = _run(world, "venv", "-c", "import os; os.umask(0o022); " + make,
               ANDYUR_DATA_DIR=str(tmp_path / "shared"))
    assert out.returncode == 0, out.stderr
    assert stat.S_IMODE((tmp_path / "shared").stat().st_mode) == 0o755


def test_the_database_and_key_material_create_the_directory_that_way():
    """The two writers reach the directory through the one function that knows
    which mode it gets."""
    for module in ("db.py", "identity.py"):
        assert "layout.create_data_dir(" in (ROOT / "andyur" / module).read_text()


def test_the_package_metadata_points_where_the_command_does():
    """The command sends an installed reader to the repository, and the package
    index shows one too. They are the same place or one of them is wrong."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["urls"]["Repository"] == cli.REPOSITORY_URL
    readme = (ROOT / "README.md").read_text()
    assert project["description"] in " ".join(readme.split()), (
        "the one-line description on the package index is not a sentence the "
        "README says")


def test_the_licence_shipped_is_the_licence_declared():
    """LICENSE was the Apache notice alone, which is a pointer to a licence and
    not a copy of one. The wheel also carries fonts under the OFL."""
    text = (ROOT / "LICENSE").read_text()
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in text
    assert "END OF TERMS AND CONDITIONS" in text
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["license"] == "Apache-2.0 AND OFL-1.1"
    assert (ROOT / "andyur" / "console" / "static" / "fonts" / "LICENSE-OFL.txt").is_file()
