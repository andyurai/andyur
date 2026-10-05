"""`infra/temporal/backup.sh`, run against a stand-in `kubectl`.

The script's two promises are the ones that matter at restore time, which is
the worst moment to find either broken: a dump that is not complete is refused
rather than kept, and what it keeps is readable by its owner alone -- a dump
holds every execution history, and payload hygiene is a guard on field names,
not a proof of what a field contains.
"""

import os
import pathlib
import stat
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKUP = ROOT / "infra" / "temporal" / "backup.sh"

COMPLETE = "-- PostgreSQL database dump\nCREATE TABLE t();\n-- PostgreSQL database dump complete\n"


def _run(tmp_path, dump_body):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    body = tmp_path / "dump.sql"
    body.write_text(dump_body)
    kubectl = bin_dir / "kubectl"
    # `get pod` answers with a name; `exec` prints the prepared dump.
    kubectl.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  get) echo andyur-temporal-db-0 ;;\n"
        f"  exec) cat {body} ;;\n"
        "esac\n")
    kubectl.chmod(0o755)
    out = tmp_path / "out"
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
    # A permissive umask in the CALLER, which is what the script must not
    # inherit.
    result = subprocess.run(["bash", "-c", f'umask 022; exec "{BACKUP}" "{out}"'],
                            capture_output=True, text=True, env=env, timeout=30)
    return result, out


def test_a_complete_backup_is_readable_by_its_owner_only(tmp_path):
    result, out = _run(tmp_path, COMPLETE)
    assert result.returncode == 0, result.stderr

    dumps = sorted(out.glob("*.sql"))
    assert [d.name.split("-")[0] for d in dumps] == ["temporal", "temporal_visibility"], (
        f"expected one dump per database, got {[d.name for d in dumps]}")
    for dump in dumps:
        mode = stat.S_IMODE(dump.stat().st_mode)
        assert mode == 0o600, (
            f"{dump.name} is {oct(mode)}; a dump holds every execution history "
            "and must not be group- or world-readable")
    assert stat.S_IMODE(out.stat().st_mode) == 0o700, "the backup directory is not owner-only"


def test_a_truncated_dump_is_refused(tmp_path):
    """The positive control's mirror: the same stand-in, minus the completion
    marker, must fail -- or the test above proves nothing about verification."""
    result, _out = _run(tmp_path, COMPLETE.replace("dump complete", "dump"))

    assert result.returncode != 0, "a dump without its completion marker was accepted"
    assert "truncated or not a dump" in result.stderr
