"""Server-side mind access + mind history (versioning).

The server is the only component that touches storage. It reads and writes an
agent's mind through the storage backend, and every change to a versioned mind
file (the agent's editable self, knowledge + instructions, plus its long-term
learnings) is recorded as an immutable version in the state database, so the
mind has full, queryable history and can be rolled back. Working memory (the
short-term scratchpad) is overwritten in place and not versioned. Runners reach
all of this over HTTP, so they need no storage access.
"""

import hashlib
import uuid

from .. import db, workspace


def _is_versioned(relpath: str) -> bool:
    return relpath in workspace.VERSIONED


def write_file(name: str, relpath: str, content: str, actor: str, run_id: str | None):
    """Write a mind file. If it is a versioned (mutable) file, record an
    immutable version first so the change is auditable and reversible."""
    if _is_versioned(relpath):
        _record_version(name, relpath, content, actor, run_id)
    workspace.write_text(name, relpath, content)


def _record_version(name: str, relpath: str, content: str, actor: str,
                    run_id: str | None) -> None:
    vid = uuid.uuid4().hex[:12]
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO mind_versions "
            "(id, agent, path, content, sha256, actor, run_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (vid, name, relpath, content, sha, actor, run_id, db.utcnow()),
        )


def history(name: str, path: str | None = None) -> list[dict]:
    """Version history for an agent (optionally one file), newest first.
    Content is omitted from the listing to keep it light."""
    clauses, params = ["agent = ?"], [name]
    if path:
        clauses.append("path = ?")
        params.append(path)
    where = " AND ".join(clauses)
    with db.connect() as conn:
        rows = conn.execute(
            f"SELECT id, agent, path, sha256, actor, run_id, created_at, "
            f"LENGTH(content) AS size FROM mind_versions WHERE {where} "
            f"ORDER BY created_at DESC",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def get_version(version_id: str) -> dict | None:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM mind_versions WHERE id = ?", (version_id,)
        ).fetchone()
    return dict(row) if row else None


def restore(name: str, version_id: str, actor: str) -> dict | None:
    """Roll a mind file back to a prior version. The restore is itself a new
    version, so history is append-only and you can always see what happened."""
    v = get_version(version_id)
    if v is None or v["agent"] != name:
        return None
    write_file(name, v["path"], v["content"], actor=actor, run_id=None)
    return {"restored": v["path"], "from_version": version_id}
