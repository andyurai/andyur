"""Conversation state: the DB-backed rendezvous between an operator and a live
agent session.

A conversation is a run of run_type='conversation' that stays open across many
turns. Two directional queues, both in the database so the operator and the
session reach each other through any stateless server replica:

- **turns**  operator/owner -> session. Queued by the operator, claimed FIFO by
  exactly one session via compare-and-swap, so the agent can never inject its
  own turns and a turn is never delivered twice.
- **events** session -> operator. The agent's streamed reply. Written only by
  the run-token-scoped session; read by the operator by cursor.

Seq is per-run and monotonic, assigned in a single INSERT..SELECT under the runs
row lock, with a UNIQUE(run_id, seq) index as the backstop, so ordering is well
defined even across concurrent replicas and on the single-writer SQLite path.
Every write re-checks that the run is a LIVE conversation, so a closed or dead
session cannot be resurrected or appended to. Bodies are redacted at this
storage boundary (defense in depth on top of the runner's own redaction).
"""

import uuid

from .. import config, db
from ..redact import redact

# run states in which a conversation still accepts turns / is drivable
_LIVE = ("pending", "running")
# turn kinds
KIND_MESSAGE = "message"
KIND_CLOSE = "close"
# event kinds
EV_CHUNK = "chunk"
EV_TURN_END = "turn_end"
EV_SESSION_END = "session_end"
EV_ERROR = "error"


class ConversationClosed(Exception):
    """The run is not an accepting conversation (wrong type, or terminal)."""


class TurnTooLarge(Exception):
    """A single human turn body exceeded CONVERSATION_MAX_TURN_BYTES."""


class Backlogged(Exception):
    """The operator stopped reading; the UNREAD event backlog hit its cap."""


def _run_row(conn, run_id: str, lock: bool = False):
    suffix = " FOR UPDATE" if (lock and db.IS_POSTGRES) else ""
    return conn.execute(
        f"SELECT id, agent, run_type, state, acting_user, conv_read_cursor "
        f"FROM runs WHERE id = ?{suffix}",
        (run_id,),
    ).fetchone()


def _insert_with_seq(conn, table: str, run_id: str, cols: dict) -> int:
    """Insert a row assigning the next per-run seq atomically, retrying (up to 3
    times) if a concurrent inserter took the same seq (UNIQUE(run_id, seq) rejects
    the loser).
    The INSERT..SELECT computes seq inside the write, so SQLite serializes it on
    its write lock and Postgres on the runs-row FOR UPDATE the caller holds."""
    names = ", ".join(["id", "run_id", "seq"] + list(cols) + ["created_at"])
    placeholders = ", ".join(["?", "?", "(SELECT COALESCE(MAX(seq), 0) + 1 FROM "
                              + table + " WHERE run_id = ?)"]
                             + ["?"] * len(cols) + ["?"])
    # ON CONFLICT DO NOTHING rather than catching the error and retrying on the
    # same connection. On Postgres a failed statement aborts the whole
    # transaction, so the retry raises InFailedSqlTransaction instead of an
    # integrity error, the `except` does not match, and it escapes the caller --
    # the documented "retry up to 3 times" simply did not exist there, and the
    # exhaustion guard below was unreachable. Same bug class as the migration
    # seed; this is the other place it lived.
    inserted = 0
    for _ in range(3):
        rid = uuid.uuid4().hex[:12]
        params = [rid, run_id, run_id] + list(cols.values()) + [db.utcnow()]
        cur = conn.execute(
            f"INSERT INTO {table} ({names}) VALUES ({placeholders}) "
            f"ON CONFLICT DO NOTHING",
            params,
        )
        inserted = cur.rowcount
        if inserted:
            break
    if not inserted:
        # true exhaustion: raise rather than return a bogus seq, so a caller can
        # never receive a fabricated position (silent corruption). Unreachable
        # while the runs-row lock serializes inserts, but fail loud if it regresses.
        raise RuntimeError(f"could not assign a unique seq in {table} for {run_id}")
    row = conn.execute(f"SELECT seq FROM {table} WHERE id = ?", (rid,)).fetchone()
    return int(row["seq"])


def count_active() -> int:
    """Conversation runs currently holding a slot (pending or running)."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM runs "
            "WHERE run_type = 'conversation' AND state IN ('pending', 'running')"
        ).fetchone()
    return int(row["n"])


def _unread(conn, run_id: str, read_cursor) -> int:
    cur = int(read_cursor or 0)
    return int(conn.execute(
        "SELECT COUNT(*) AS n FROM conversation_events WHERE run_id = ? AND seq > ?",
        (run_id, cur),
    ).fetchone()["n"])


def enqueue_turn(run_id: str, sender: str, body: str, kind: str = KIND_MESSAGE) -> int:
    """Queue a human turn (or a close sentinel). Returns its seq.

    Raises ConversationClosed if the run is not a live conversation, TurnTooLarge
    if a message body is oversized, Backlogged if a MESSAGE arrives while the
    operator's UNREAD backlog is over cap. A CLOSE is always accepted (it is the
    control that ends a backlogged/abandoned session)."""
    if kind == KIND_MESSAGE and len(body.encode("utf-8")) > config.CONVERSATION_MAX_TURN_BYTES:
        raise TurnTooLarge()
    with db.connect() as conn:
        row = _run_row(conn, run_id, lock=True)
        if row is None or row["run_type"] != "conversation" or row["state"] not in _LIVE:
            raise ConversationClosed()
        # backpressure on a non-reading operator: refuse new MESSAGES when the
        # UNREAD backlog (events past the operator's read cursor) is over cap.
        # CLOSE is exempt -- it must always land, it is what ends the session.
        if kind == KIND_MESSAGE and _unread(conn, run_id, row["conv_read_cursor"]) \
                > config.CONVERSATION_MAX_EVENT_BACKLOG:
            raise Backlogged()
        # redact at the storage boundary too, so a pasted secret is not persisted
        stored = redact(body) if kind == KIND_MESSAGE else ""
        return _insert_with_seq(conn, "conversation_turns", run_id,
                                {"kind": kind, "sender": sender, "body": stored,
                                 "state": "pending"})


def claim_next_turn(run_id: str) -> dict | None:
    """Compare-and-swap claim the oldest pending turn for this run (pending ->
    delivered), returning it, or None if the queue is empty. Exactly-once: two
    racing sessions cannot both claim the same turn (only one UPDATE matches)."""
    with db.connect() as conn:
        while True:
            r = conn.execute(
                "SELECT id, seq, kind, sender, body FROM conversation_turns "
                "WHERE run_id = ? AND state = 'pending' ORDER BY seq LIMIT 1",
                (run_id,),
            ).fetchone()
            if r is None:
                return None
            claimed = conn.execute(
                "UPDATE conversation_turns SET state = 'delivered' "
                "WHERE id = ? AND state = 'pending'",
                (r["id"],),
            )
            if claimed.rowcount:
                conn.execute(
                    "UPDATE runs SET heartbeat_at = ? WHERE id = ?",
                    (db.utcnow(), run_id),
                )
                return dict(r)
            # lost the race for that row; loop and try the next pending one


def beat(run_id: str) -> None:
    """Liveness beat with no turn to claim (called on each empty poll)."""
    with db.connect() as conn:
        conn.execute(
            "UPDATE runs SET heartbeat_at = ? WHERE id = ? AND state = 'running'",
            (db.utcnow(), run_id),
        )


def append_event(run_id: str, kind: str, body: str = "") -> int:
    """Append a reply event from the session. Returns its seq. Rejects a terminal
    run (no post-finalize appends) and beats liveness (a streaming turn keeps the
    session alive between turn polls). Body is size-capped and redacted here."""
    body = redact(body)
    if len(body.encode("utf-8")) > config.CONVERSATION_MAX_EVENT_BYTES:
        body = body.encode("utf-8")[:config.CONVERSATION_MAX_EVENT_BYTES].decode(
            "utf-8", "ignore") + " <truncated>"
    with db.connect() as conn:
        row = _run_row(conn, run_id, lock=True)
        # self-defending: only a LIVE conversation accepts events, so a zombie or
        # superseded runner cannot grow the store of a finalized run (the auth-layer
        # liveness check is a backstop, not the only guard).
        if row is None or row["run_type"] != "conversation" or row["state"] not in _LIVE:
            raise ConversationClosed()
        # beat liveness here too, so a long streaming turn (many chunks, no turn
        # poll in between) does not look dead to the reaper.
        conn.execute("UPDATE runs SET heartbeat_at = ? WHERE id = ?",
                     (db.utcnow(), run_id))
        return _insert_with_seq(conn, "conversation_events", run_id,
                                {"kind": kind, "body": body})


def read_events(run_id: str, after: int) -> list[dict]:
    """Events with seq greater than the operator's cursor, in order. Advances the
    server-side read cursor (never regresses) so the backlog cap can measure the
    operator's UNREAD backlog rather than total events. `after` is CLAMPED to the
    highest seq that actually exists, so a client cannot jump the cursor past real
    events to defeat the backlog backpressure control (or overflow the column)."""
    after = max(0, int(after))
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT seq, kind, body FROM conversation_events "
            "WHERE run_id = ? AND seq > ? ORDER BY seq",
            (run_id, after),
        ).fetchall()
        max_seq = conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS m FROM conversation_events WHERE run_id = ?",
            (run_id,),
        ).fetchone()["m"]
        cursor = min(after, int(max_seq))  # never ack beyond what exists
        conn.execute(
            "UPDATE runs SET conv_read_cursor = ? WHERE id = ? "
            "AND (conv_read_cursor IS NULL OR conv_read_cursor < ?)",
            (cursor, run_id, cursor),
        )
    return [dict(r) for r in rows]
