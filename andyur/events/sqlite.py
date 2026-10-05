"""SQLite RunEventStore for local development and deterministic replay tests."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
from threading import RLock
from uuid import uuid4

from .models import RunEvent
from .schema import strict_json_loads
from .store import _PendingRunEvent, _StoreWriter, TerminalRunError
from .taxonomy import (
    DataClassification, Durability, EventCategory, EventType, EventVisibility,
    TrustClass,
)

_TERMINAL_TYPES = frozenset({
    EventType.RUN_COMPLETED, EventType.RUN_FAILED, EventType.RUN_CANCELLED,
    EventType.RUN_TIMEOUT,
})

class SQLiteRunEventStore:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = RLock()
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA busy_timeout = 5000")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS run_events (
                tenant_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                document_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, run_id, sequence)
            )
        """)
        self._db.commit()

    def _new_writer(self) -> _StoreWriter:
        return _StoreWriter(self._append)

    def _append(self, pending: _PendingRunEvent) -> RunEvent:
        if pending.durability is not Durability.DURABLE:
            raise ValueError("SQLite store accepts durable events only")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                terminal = self._db.execute(
                    "SELECT document_json FROM run_events WHERE tenant_id=? AND run_id=? "
                    "ORDER BY sequence DESC LIMIT 1",
                    (pending.tenant_id, pending.run_id),
                ).fetchone()
                if terminal is not None:
                    last_type = strict_json_loads(terminal["document_json"])["type"]
                    if EventType(last_type) in _TERMINAL_TYPES:
                        raise TerminalRunError("run event stream is terminal")
                row = self._db.execute(
                    "SELECT COALESCE(MAX(sequence), 0) AS value FROM run_events "
                    "WHERE tenant_id=? AND run_id=?",
                    (pending.tenant_id, pending.run_id),
                ).fetchone()
                sequence = int(row["value"]) + 1
                recorded = RunEvent(
                    event_id=f"evt_{uuid4().hex}", sequence=sequence,
                    recorded_at=datetime.now(timezone.utc), **pending.__dict__,
                )
                document = json.dumps(recorded.to_dict(), allow_nan=False,
                                      separators=(",", ":"), sort_keys=True)
                self._db.execute(
                    "INSERT INTO run_events(tenant_id,run_id,sequence,event_id,document_json) "
                    "VALUES(?,?,?,?,?)",
                    (recorded.tenant_id, recorded.run_id, recorded.sequence,
                     recorded.event_id, document),
                )
                self._db.commit()
                return recorded
            except BaseException:
                try:
                    self._db.rollback()
                except Exception:
                    pass
                raise

    def read_after(self, tenant_id: str, run_id: str, sequence: int,
                   limit: int = 200) -> list[RunEvent]:
        if sequence < 0 or not 1 <= limit <= 1000:
            raise ValueError("invalid replay cursor or limit")
        with self._lock:
            rows = self._db.execute(
                "SELECT document_json FROM run_events WHERE tenant_id=? AND run_id=? "
                "AND sequence>? ORDER BY sequence LIMIT ?",
                (tenant_id, run_id, sequence, limit),
            ).fetchall()
        return [_event_from_document(row["document_json"]) for row in rows]

    def high_watermark(self, tenant_id: str, run_id: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COALESCE(MAX(sequence),0) AS value FROM run_events "
                "WHERE tenant_id=? AND run_id=?", (tenant_id, run_id),
            ).fetchone()
        return int(row["value"])

    def close(self) -> None:
        with self._lock:
            self._db.close()


def _event_from_document(document: str) -> RunEvent:
    value = strict_json_loads(document)
    return RunEvent(
        event_id=value["event_id"], tenant_id=value["tenant_id"],
        workflow_id=value["workflow_id"], run_id=value["run_id"],
        agent_id=value["agent_id"], sequence=value["sequence"],
        occurred_at=datetime.fromisoformat(value["occurred_at"]) if value["occurred_at"] else None,
        recorded_at=datetime.fromisoformat(value["recorded_at"]),
        category=EventCategory(value["category"]), type=EventType(value["type"]),
        source=value["source"], trust_class=TrustClass(value["trust_class"]),
        durability=Durability(value["durability"]),
        classification=DataClassification(value["classification"]),
        visibility=EventVisibility(value["visibility"]), summary=value["summary"],
        payload=value["payload"], trace_id=value["trace_id"], span_id=value["span_id"],
        parent_event_id=value["parent_event_id"], registry_digest=value["registry_digest"],
        authority_revision=value["authority_revision"], schema_version=value["schema_version"],
    )
