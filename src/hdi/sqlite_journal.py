from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import time

from hdi.model import HDIEvent


class EventConflictError(ValueError):
    """An event ID was reused for different canonical event content."""


class LeaseError(ValueError):
    """A delivery operation does not own the active lease."""


@dataclass(frozen=True)
class Delivery:
    event: HDIEvent
    event_id: str
    digest: str
    attempts: int
    lease_owner: str
    lease_until: float


class SQLiteJournal:
    """Durable, idempotent local journal with an at-least-once delivery outbox.

    Each append and outbox insert commit in one SQLite transaction. Re-appending
    the same event ID and digest is idempotent. Reusing an ID with different
    content is rejected. A delivery can be claimed by one lease owner at a time;
    expired leases become eligible for redelivery.
    """

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time):
        self.path = str(path)
        self._clock = clock
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    digest TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    event_id TEXT PRIMARY KEY REFERENCES events(event_id),
                    state TEXT NOT NULL CHECK(state IN ('pending','leased','delivered')),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    lease_owner TEXT,
                    lease_until REAL,
                    delivered_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_outbox_delivery
                    ON outbox(state, lease_until, event_id);
            """)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA busy_timeout=10000")
            yield db
        finally:
            db.close()

    def append(self, event: HDIEvent) -> str:
        event.validate()
        digest = event.canonical_sha256()
        encoded = json.dumps(
            event.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False
        )
        now = self._clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT digest FROM events WHERE event_id=?", (event.event_id,)
            ).fetchone()
            if existing:
                if existing["digest"] != digest:
                    db.rollback()
                    raise EventConflictError(
                        f"event_id {event.event_id!r} already exists with different content"
                    )
                db.commit()
                return digest
            db.execute(
                "INSERT INTO events(event_id,digest,event_json,created_at) VALUES(?,?,?,?)",
                (event.event_id, digest, encoded, now),
            )
            db.execute(
                "INSERT INTO outbox(event_id,state,attempts) VALUES(?,'pending',0)",
                (event.event_id,),
            )
            db.commit()
        return digest

    def get(self, event_id: str) -> HDIEvent | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT event_json FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
        return HDIEvent.from_dict(json.loads(row["event_json"])) if row else None

    def read_all(self) -> Iterator[HDIEvent]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT event_json FROM events ORDER BY created_at,event_id"
            ).fetchall()
        for row in rows:
            yield HDIEvent.from_dict(json.loads(row["event_json"]))

    def claim_next(self, worker_id: str, *, lease_seconds: float = 30.0) -> Delivery | None:
        if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 128:
            raise ValueError("worker_id must be a non-empty string of at most 128 characters")
        if not isinstance(lease_seconds, (int, float)) or isinstance(lease_seconds, bool):
            raise TypeError("lease_seconds must be a number")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be a positive number")
        now = self._clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""
                SELECT e.event_id,e.digest,e.event_json,o.attempts
                FROM outbox o JOIN events e USING(event_id)
                WHERE o.state='pending'
                   OR (o.state='leased' AND o.lease_until <= ?)
                ORDER BY e.created_at,e.event_id
                LIMIT 1
            """, (now,)).fetchone()
            if row is None:
                db.commit()
                return None
            lease_until = now + float(lease_seconds)
            attempts = row["attempts"] + 1
            db.execute("""
                UPDATE outbox
                SET state='leased', attempts=?, lease_owner=?, lease_until=?
                WHERE event_id=?
            """, (attempts, worker_id, lease_until, row["event_id"]))
            db.commit()
        return Delivery(
            event=HDIEvent.from_dict(json.loads(row["event_json"])),
            event_id=row["event_id"], digest=row["digest"], attempts=attempts,
            lease_owner=worker_id, lease_until=lease_until,
        )

    def acknowledge(self, event_id: str, worker_id: str) -> bool:
        """Mark a leased event delivered. Returns False for an already-delivered event."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,lease_owner FROM outbox WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None:
                db.rollback()
                raise KeyError(event_id)
            if row["state"] == "delivered":
                db.commit()
                return False
            if row["state"] != "leased" or row["lease_owner"] != worker_id:
                db.rollback()
                raise LeaseError("worker does not own the active delivery lease")
            db.execute("""
                UPDATE outbox SET state='delivered', lease_owner=NULL,
                    lease_until=NULL, delivered_at=? WHERE event_id=?
            """, (self._clock(), event_id))
            db.commit()
        return True

    def release(self, event_id: str, worker_id: str) -> None:
        """Return a leased event to pending after a transient delivery failure."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,lease_owner FROM outbox WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None:
                db.rollback()
                raise KeyError(event_id)
            if row["state"] != "leased" or row["lease_owner"] != worker_id:
                db.rollback()
                raise LeaseError("worker does not own the active delivery lease")
            db.execute("""
                UPDATE outbox SET state='pending', lease_owner=NULL, lease_until=NULL
                WHERE event_id=?
            """, (event_id,))
            db.commit()

    def outbox_counts(self) -> dict[str, int]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT state,COUNT(*) AS count FROM outbox GROUP BY state"
            ).fetchall()
        counts = {"pending": 0, "leased": 0, "delivered": 0}
        counts.update({row["state"]: row["count"] for row in rows})
        return counts
