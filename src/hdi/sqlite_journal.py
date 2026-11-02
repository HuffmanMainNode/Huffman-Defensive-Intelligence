from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import re
import uuid

from hdi.model import HASH, HDIEvent


class EventConflictError(ValueError):
    """An event ID was reused for different canonical event content."""


class LeaseError(ValueError):
    """A delivery operation does not own the active lease."""


class ReplayDetectedError(ValueError):
    """An OIX sender reused a nonce or message ID."""


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
                CREATE TABLE IF NOT EXISTS oix_replay (
                    sender TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    message_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
                    envelope_sha256 TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    accepted_at REAL NOT NULL,
                    PRIMARY KEY(sender, nonce)
                );
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


    def append_verified_oix(
        self,
        event: HDIEvent,
        *,
        sender: str,
        nonce: str,
        envelope_sha256: str,
        expires_at: int,
    ) -> str:
        """Atomically persist a cryptographically verified OIX event and replay key.

        The caller must use OIXAdapter.verify_and_normalize_envelope with a peer
        key resolved from an operator-controlled trust store. This method makes
        the nonce/message-ID replay decision durable in the same transaction as
        event and outbox insertion.
        """
        event.validate()
        if event.source_project != "oix":
            raise ValueError("append_verified_oix accepts only OIX events")
        if not isinstance(sender, str) or not re.fullmatch(r"ed25519:[a-f0-9]{64}", sender):
            raise ValueError("sender must be an OIX Ed25519 fingerprint")
        if not isinstance(nonce, str) or not 20 <= len(nonce) <= 128:
            raise ValueError("nonce must contain 20 to 128 characters")
        if not isinstance(envelope_sha256, str) or not HASH.fullmatch(envelope_sha256):
            raise ValueError("envelope_sha256 must be lowercase SHA-256")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at < 1:
            raise ValueError("expires_at must be a positive integer Unix timestamp")
        try:
            if str(uuid.UUID(event.event_id)) != event.event_id:
                raise ValueError
        except (ValueError, AttributeError) as exc:
            raise ValueError("OIX event_id must be a canonical UUID") from exc
        if (
            event.payload.get("sender_fingerprint") != sender
            or event.payload.get("envelope_sha256") != envelope_sha256
        ):
            raise ValueError("OIX event provenance does not match replay metadata")
        checks = event.payload.get("verification")
        required = ("signature_valid", "sender_trusted", "recipient_valid", "payload_schema_valid")
        if not isinstance(checks, dict) or any(checks.get(key) is not True for key in required):
            raise ValueError("OIX event lacks cryptographic and trust verification")
        payload = dict(event.payload)
        payload["verification"] = {**checks, "replay_checked": True}
        accepted_event = HDIEvent(
            event_id=event.event_id,
            event_type=event.event_type,
            source_project=event.source_project,
            occurred_at=event.occurred_at,
            payload=payload,
            evidence=event.evidence,
            schema_version=event.schema_version,
            correlation_id=event.correlation_id,
        )
        accepted_event.validate()
        digest = accepted_event.canonical_sha256()
        encoded = json.dumps(
            accepted_event.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False
        )
        now = self._clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT message_id,envelope_sha256 FROM oix_replay WHERE sender=? AND nonce=?",
                (sender, nonce),
            ).fetchone()
            if prior is not None:
                existing = db.execute(
                    "SELECT digest FROM events WHERE event_id=?", (prior["message_id"],)
                ).fetchone()
                if (
                    prior["message_id"] == accepted_event.event_id
                    and prior["envelope_sha256"] == envelope_sha256
                    and existing is not None
                    and existing["digest"] == digest
                ):
                    db.commit()
                    return digest
                db.rollback()
                raise ReplayDetectedError("OIX sender reused a previously accepted nonce")
            prior_message = db.execute(
                "SELECT nonce,envelope_sha256 FROM oix_replay WHERE sender=? AND message_id=?",
                (sender, accepted_event.event_id),
            ).fetchone()
            if prior_message is not None:
                db.rollback()
                raise ReplayDetectedError("OIX sender reused a previously accepted message ID")
            existing_event = db.execute(
                "SELECT digest FROM events WHERE event_id=?", (accepted_event.event_id,)
            ).fetchone()
            if existing_event is not None:
                db.rollback()
                raise EventConflictError("OIX message ID already exists outside replay acceptance")
            db.execute(
                "INSERT INTO events(event_id,digest,event_json,created_at) VALUES(?,?,?,?)",
                (accepted_event.event_id, digest, encoded, now),
            )
            db.execute(
                "INSERT INTO outbox(event_id,state,attempts) VALUES(?,'pending',0)",
                (accepted_event.event_id,),
            )
            db.execute(
                """INSERT INTO oix_replay(
                    sender,nonce,message_id,envelope_sha256,expires_at,accepted_at
                ) VALUES(?,?,?,?,?,?)""",
                (sender, nonce, accepted_event.event_id, envelope_sha256, expires_at, now),
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
