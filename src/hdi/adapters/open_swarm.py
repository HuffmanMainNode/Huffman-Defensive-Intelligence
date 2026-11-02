import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from hdi.adapters.base import Adapter
from hdi.model import EventValidationError, HDIEvent


CLASSIFICATIONS = {"public", "internal", "restricted"}
PLATFORM_EVENT_COLUMNS = {
    "sequence", "event_id", "event_type", "schema_version", "occurred_at",
    "source", "classification", "correlation_id", "causation_id",
    "evidence_refs_json", "payload_json", "canonical_json",
}
PLATFORM_EVENT_FIELDS = {
    "event_id", "event_type", "source", "payload", "schema_version",
    "classification", "evidence_refs", "correlation_id", "causation_id",
    "occurred_at",
}


@dataclass(frozen=True)
class OpenSwarmImportResult:
    source_id: str
    imported_count: int
    last_sequence: int
    event_ids: tuple[str, ...]


class OpenSwarmAdapter(Adapter):
    """Normalize Open-Swarm PlatformEvent records."""

    project_id = "open_swarm"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("Open-Swarm adapter received another project's event")
        return event

    def normalize_platform_event(self, raw):
        if not isinstance(raw, dict) or set(raw) != PLATFORM_EVENT_FIELDS:
            raise EventValidationError("incomplete or unknown Open-Swarm PlatformEvent fields")
        if raw["schema_version"] != "1.0":
            raise EventValidationError("unsupported Open-Swarm event schema")
        if (not isinstance(raw["classification"], str)
                or raw["classification"] not in CLASSIFICATIONS):
            raise EventValidationError("invalid Open-Swarm classification")
        if not isinstance(raw["source"], str) or not raw["source"].strip():
            raise EventValidationError("Open-Swarm source is required")
        if not isinstance(raw["payload"], dict):
            raise EventValidationError("Open-Swarm payload must be an object")
        if not isinstance(raw["evidence_refs"], list) or len(raw["evidence_refs"]) > 100:
            raise EventValidationError("invalid Open-Swarm evidence_refs")
        if any(not isinstance(ref, str) or not ref.strip() or len(ref) > 512
               for ref in raw["evidence_refs"]):
            raise EventValidationError("invalid Open-Swarm evidence reference")
        event = HDIEvent(
            event_id=raw["event_id"],
            event_type=raw["event_type"],
            source_project="open_swarm",
            occurred_at=raw["occurred_at"],
            correlation_id=raw.get("correlation_id"),
            payload={
                "upstream": "open_swarm",
                "upstream_schema_version": raw["schema_version"],
                "source": raw["source"],
                "classification": raw["classification"],
                "payload": raw["payload"],
                "evidence_refs": raw["evidence_refs"],
                "causation_id": raw.get("causation_id"),
            },
        )
        event.validate()
        return event


class OpenSwarmSQLiteImporter:
    """Read-only importer for the upstream SQLiteEventBus platform_events table.

    It never mutates the source database. The HDI target journal stores the
    source sequence cursor atomically with normalized event and outbox writes.
    """

    def __init__(self, source_database: str | Path, *, source_id: str):
        if not isinstance(source_id, str) or not source_id.strip() or len(source_id) > 128:
            raise ValueError("source_id must contain 1 to 128 characters")
        path = Path(source_database)
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ValueError("Open-Swarm source database path must not traverse symlinks")
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("Open-Swarm source database does not exist") from exc
        if not resolved.is_file():
            raise ValueError("Open-Swarm source database must be a regular file")
        self.source_database = resolved
        self.source_id = source_id
        self.adapter = OpenSwarmAdapter()

    def _connect_read_only(self):
        db = sqlite3.connect(
            f"{self.source_database.as_uri()}?mode=ro",
            uri=True,
            timeout=5.0,
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def _read_batch(self, after_sequence: int, limit: int):
        if not isinstance(after_sequence, int) or isinstance(after_sequence, bool) or after_sequence < 0:
            raise ValueError("after_sequence must be a non-negative integer")
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with closing(self._connect_read_only()) as db:
            columns = {
                row["name"] for row in db.execute("PRAGMA table_info(platform_events)")
            }
            if columns != PLATFORM_EVENT_COLUMNS:
                raise EventValidationError("Open-Swarm platform_events schema does not match contract")
            rows = db.execute(
                """SELECT sequence,event_id,event_type,schema_version,occurred_at,source,
                          classification,correlation_id,causation_id,evidence_refs_json,
                          payload_json,canonical_json
                   FROM platform_events WHERE sequence>? ORDER BY sequence LIMIT ?""",
                (after_sequence, limit),
            ).fetchall()
        events = []
        event_ids = []
        last_sequence = after_sequence
        for row in rows:
            sequence = row["sequence"]
            if not isinstance(sequence, int) or sequence <= last_sequence:
                raise EventValidationError("Open-Swarm event sequence is not strictly increasing")
            try:
                raw = json.loads(row["canonical_json"])
                payload = json.loads(row["payload_json"])
                evidence_refs = json.loads(row["evidence_refs_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise EventValidationError("Open-Swarm source row contains invalid JSON") from exc
            if not isinstance(raw, dict) or set(raw) != PLATFORM_EVENT_FIELDS:
                raise EventValidationError("Open-Swarm canonical event has an invalid field set")
            canonical = json.dumps(
                raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
            if canonical != row["canonical_json"]:
                raise EventValidationError("Open-Swarm canonical event bytes do not match source")
            if raw["payload"] != payload or raw["evidence_refs"] != evidence_refs:
                raise EventValidationError("Open-Swarm indexed columns disagree with canonical event")
            for field in (
                "event_id", "event_type", "schema_version", "occurred_at", "source",
                "classification", "correlation_id", "causation_id",
            ):
                if raw[field] != row[field]:
                    raise EventValidationError(f"Open-Swarm source column mismatch: {field}")
            event = self.adapter.normalize_platform_event(raw)
            events.append(event)
            event_ids.append(event.event_id)
            last_sequence = sequence
        return events, tuple(event_ids), last_sequence

    def import_into(self, journal, *, limit: int = 100) -> OpenSwarmImportResult:
        """Import the next source batch with an atomic HDI cursor update."""
        source_identity = str(self.source_database)
        offset = journal.source_offset(self.source_id, source_identity=source_identity)
        events, event_ids, last_sequence = self._read_batch(offset, limit)
        if not events:
            return OpenSwarmImportResult(self.source_id, 0, offset, ())
        journal.append_batch_with_offset(
            events, source_id=self.source_id, last_sequence=last_sequence,
            source_identity=source_identity
        )
        return OpenSwarmImportResult(
            self.source_id, len(events), last_sequence, event_ids
        )

def ingest_open_swarm_batch(bus, journal, *, consumer_id="hdi-open-swarm", limit=100):
    """Durably ingest one Open-Swarm consumer batch into the HDI journal.

    The source consumer offset advances only after HDI append succeeds. If the
    process stops between append and acknowledgement, the source redelivers and
    HDI's event-ID/digest idempotency makes the retry safe.

    This is a local Python integration over the documented SQLiteEventBus
    interface. It does not open another repository's database automatically,
    start a background worker, or provide cross-host coordination.
    """
    if not isinstance(consumer_id, str) or not consumer_id.strip() or len(consumer_id) > 128:
        raise ValueError("consumer_id must contain 1 to 128 characters")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer between 1 and 1000")
    records = bus.read(consumer_id, limit=limit)
    accepted = []
    for record in records:
        raw_event = record.event.to_dict()
        normalized = OpenSwarmAdapter().normalize_platform_event(raw_event)
        digest = journal.append(normalized)
        bus.acknowledge(consumer_id, record.sequence)
        accepted.append({
            "event_id": normalized.event_id,
            "sequence": record.sequence,
            "digest": digest,
        })
    return accepted
