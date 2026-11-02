# Open-Swarm read-only event import

HDI 0.5.0 can import events from the upstream Open-Swarm `SQLiteEventBus` database.

## Usage

```python
from hdi.adapters.open_swarm import OpenSwarmSQLiteImporter
from hdi.sqlite_journal import SQLiteJournal

target = SQLiteJournal("./hdi-state/events.sqlite")
source = OpenSwarmSQLiteImporter(
    "./openswarm-state/events.sqlite3",
    source_id="openswarm-primary-local",
)

result = source.import_into(target, limit=100)
print(result.imported_count, result.last_sequence)
```

Use a stable `source_id` for the same source database across restarts. HDI binds that cursor to the resolved source database path and rejects reuse of the same ID for a different path. If the database is intentionally moved, configure a new source ID or perform a reviewed cursor migration. The cursor is stored in the HDI target database, not in the Open-Swarm source database.

## Read-only and validation behavior

The importer opens the source with SQLite URI `mode=ro` and `PRAGMA query_only=ON`. It does not write source consumer offsets, mark upstream outbox records published, or mutate source events.

Before normalizing a batch it verifies:
- The source is a regular file and its path does not traverse symlinks.
- The `platform_events` table has the expected v1 columns.
- Sequence numbers increase strictly.
- Canonical JSON parses to the exact PlatformEvent field set.
- Re-serialized canonical JSON exactly matches the stored canonical bytes.
- Indexed source columns match their values in canonical JSON.
- The event passes HDI's strict event validation.

A malformed row aborts the batch before any HDI cursor advancement.

## Atomic target import

The target HDI journal stores:
- normalized events,
- corresponding pending outbox rows,
- a stable source ID and last imported source sequence.

Those writes happen in one SQLite `BEGIN IMMEDIATE` transaction. If an event conflicts with existing HDI content, the batch and cursor update roll back together. If the process crashes after commit, the next import resumes after the stored cursor.

Identical event IDs and canonical content are idempotent. Reusing an event ID with different content raises a conflict.

## Data mapping

The adapter preserves the original Open-Swarm `source`, `classification`, payload, evidence references, schema version, correlation ID and causation ID inside the normalized HDI event. The normalized event source project is `open_swarm`; this does not rewrite the originating collector identity.

The importer copies event records only. It does not import Open-Swarm task prompts, model outputs outside the event journal, private database tables, or task/outbox state.

## Operational boundaries

- Local file access only. No socket listener, API client or remote database transport.
- The importer is pull-based and must be invoked by an operator or a future supervised local service.
- It does not acknowledge or mutate the source event stream.
- It does not provide a source-side lease. Two HDI importers using the same `source_id` share one target cursor; do not run them as competing independent importers.
- The target SQLite journal is single-host. This is not multi-host replication, distributed consensus or exactly-once delivery.
- Outbox delivery remains at least once. Consumers must deduplicate external side effects by event ID.
