# Open-Swarm durable consumer

HDI 0.4.0 adds an explicit local connector from the documented Open-Swarm `SQLiteEventBus` consumer interface into the HDI `SQLiteJournal`.

## Example

```python
from openswarm.events import SQLiteEventBus
from hdi.adapters.open_swarm import ingest_open_swarm_batch
from hdi.sqlite_journal import SQLiteJournal

source = SQLiteEventBus("/var/lib/openswarm/events.sqlite3")
destination = SQLiteJournal("/var/lib/hdi/events.sqlite3")

receipts = ingest_open_swarm_batch(
    source,
    destination,
    consumer_id="hdi-open-swarm",
    limit=100,
)
print(f"durably ingested {len(receipts)} events")
```

Install the Open-Swarm package in the same Python environment or otherwise provide its documented `SQLiteEventBus` object. HDI deliberately does not add Open-Swarm as a runtime dependency and does not guess database paths.

## Processing order

For each source record, HDI:

1. Reads the PlatformEvent and converts it to its strict dictionary representation.
2. Validates the exact upstream field set, schema version, classification, source, evidence-reference bounds and HDI event constraints.
3. Preserves the source event ID, event type, timestamp, classification, payload, evidence references, correlation ID and causation ID.
4. Appends the normalized event to the HDI journal. The HDI journal atomically persists the event and its local delivery outbox.
5. Acknowledges the Open-Swarm consumer sequence only after the HDI append returns successfully.

## Crash and retry behavior

If the process stops before the HDI append, the source offset remains unchanged and the event is delivered again.

If it stops after the HDI append but before source acknowledgement, Open-Swarm redelivers the same event. HDI recognizes the stable event ID and canonical digest and treats the append as idempotent. The connector can then acknowledge the source sequence.

If an event with the same ID has different content, HDI raises an event conflict. If validation fails, the connector raises and does not acknowledge that record. This intentionally leaves a poison event visible for operator investigation rather than silently discarding it.

## Operational requirements

- Use the same stable consumer ID across restarts.
- Run one active poller for that consumer ID.
- Keep both SQLite databases on the same host or supported local storage.
- Protect both databases and their backups. File permissions are not encryption.
- Supervise the callable externally; HDI does not create a daemon or schedule polling.
- Do not assume exactly-once delivery. The source-to-destination boundary is at-least-once with idempotent destination writes.
- Review event classification before exporting data beyond the local host. A `public` label is producer-supplied metadata, not an egress authorization decision.
- Do not execute task payloads merely because they arrived through this connector. Task authorization remains an independent local policy and approval decision.

## What is not included

This connector does not open the upstream database automatically, perform network transport, coordinate pollers across hosts, encrypt either database, or bridge remote Open-Swarm workers. It does not claim a distributed event bus.
