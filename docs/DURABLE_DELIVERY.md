# Durable journal and delivery semantics

HDI 0.2 adds an optional SQLite-backed journal alongside the original JSONL reference journal.

## Guarantees

- Event insertion and outbox creation occur in one SQLite transaction.
- Event IDs are unique. Repeating the same event ID and canonical digest is idempotent; reusing an ID for different content raises `EventConflictError`.
- SQLite WAL mode, full synchronous commits, foreign keys and a busy timeout are enabled.
- Workers claim pending events under an atomic write transaction and receive a time-bounded lease plus a unique random per-claim fencing token.
- Acknowledge and release require both the worker ID and exact lease token. Expired leases are rejected even before another worker reclaims them; a later claim receives a different token, including when the worker ID is reused.
- Existing databases are migrated by invalidating legacy owner-only leases and returning those events to pending for safe redelivery.
- Delivery is **at least once**. A worker can perform an external side effect and crash before acknowledging. Consumers must deduplicate by event ID or another stable idempotency key.

## Minimal usage

```python
from hdi.sqlite_journal import SQLiteJournal

journal = SQLiteJournal("./state/hdi.sqlite")
journal.append(event)

delivery = journal.claim_next("worker-01", lease_seconds=30)
if delivery is not None:
    process_idempotently(delivery.event, idempotency_key=delivery.event_id)
    journal.acknowledge(delivery.event_id, "worker-01", delivery.lease_token)
```

On transient failure, call `release(event_id, worker_id, lease_token)` using the token returned with that delivery; if a worker disappears, the lease expires and the event becomes claimable again.

## Boundaries

This is a single-host SQLite component. SQLite supports concurrent local processes through its locking and transaction model, but this is not multi-host replication, consensus, exactly-once delivery, or a broker cluster. Back up the database and its WAL using SQLite-aware backup procedures. Do not copy a live database file alone and assume it is a consistent backup.
