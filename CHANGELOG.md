# Changelog

## 0.6.0
- Added a bounded, read-only Halloween OSINT manifest importer.
- Rejected duplicate JSON keys, oversized files, symlinked manifest paths and unsafe/duplicate evidence paths.
- Preserved manifest and per-file SHA-256 provenance while redacting the source root path.
- Added deterministic idempotent journal import and security-focused tests.


## 0.5.0
- Added a read-only Open-Swarm SQLite event importer with source schema and canonical-row integrity checks.
- Added atomic source cursor, event and outbox persistence with resume and conflict rollback.
- Bound import cursors to resolved source database identity and rejected symlink paths.
- Added importer tests for read-only access, corruption, idempotency, conflict rollback and restart recovery.


## 0.4.0
- Added a durable Open-Swarm consumer that appends normalized events to HDI before acknowledging the source offset.
- Added retry-safe idempotent ingestion across the append/ack crash window.
- Added tests for provenance preservation, failed acknowledgements, invalid classification, and batch bounds.


## 0.3.0
- Added OIX v0.1 Ed25519 signed-agent-card and message-envelope verification.
- Added operator-trusted peer-key matching and exact recipient/time-window checks.
- Added atomic SQLite sender/nonce and message-ID replay acceptance with event/outbox writes.
- Added authenticated-ingress and durable replay test coverage.

## 0.2.0
- Added a transactional SQLite event journal and leased delivery outbox.
- Added idempotent event insertion and conflicting event-ID detection.
- Added at-least-once delivery, lease expiry, acknowledgement and release semantics.
- Added tests and explicit single-host durability boundaries.

## 0.1.0
- Initial reference integration package.
- Added versioned event envelope and evidence references.
- Added four source-specific adapter contracts.
- Added local JSONL journal, routing helper and validation CLI.
- Added CI and initial conformance tests.
