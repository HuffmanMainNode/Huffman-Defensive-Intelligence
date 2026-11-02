# Changelog

## 0.4.0
- Added a read-only Open-Swarm SQLiteEventBus importer.
- Added canonical source-row verification and schema fingerprint checks.
- Added atomic source cursor advancement with normalized event/outbox persistence.
- Added batch rollback, corruption, resume and symlink-path tests.

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
