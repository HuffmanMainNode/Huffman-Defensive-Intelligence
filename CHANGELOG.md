# Changelog

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
