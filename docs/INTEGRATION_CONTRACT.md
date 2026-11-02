# Upstream integration contract

This document records the upstream interfaces inspected for HDI 0.1.0. It is a compatibility map, not a claim that HDI currently connects to them.

## OIX: signed message and evidence submission

Repository: https://github.com/HuffmanMainNode/Open-Intelligence-Exchange

Relevant upstream contract:
- `schemas/evidence-submit.schema.json` defines the strict 1.0 evidence payload.
- `evidence.submit` messages are signed OIX envelopes.
- Evidence metadata includes source URI/timestamps, collector and method identity, artifact SHA-256/size/media type, classification, status, summary, and limitations.
- OIX signature/schema validation establishes envelope integrity and sender-key possession. It does not prove factual accuracy or real-world identity.

HDI must consume an OIX message only after the OIX verifier has validated the signature, recipient, sender trust, expiry, replay state, and payload schema. HDI must preserve the original message ID, sender fingerprint, envelope digest, and validation outcome. A discovery announcement alone is not a trust grant.

## Open-Swarm: platform event journal

Repository: https://github.com/HuffmanMainNode/-Open-Swarm

Relevant upstream contract:
- `src/openswarm/events.py` defines `PlatformEvent`.
- Fields include event ID, event type, schema version, occurrence timestamp, source, classification, payload, evidence references, correlation ID, and causation ID.
- The SQLite journal is single-host and uses consumer acknowledgements with at-least-once delivery semantics.
- The outbox relay is transactional with task lifecycle changes. Duplicate event delivery is expected and consumers must be idempotent.

HDI must preserve event identity, classification, correlation/causation, and evidence references. It must not upgrade at-least-once delivery to an exactly-once claim. HDI must not treat remote task payloads as authorization or operator approval.

## Halloween OSINT: evidence manifests

Repository: https://github.com/HuffmanMainNode/Halloween-OSINT-2026

Relevant upstream contract:
- `schemas/evidence-manifest.schema.json` defines manifest version 1.0.
- The manifest includes creation timestamp, SHA-256 algorithm, root directory, and file records containing relative path, byte size, and SHA-256 digest.
- Domain observations and transaction analysis are bounded outputs with documented limitations.

HDI should ingest the manifest as a collection-level evidence record and retain each file's relative path, size, and digest. A file hash proves byte identity relative to the recorded digest, not source authenticity, ownership, or the truth of an analyst's interpretation.

## Cyber Observatory: OIX evidence bridge

Repository: https://github.com/HuffmanMainNode/Huffman-Cyber-Observatory

Relevant upstream contract:
- `src/huffman_cyber/oix_bridge.py` hashes a selected local report and creates a signed OIX `evidence.submit` envelope.
- Supported evidence types are `sbom_analysis` and `file_manifest`.
- The report bytes remain local; the envelope carries metadata and a digest.
- The receiving OIX inbox places validated evidence into pending review. An operator must approve it before downstream ingestion.

HDI must not bypass that approval boundary or imply that the report itself was transferred. A valid signed envelope is not a substitute for review of the underlying evidence.

## Required HDI adapter sequence

1. Identify the upstream project and exact contract version.
2. Bound input size before parsing.
3. Validate the upstream schema and reject unknown fields.
4. Verify signatures and sender trust in the upstream component where applicable.
5. Preserve source event/message IDs, timestamps, classification, and provenance.
6. Convert to the HDI event envelope without dropping uncertainty or limitations.
7. Apply local policy and human approval before task execution or external side effects.
8. Journal idempotently and acknowledge the upstream delivery only after durable persistence.
9. Record validation failures without executing embedded instructions.

## Not yet implemented in HDI 0.4.0

- Live OIX transport or signature verification.
- A continuously supervised Open-Swarm background relay or service.
- Halloween OSINT manifest reader.
- Cyber Observatory report bridge consumer.
- Cross-project end-to-end integration harness.

The above are the next engineering tasks, not current capabilities.


## Current HDI normalization entry points

- `OIXAdapter.normalize_verified_envelope(...)` maps a bounded OIX envelope after the caller supplies all required verification outcomes. HDI does not perform cryptographic signature verification, trust-store lookup, recipient verification, or replay checks itself.
- `OpenSwarmAdapter.normalize_platform_event(...)` preserves the upstream event source, classification, payload, evidence references, correlation ID, and causation ID.
- `HalloweenOSINTAdapter.normalize_manifest(...)` validates the manifest file records and creates a deterministic event ID from the canonical manifest digest.
- `CyberObservatoryAdapter.normalize_verified_evidence_submit(...)` accepts the Cyber evidence payload only with the same explicit OIX verification attestation and preserves artifact digest and sender provenance.

These are in-process normalization functions. The Open-Swarm consumer can be wired to an already-open upstream SQLiteEventBus and HDI SQLiteJournal; it does not discover or open either database automatically. The functions do not bypass the OIX inbox's pending-review state.


## Authenticated OIX ingress implementation

HDI 0.3.0 implements an in-process OIX v0.1 verification path using Ed25519 and the upstream restricted canonical JSON format. The caller must supply the peer public key obtained from an operator-controlled trust store. The signed card's public key must exactly match that trusted key; a self-signed card is not a trust grant.

After verification, `SQLiteJournal.append_verified_oix` atomically writes the HDI event, outbox row and sender/nonce replay record. Repeated identical deliveries are idempotent. Reused sender nonces or message IDs are rejected. Replay records are retained in the local database; do not delete them while messages may be replayed.

This does not yet provide a network listener, automatic OIX trust-store synchronization, peer-key revocation propagation, or multi-host replay consensus.


## Open-Swarm read-only importer implementation

HDI 0.5.0 adds `OpenSwarmSQLiteImporter` for local source database import. It opens the upstream SQLite file with `mode=ro` and `query_only`, validates the expected `platform_events` schema, canonical event bytes, indexed column consistency and normalized event contract. It commits normalized events, outbox rows and a source-specific sequence cursor atomically in the HDI target journal.

The importer does not mutate source events, consumer offsets or outbox state. It is a local pull mechanism and not a daemon or network connector. See `docs/OPEN_SWARM_IMPORT.md`.


## Halloween OSINT manifest importer implementation

HDI 0.6.0 adds `HalloweenManifestImporter` for bounded read-only ingestion of the upstream evidence-manifest v1.0 JSON format. It rejects duplicate JSON object keys, invalid UTF-8, oversized files, symlinked manifest paths, non-canonical relative file paths and duplicate file records. It preserves the manifest digest and file records while redacting the source root path from the normalized event.

The importer reads only the manifest file. It does not follow the root path, read evidence files or recalculate their hashes. Byte-level evidence verification remains the responsibility of the upstream Halloween OSINT verifier. See `docs/HALLOWEEN_MANIFEST_IMPORT.md`.


## Cyber Observatory verified evidence ingress implementation

HDI 0.7.0 adds `CyberObservatoryAdapter.verify_and_ingest_evidence_submit(...)`. It verifies the OIX v0.1 signed agent card and envelope using the operator-supplied trusted Ed25519 public key, requires the OIX message type `evidence.submit`, validates the Cyber evidence payload, atomically accepts the OIX sender/nonce replay record, and then appends a separate normalized Cyber evidence event.

The two events use distinct deterministic IDs: one records the authenticated OIX envelope and one records the normalized Cyber evidence metadata. Repeated identical deliveries are idempotent. The artifact itself is not transferred or fetched. The upstream OIX inbox's pending-review approval remains a separate workflow and is not bypassed by this local adapter. See `docs/CYBER_EVIDENCE_INGRESS.md`.
