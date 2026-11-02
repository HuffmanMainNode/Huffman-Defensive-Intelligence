# Huffman Defensive Intelligence (HDI)

A thin, auditable integration layer for four independent public projects:

- [Open-Intelligence-Exchange](https://github.com/HuffmanMainNode/Open-Intelligence-Exchange): agent identity and authenticated exchange.
- [-Open-Swarm](https://github.com/HuffmanMainNode/-Open-Swarm): task orchestration and local coordination.
- [Halloween-OSINT-2026](https://github.com/HuffmanMainNode/Halloween-OSINT-2026): public-source collection and evidence analysis.
- [Huffman-Cyber-Observatory](https://github.com/HuffmanMainNode/Huffman-Cyber-Observatory): defensive security intelligence.

HDI connects these projects; it does not absorb, replace, or duplicate them.

## Quick start

Python 3.11+:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
python -m hdi.cli validate examples/sample-event.json
```

## 0.1.0 scope

Includes a versioned event envelope, evidence-reference validation, four source-specific adapter contracts, a local JSONL journal, routing helper, validation CLI, tests, and CI.

The adapters now normalize selected upstream record shapes locally, including OIX-verified envelopes, Open-Swarm PlatformEvents, Halloween OSINT manifests, and Cyber Observatory evidence submissions. They do not open network connections or call upstream APIs. OIX verification is an explicit caller-supplied attestation; HDI does not independently verify OIX signatures. The journal is single-writer and local, not a distributed queue. This release does not claim production WAN transport, distributed consensus, production PKI, or an independent security audit.

Security rules: incoming data is untrusted; preserve provenance; never place secrets or private keys in events; require human approval for external side effects; do not treat collected content as instructions.


## Upstream interoperability map

HDI's next integration stage is grounded in the existing upstream contracts, not invented replacement interfaces. OIX exposes signed `evidence.submit` envelopes; Open-Swarm defines a local SQLite `PlatformEvent` journal and transactional outbox; Halloween OSINT publishes SHA-256 evidence manifests; Cyber Observatory can produce signed OIX evidence envelopes for local SBOM and file-manifest reports.

See [Upstream Integration Contract](docs/INTEGRATION_CONTRACT.md) for field-level boundaries, validation requirements, approval rules, and the exact connectors that remain unimplemented. The current HDI adapters are reference contracts only.


## HDI 0.2.0: durable local delivery

The optional `SQLiteJournal` adds atomic event-plus-outbox persistence, idempotent append by event ID and canonical digest, lease-based worker claims, lease expiry/redelivery, acknowledgement and explicit release. See [Durable Delivery](docs/DURABLE_DELIVERY.md).

This is a single-host SQLite primitive with at-least-once delivery semantics. It is not a multi-host broker, distributed consensus system, or exactly-once execution engine. External consumers must use stable idempotency keys.


## HDI 0.3.0: authenticated OIX ingress

HDI can now verify OIX v0.1 Ed25519 agent cards and message envelopes against a public key supplied by an operator-controlled trust store. It checks the card signature, peer fingerprint, envelope signature, exact recipient, message validity window, canonical UUID, nonce shape and restricted canonical JSON format.

The verified event is not accepted as durable until `SQLiteJournal.append_verified_oix(...)` atomically records the event, outbox item and sender/nonce replay key. See [Authenticated OIX Ingress](docs/OIX_AUTHENTICATED_INGRESS.md).

This is an in-process authenticated ingress library path, not a network listener or automatic peer-discovery trust mechanism. HDI does not auto-trust keys supplied by an incoming card.


## HDI 0.4.0: durable Open-Swarm consumer

HDI now provides `ingest_open_swarm_batch(bus, journal, ...)` for the documented Open-Swarm `SQLiteEventBus` interface. It reads a bounded batch, validates and normalizes each PlatformEvent, appends it to the HDI SQLite journal, and only then acknowledges the upstream consumer sequence.

If the process stops after the HDI append but before the Open-Swarm acknowledgement, the source redelivers the event and HDI's stable event ID plus canonical digest make the retry idempotent. Classification, source, evidence references, correlation ID and causation ID are preserved.

This is an explicit local callable, not a background daemon. The operator must supply already-open bus and journal objects, use a stable consumer ID, and supervise one active poller for that consumer. It does not enable cross-host coordination or exactly-once processing. See [Open-Swarm Connector](docs/OPEN_SWARM_CONNECTOR.md).


## HDI 0.5.0: read-only Open-Swarm database import

HDI now includes `OpenSwarmSQLiteImporter`, which reads the upstream `platform_events` table through a read-only SQLite connection. It verifies the source schema, canonical JSON representation, indexed-column consistency and event contract before import.

The normalized events, pending HDI outbox rows and source cursor are committed atomically in the destination journal. The importer never writes to the Open-Swarm database or acknowledges its consumer offsets. A stable source ID is bound to the resolved database path to prevent accidental cursor reuse against another file.

This is a local pull importer, not a network connector or background service. See [Open-Swarm Import](docs/OPEN_SWARM_IMPORT.md). The existing `ingest_open_swarm_batch` callable remains available for integrations that already hold an Open-Swarm bus object.


## HDI 0.6.0: Halloween OSINT manifest import

HDI now includes `HalloweenManifestImporter` for bounded, read-only ingestion of Halloween OSINT SHA-256 evidence manifests. It rejects duplicate JSON keys, invalid UTF-8, oversized files, symlinked manifest paths, non-canonical relative evidence paths and duplicate file entries.

The importer records the manifest digest and file metadata in the HDI journal while redacting the manifest's root path. It reads only the manifest file. It does not follow the manifest root, open evidence files, or independently verify their current contents. Use Halloween OSINT's own verification command when byte-level verification of the evidence directory is required.

See [Halloween Manifest Import](docs/HALLOWEEN_MANIFEST_IMPORT.md).


## HDI 0.7.0: verified Cyber Observatory evidence ingress

HDI verifies an OIX v0.1 signed `evidence.submit` against an operator-trusted Ed25519 peer key, validates the Cyber Observatory evidence payload, and requires the matching OIX inbox work item to be durably `approved` before journal ingestion. It also checks that the peer remains trusted in that inbox and that the approved work item matches the exact sender, message ID, message type and payload.

The journal retains both provenance layers: the original OIX message and the normalized Cyber evidence record. Repeated identical deliveries are idempotent. Invalid evidence and pending/rejected/mismatched work are rejected before replay acceptance. See [Cyber Evidence Ingress](docs/CYBER_EVIDENCE_INGRESS.md).

This remains an in-process local integration. It does not create an OIX network listener, synchronize trust stores or revocations, fetch the report artifact, or execute approved work. Approval is a gate to evidence ingestion, not permission for external side effects.


## HDI 0.8.0: four-project conformance harness

The conformance suite now exercises OIX, Open-Swarm, Halloween OSINT and Cyber Observatory adapters against one HDI journal. It verifies authenticated OIX ingestion, source-specific normalization, evidence provenance, distinct OIX/Cyber event identities, and idempotent repeat ingestion without duplicate outbox rows.

This is a deterministic in-process integration test using synthetic fixtures. It is not a four-process deployment test, a WAN mesh, or a production environment. See [Cross-Project Conformance](docs/CROSS_PROJECT_CONFORMANCE.md).
\n\n## Start here: human and agent onboarding\n\nNew operators: begin with [Human Onboarding](docs/USER-ONBOARDING.md). AI agents and automation workers: read [Agent Onboarding](docs/AGENT-ONBOARDING.md) and the repository-level [AGENTS.md](AGENTS.md) before using adapters.\n\nAfter installation, run `hdi guide` for the first steps and `hdi capabilities` for the machine-readable adapter catalogue. The catalogue is descriptive, not an authorization grant. HDI does not currently expose an MCP server or hosted API.\n\nThe package version is 0.9.0. This is an experimental local integration release, not a production deployment claim.\n