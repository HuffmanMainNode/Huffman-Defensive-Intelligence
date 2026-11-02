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
