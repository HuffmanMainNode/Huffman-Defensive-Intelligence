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
