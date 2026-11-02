# Cross-project conformance harness

HDI 0.8.0 includes a deterministic integration test that sends representative events from all four upstream projects through their current HDI adapter paths and into one local SQLite journal.

## Covered paths

- **OIX:** Ed25519 signed agent card and signed task-request envelope, verified against an operator-trusted key and accepted through the durable sender/nonce replay gate.
- **Open-Swarm:** versioned PlatformEvent normalization with source, classification, evidence references, correlation and causation metadata.
- **Halloween OSINT:** bounded manifest import with deterministic event identity and root-path redaction. The test does not open the referenced evidence directory.
- **Cyber Observatory:** signed OIX `evidence.submit`, strict evidence payload validation, durable OIX replay acceptance, and a separate normalized Cyber evidence event.

## Invariants tested

1. All four project identities are represented in the same HDI journal.
2. Every normalized event passes the HDI event validator.
3. OIX sender, signature and replay checks are required for signed ingress.
4. The original OIX envelope and normalized Cyber evidence event retain distinct IDs.
5. Evidence hashes and source provenance remain attached to the appropriate event.
6. Reprocessing the same signed messages, PlatformEvent and manifest does not create duplicate journal records or outbox rows.
7. The resulting outbox contains five durable records: one OIX task request, one Open-Swarm event, one Halloween manifest event, and two Cyber/OIX evidence provenance records.

## Run

```bash
python -m pip install -e ".[dev]"
pytest -q tests/test_four_project_conformance.py
```

## Scope limits

This is an in-process conformance harness with synthetic data and generated test keys. It is not a four-process deployment test, network transport test, independent security audit, or proof of production interoperability across arbitrary versions of the upstream repositories.

The harness validates the current documented contracts represented in HDI fixtures. Upstream schema changes must be reviewed and reflected in the adapters and tests before being treated as compatible.
