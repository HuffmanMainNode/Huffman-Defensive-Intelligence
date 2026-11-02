# Human onboarding

HDI is the integration workbench for four independent projects. It is a Python library and local CLI, not a hosted dashboard, agent model, network listener or mandatory service.

## 1. Choose the smallest useful starting point

| Goal | Start here |
|---|---|
| Preserve and inspect evidence | [Halloween OSINT](https://github.com/HuffmanMainNode/Halloween-OSINT-2026) · [setup guide](https://github.com/HuffmanMainNode/Halloween-OSINT-2026/blob/main/docs/USER-ONBOARDING.md) |
| Assess local software and security evidence | [Huffman Cyber Observatory](https://github.com/HuffmanMainNode/Huffman-Cyber-Observatory) · [setup guide](https://github.com/HuffmanMainNode/Huffman-Cyber-Observatory/blob/main/docs/USER-ONBOARDING.md) |
| Run local tasks and workers | [Open-Swarm](https://github.com/HuffmanMainNode/-Open-Swarm) · [setup guide](https://github.com/HuffmanMainNode/-Open-Swarm/blob/main/docs/USER-ONBOARDING.md) |
| Give independent agents signed identities and exchange messages | [Open Intelligence Exchange](https://github.com/HuffmanMainNode/Open-Intelligence-Exchange) · [setup guide](https://github.com/HuffmanMainNode/Open-Intelligence-Exchange/blob/main/docs/USER-ONBOARDING.md) |
| Normalize and route events across those projects | HDI |

You do not need to install all five projects to use one of them. Install only the project that solves the immediate job.

## 2. Install HDI

Requirements: Python 3.11 or newer and Git.

```bash
git clone https://github.com/HuffmanMainNode/Huffman-Defensive-Intelligence.git
cd Huffman-Defensive-Intelligence
python -m venv .venv
```

Activate the environment:

```bash
# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\\Scripts\\Activate.ps1
```

Install the project and development checks:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## 3. Verify your installation

```bash
hdi --version
hdi guide
hdi capabilities
hdi validate examples/sample-event.json
pytest -q
ruff check .
```

A valid sample prints its event ID and canonical SHA-256 digest. The digest is a content-integrity identifier, not a signature or proof that the event is true.

## 4. Understand the parts

- **OIX** handles agent identity, signed messages, peer trust and approval-gated inboxes.
- **Open-Swarm** handles task queues, workers, task approvals and local event delivery.
- **Halloween OSINT** handles evidence manifests, passive DNS/TLS observations and offline analysis of supplied transaction data.
- **Cyber Observatory** handles defensive security checks, SBOM/KEV correlation, integrity and cryptographic file operations.
- **HDI** validates and normalizes records, preserves provenance, and provides local integration and delivery primitives.

Read the relevant upstream project's own quick start before using its commands. HDI does not replace their safety controls or automatically start them.

## 5. First safe exercise

Validate the included synthetic event:

```bash
hdi validate examples/sample-event.json
```

Then inspect the machine-readable adapter catalogue:

```bash
hdi capabilities
```

No network calls, credentials, private keys, external actions or database writes are required for these two steps.

## 6. Connect projects deliberately

Before connecting an upstream project:

1. Read [the integration contract](INTEGRATION_CONTRACT.md) and the adapter-specific guide.
2. Install and configure that upstream project independently.
3. Use an operator-controlled trust store for OIX. Never trust a key merely because it arrived in an agent card.
4. Keep local databases and evidence artifacts under operator control.
5. Use stable event IDs and idempotent consumers. Delivery may be at least once.
6. Review restricted evidence and approve work explicitly.
7. Test with synthetic fixtures before using real records.

The adapters are local integration functions. HDI does not currently expose an MCP server, public API, hosted relay, or automatic network discovery.

## 7. Where to get help

- [Architecture](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
- [Integration contract](INTEGRATION_CONTRACT.md)
- [Cross-project conformance](CROSS_PROJECT_CONFORMANCE.md)
- [Roadmap](ROADMAP.md)
- [Contributing](../CONTRIBUTING.md)
- [Security reporting](../SECURITY.md)

If something fails, include the command, Python version, operating system, exact error, and whether the input is synthetic or real. Remove credentials, private keys, personal data and restricted evidence before sharing logs.

## Production warning

HDI 0.8.1 is an experimental local integration foundation. It is not production-ready. The current local journal and SQLite delivery primitives do not provide distributed consensus, a multi-host scheduler, exactly-once execution, production key custody or independent security certification. See the roadmap before deploying beyond a controlled test environment.
