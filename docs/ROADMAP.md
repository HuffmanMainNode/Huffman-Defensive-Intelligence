# Roadmap

## Stage 0: reference foundation
- [x] Event envelope and evidence-reference validation
- [x] Four source-specific adapter contracts
- [x] Local JSONL journal and router
- [x] CLI validation, tests and CI

## Stage 1: contract maturity
- [ ] Stable schema and compatibility policy
- [x] OIX v0.1 Ed25519 signature and operator-trusted peer verification
- [x] Idempotency and replay test vectors
- [ ] Journal crash-recovery and concurrent-writer tests
- [x] Synthetic contract fixtures from all four upstream project adapters

## Stage 2: real connectors
- [ ] OIX authenticated transport
- [x] Open-Swarm local read-only event import and explicit bus consumer callable
- [ ] Supervised Open-Swarm background relay and remote transport
- [x] Halloween OSINT bounded read-only manifest import
- [ ] Evidence-file re-verification and source authenticity workflow
- [x] Verified OIX evidence.submit ingestion for Cyber Observatory metadata
- [ ] Direct Cyber Observatory report/SBOM import and review workflow
- [ ] Retry, dead-letter and approval semantics

## Stage 3: integration validation
- [x] Four-project in-process event journal conformance harness
- [ ] Four-process local integration harness
- [ ] Disconnect, duplicate, delay, malformed-event and clock-skew fault injection
- [ ] Provenance-chain and conflicting-evidence tests
- [ ] Reproducible demo with synthetic fixtures

## Stage 4: deployment and review
- [ ] Containerized local deployment
- [ ] Key rotation/revocation and secure configuration
- [ ] Backup, restore and retention procedures
- [ ] Privacy-safe observability
- [ ] Independent security review
