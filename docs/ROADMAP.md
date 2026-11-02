# Roadmap

## Stage 0: reference foundation
- [x] Human first-run onboarding and project selection guide
- [x] Agent onboarding and repository operating contract
- [x] Machine-readable capability catalogue and CLI discovery commands
- [x] Event envelope and evidence-reference validation
- [x] Four source-specific adapter contracts
- [x] Local JSONL journal and router
- [x] CLI validation, tests and CI

## Stage 1: contract maturity
- [ ] Stable schema and compatibility policy
- [ ] User-facing diagnostic command for local connector prerequisites
- [x] OIX v0.1 Ed25519 signature and operator-trusted peer verification
- [x] Idempotency and replay test vectors
- [x] Journal duplicate-ID rejection, fsync append, and valid-record newline recovery tests
- [x] SQLiteJournal concurrent local-writer safety (transactional backend); JSONL remains single-writer
- [x] Synthetic contract fixtures from all four upstream project adapters

## Stage 2: real connectors
- [ ] OIX authenticated transport
- [x] Open-Swarm local read-only event import and explicit bus consumer callable
- [ ] Supervised Open-Swarm background relay and remote transport
- [x] Halloween OSINT bounded read-only manifest import
- [ ] Evidence-file re-verification and source authenticity workflow
- [x] Verified OIX evidence.submit ingestion for Cyber Observatory metadata
- [ ] Direct Cyber Observatory report/SBOM import and review workflow
- [ ] Dead-letter policy and bounded retry/backoff semantics
- [x] At-least-once outbox claims, lease expiry/redelivery, explicit release, and per-claim fencing-token acknowledgement

## Stage 3: integration validation
- [x] Four-project in-process event journal conformance harness
- [x] Four-process local integration harness (synthetic fixtures, local SQLite only)
- [x] Local duplicate, malformed-event, OIX clock-skew, lease-expiry/restart, batch-rollback and concurrent-writer fault tests
- [ ] Network disconnect/delay and hard process-termination fault injection
- [ ] Provenance-chain and conflicting-evidence tests
- [x] Reproducible four-process demo with synthetic fixtures

## Stage 4: deployment and review
- [ ] Containerized local deployment
- [ ] Key rotation/revocation and secure configuration
- [ ] Backup, restore and retention procedures
- [ ] Privacy-safe observability
- [ ] Independent security review
