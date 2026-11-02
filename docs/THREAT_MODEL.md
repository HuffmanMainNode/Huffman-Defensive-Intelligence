# Threat Model

## Assets
Evidence integrity, source provenance, agent identity, task approvals, credentials and availability.

## Threats
Malformed/oversized payloads; source spoofing; replay/duplicate delivery; poisoned public-source evidence; prompt injection embedded in collected documents; SSRF/path traversal in upstream collectors; credential leakage; unauthorized task execution; journal truncation/tampering.

## Current controls
Strict field allowlist; source-project allowlist; adapter source checks; timezone-aware timestamps; payload size cap; evidence hash-format validation; canonical event digest; malformed journal record detection; no network side effects in reference adapters.

## Gaps
No HDI event signature verification, key rotation/revocation, distributed replay cache, transactional durability guarantee, multi-writer lock, schema negotiation or independent penetration test.

Treat collected content as data, never instructions. Require human approval before external actions. Do not ingest credentials or non-public personal information.
