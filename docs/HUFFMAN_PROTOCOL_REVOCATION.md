# Huffman Protocol: OIX-to-Open-Swarm Revocation Boundary

**Status:** Implemented local lifecycle hardening across OIX and Open-Swarm. Not a distributed revocation protocol.

## Purpose

An OIX message can be authenticated and accepted while its sender is trusted, then wait for operator approval before it is dispatched into Open-Swarm. Trust may be revoked during that interval. The integration must not treat an earlier authentication or approval as permanently valid after the sender has been revoked.

## Implemented behavior

### OIX receive and revocation

OIX verifies the sender's signed identity, recipient, message integrity, expiry, replay state, and local capability policy before creating an inbound work item.

When SQLiteInbox.revoke_peer(agent_id) is called, one SQLite transaction:
1. removes the peer from the trusted-peer store;
2. changes that sender's pending_approval, pending_review, and approved inbound work to revoked;
3. records the revocation timestamp in the work decision timestamp field;
4. leaves the original inbox message available for audit.

A later trust restoration does not reactivate those revoked work items. New work requires a new signed message and a new operator decision.

### Open-Swarm dispatch gate

Before an approved OIX task enters the Open-Swarm queue, OIXTaskHandoff checks the current trusted-peer record inside the same SQLite transaction used for the handoff. The bulk handoff query also excludes senders that are no longer trusted.

This is defense in depth. It protects the dispatch boundary even if an older or externally modified inbox database still contains an approved row after peer trust has been removed.

### State transition contract

| State at revocation | Result | Meaning |
|---|---|---|
| pending_approval | revoked | Cannot be approved later |
| pending_review | revoked | Cannot be ingested later |
| approved | revoked | Cannot be dispatched later |
| dispatched | unchanged | Already crossed the dispatch boundary |
| revoked, then peer re-trusted | revoked | Old work is not revived |

### Explicit limitations

- This is a local same-SQLite-database guarantee, not network-wide revocation propagation.
- Work already marked dispatched is not automatically canceled.
- A running model inference or downstream side effect is not retroactively undone.
- Result delivery and in-flight cancellation need their own lifecycle gates.
- The trusted-peer table is local operator state, not a federated root of trust.
- This is not an implementation of AAP. AAP remains the external authorization specification to evaluate for scoped grants, delegation, broker enforcement, and federated revocation.

## Verification evidence

The implementation is covered by separate regression suites:
- OIX tests that pending and approved work becomes terminally revoked and remains revoked after the peer is trusted again.
- Open-Swarm tests that a revoked peer cannot dispatch an approved work item and that bulk handoff skips revoked senders.
- Both repositories' configured Python 3.11, 3.12, and 3.13 CI matrices passed for the corresponding merged changes. Open-Swarm CI also runs Ruff and Bandit; OIX CI includes independent-process and multi-node demos.

The two repositories test their own boundaries. This is not yet a single end-to-end test that launches both projects as independent processes in one run.
