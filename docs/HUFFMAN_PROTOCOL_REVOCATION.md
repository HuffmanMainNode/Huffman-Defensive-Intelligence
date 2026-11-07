# Huffman Protocol: OIX-to-Open-Swarm Revocation Boundary

**Status:** Implemented local lifecycle hardening across OIX and Open-Swarm. Not a distributed revocation protocol.

## Purpose

An OIX message can be authenticated and accepted while its sender is trusted, then wait for operator approval before it is dispatched into Open-Swarm. Trust may be revoked during that interval or after execution but before result delivery. The integration must not treat an earlier authentication or approval as permanently valid after the sender has been revoked.

## Implemented behavior

### OIX receive and revocation

OIX verifies the sender's signed identity, recipient, message integrity, expiry, replay state, and local capability policy before creating an inbound work item.

When SQLiteInbox.revoke_peer(agent_id) is called, one SQLite transaction:
1. removes the peer from the trusted-peer store;
2. changes that sender's pending_approval, pending_review, and approved inbound work to revoked;
3. records the revocation timestamp in the work decision timestamp field;
4. leaves the original inbox message available for audit;
5. if the shared OIX result outbox exists, changes that peer's pending-approval, approved, and signed-but-undelivered result records to rejected in the same transaction.

A later trust restoration does not reactivate those revoked work items or result records. New work requires a new signed message and a new operator decision.

### Open-Swarm dispatch and execution gates

Before an approved OIX task enters the Open-Swarm queue, OIXTaskHandoff checks the current trusted-peer record inside the same SQLite transaction used for the handoff. The bulk handoff query also excludes senders that are no longer trusted.

After a queued task is claimed, the runtime checks current peer trust again before invoking its adapter. If the sender has been revoked, the task is marked BLOCKED and the adapter is not called.

The queue completion transaction checks trust once more. If revocation occurs during model inference, the task is changed to BLOCKED, its generated output is discarded, and no new result outbox record is created. This closes the race between the pre-execution check and result persistence.

These checks are defense in depth. They protect the dispatch and completion boundaries even if an older or externally modified inbox database still contains an approved or dispatched row after peer trust has been removed.

### State transition contract

| State at revocation | Result | Meaning |
|---|---|---|
| pending_approval | revoked | Cannot be approved later |
| pending_review | revoked | Cannot be ingested later |
| approved | revoked | Cannot be dispatched later |
| dispatched, still queued | blocked before adapter | No model or adapter execution begins |
| running inference | blocked at completion | Inference is not interrupted; generated output is discarded |
| result pending_approval / approved / signed | rejected | No further signing or delivery is permitted |
| result delivered | delivered | Historical delivery remains recorded |
| revoked, then peer re-trusted | revoked / rejected | Old work and results are not revived |

### Explicit limitations

- This is a local same-SQLite-database guarantee, not network-wide revocation propagation.
- A running model inference is not interrupted; only its result is discarded and the task is marked BLOCKED.
- The current runtime has no arbitrary external tool execution. Any future side-effecting adapter must revalidate authority immediately before each effect.
- A downstream side effect already performed cannot be retroactively undone.
- A result already transmitted over a network cannot be retracted; the outbox gate only blocks not-yet-delivered results.
- The trusted-peer table is local operator state, not a federated root of trust.
- This is not an implementation of AAP. AAP remains the external authorization specification to evaluate for scoped grants, delegation, broker enforcement, and federated revocation.

## Verification evidence

The implementation is covered by separate regression suites:
- OIX tests that pending and approved work becomes terminally revoked and remains revoked after the peer is trusted again, and that pending or signed-but-undelivered result outbox entries become rejected.
- Open-Swarm tests that a revoked peer cannot dispatch an approved work item, that bulk handoff skips revoked senders, that queued tasks are blocked before adapter invocation, and that output is suppressed if revocation occurs during inference.
- Both repositories' configured Python 3.11, 3.12, and 3.13 CI matrices passed for the corresponding merged changes. Open-Swarm CI also runs Ruff and Bandit; OIX CI includes independent-process and multi-node demos.

The two repositories test their own boundaries. This is not yet a single end-to-end test that launches both projects as independent processes in one run.
