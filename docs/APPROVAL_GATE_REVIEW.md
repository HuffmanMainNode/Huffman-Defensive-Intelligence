# HDI approval-gate design review

Review scope: the local Cyber Observatory `evidence.submit` ingress path added in HDI 0.7.0 and hardened in 0.8.1.

## Required state transition

```text
untrusted signed envelope
        |
        v
OIX signature + trusted peer + recipient + validity verification
        |
        v
OIX SQLiteInbox.receive()
        |
        v
pending_review
        |
        | explicit operator decision
        v
approved
        |
        v
HDI verifies current peer trust and exact work record
        |
        v
HDI replay acceptance + original OIX event/outbox
        |
        v
HDI normalized Cyber evidence event/outbox
```

A signature proves possession of a private key corresponding to a trusted public key. It does not establish operator approval, factual accuracy, real-world identity, or permission for unrelated external side effects.

## Enforcement points

HDI requires a caller-supplied OIX inbox object exposing the read-only `trusted_peer_public_key(agent_id)` and `get_work(work_id)` methods, plus the exact work ID. Before writing to the HDI journal it:

1. Independently verifies the signed card and envelope.
2. Resolves the sender's currently trusted public key from the supplied inbox and requires an exact key match.
3. Reads the durable work item through the inbox's read-only `get_work(work_id)` method.
4. Requires approved status, evidence.submit work type, exact sender, exact message ID, exact payload and a recorded decision timestamp.
5. Validates the Cyber evidence payload against the upstream OIX evidence schema limits.
6. Only then accepts the replay key and appends the two HDI provenance records.

OIX `get_work` does not change state. OIX `decide_work` remains the operator-controlled one-way decision. HDI does not call it.

## Recovery and idempotency

The OIX envelope event, its outbox row and its sender/nonce replay record are committed atomically by `SQLiteJournal.append_verified_oix`. The normalized Cyber event is appended afterward under a deterministic event ID derived from the OIX message ID.

If the process stops between those two transactions, retrying the same signed envelope reuses the already-accepted OIX event and can finish the normalized append. If the event ID is reused with different content, the journal conflict path must reject it.

## Regression matrix

| Scenario | Expected result |
|---|---|
| Valid signature, pending review | Reject before HDI writes |
| Valid signature, rejected work | Reject before HDI writes |
| Approved work for another sender | Reject |
| Approved work for another message ID | Reject |
| Approved work with changed payload | Reject |
| Peer revoked from OIX inbox | Reject |
| Invalid evidence metadata | Reject before replay acceptance |
| Tampered envelope | Reject signature |
| Reused sender nonce with new message ID | Reject replay |
| Crash after OIX replay acceptance | Retry completes normalized event |
| Repeated exact approved delivery | No duplicate events or outbox rows |

## Residual limitations

- The HDI adapter consumes a live local OIX inbox object. It does not create a network listener or synchronize inbox databases.
- OIX and HDI use separate SQLite databases. The approval lookup and HDI journal write are not one cross-database transaction. The approval decision is checked immediately before HDI replay acceptance, but a later OIX revocation or operator policy change cannot retroactively erase an already-ingested HDI event.
- The supplied inbox object is a local application dependency. A hostile caller can replace it with a fake object; this API is a fail-closed integration guardrail, not a security boundary against malicious code already executing inside the trusted HDI process.
- A recorded approval is evidence of a local OIX state transition, not a cryptographically signed approval receipt. A future cross-process deployment should define a signed, auditable approval receipt or a transactionally shared review service.
- Approval gates ingestion of evidence metadata. It does not authorize public release, task execution, wallet actions, system changes or other external side effects.
- Artifact bytes are not transferred or re-hashed by HDI. The source artifact's digest and limitations remain claims from the submitting evidence producer.

## Release gate

Do not describe this integration as production-ready. Before production use, require CI across supported Python versions, four-process fault-injection tests, cross-database recovery tests, key-rotation/revocation tests, backup/restore drills and independent security review.
