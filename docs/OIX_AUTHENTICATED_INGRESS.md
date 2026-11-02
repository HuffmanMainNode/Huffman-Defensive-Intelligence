# Authenticated OIX ingress

HDI 0.3.0 implements a local verification and durable-acceptance path for OIX v0.1 signed messages.

## Trust boundary

The caller supplies both:
1. The signed OIX agent card received from the peer.
2. The peer Ed25519 public key resolved from an operator-controlled OIX trust store.

HDI verifies that the card's public key exactly equals the operator-trusted key, that the card fingerprint matches that key, and that the card self-signature is valid. A card's self-signature proves possession of its own private key. It does not grant trust. Never resolve the trusted key from an untrusted incoming message and pass it through as trusted.

## Verification sequence

`OIXAdapter.verify_and_normalize_envelope(...)` validates:
- Exact v0.1 agent-card and message-envelope field sets.
- Ed25519 public-key length, card signature, and fingerprint.
- Operator-trusted key equality.
- Exact local recipient identity.
- Ed25519 message signature over the upstream canonical body bytes.
- OIX restricted canonical JSON rules, including Unicode NFC normalization and rejection of floats/non-string object keys.
- Message UUID, nonce bounds, capability bounds, 1 MB envelope cap, and 1 to 86400 second validity window.
- Issued-at clock skew no more than 60 seconds into the future and non-expired message.

It returns a `VerifiedOIXMessage` containing the normalized event and the sender/nonce/envelope digest/expiry metadata needed for durable replay acceptance.

## Durable acceptance

Pass the verified message to:

```python
journal.append_verified_oix(
    verified.event,
    sender=verified.sender,
    nonce=verified.nonce,
    envelope_sha256=verified.envelope_sha256,
    expires_at=verified.expires_at,
)
```

The SQLite transaction writes the HDI event, outbox row, and sender/nonce replay record together. The stored event records `replay_checked: true` only after that transaction's replay gate is passed.

- Same sender + same nonce + same message ID + same envelope digest is an idempotent duplicate.
- Same sender + reused nonce with a different message is rejected.
- Same sender + reused message ID with a new nonce is rejected.
- A message ID already present in the HDI event store without a matching OIX replay record is rejected rather than silently adopted.

Replay records are durable and retained in the database. Deleting them weakens replay protection. Back up and restore them with the event database.

## What this does not do

- It does not open a socket or run an OIX listener.
- It does not fetch or automatically trust peer cards.
- It does not synchronize peer-key revocation or rotation from OIX.
- It does not independently query the upstream OIX SQLite trust store. The caller must resolve the trusted key from that operator-controlled store.
- It does not provide distributed replay consensus or cross-host exactly-once processing.
- It does not execute received task payloads. The resulting event is data for local policy and approval workflows.

The outbox remains at-least-once. Downstream consumers must deduplicate external side effects using stable event IDs.
