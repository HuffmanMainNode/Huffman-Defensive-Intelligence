# Cyber Observatory verified evidence ingress

HDI 0.8.1 connects Cyber Observatory's metadata-only OIX evidence bridge to the HDI event journal.

## Usage

```python
from hdi.adapters.cyber_observatory import CyberObservatoryAdapter
from hdi.sqlite_journal import SQLiteJournal

journal = SQLiteJournal("./hdi-state/events.sqlite")
receipt = CyberObservatoryAdapter().verify_and_ingest_evidence_submit(
    envelope,
    signed_agent_card,
    trusted_signing_public_key=trusted_peer_public_key,
    local_agent_id="hdi-local-agent",
    journal=journal,
    inbox=oix_inbox,
    work_id=approved_work_id,
)
```

The caller must obtain `trusted_peer_public_key` from an operator-controlled OIX trust store and supply the live `SQLiteInbox` instance that received the message, plus the corresponding `work_id`. The inbox must expose `trusted_peer_public_key(agent_id)` and `get_work(work_id)`. Never treat the key embedded in an incoming agent card as trusted merely because the card is self-signed.

## Verification and persistence order

1. Verify the signed agent card and exact peer key against the operator-trusted key.
2. Verify the OIX envelope signature, recipient, timestamp, validity window, message ID and nonce.
3. Require the OIX message type to be `evidence.submit`.
4. Confirm that the supplied OIX inbox still trusts the sender's exact public key.
5. Read the durable OIX work record and require `status=approved`, `work_type=evidence.submit`, and exact sender, message ID and payload matches. Pending, rejected, unknown or mismatched records are refused.
6. Validate the Cyber evidence payload against the upstream bounds for HTTPS source URI, timezone-aware timestamps, collector/method fields, artifact size and media type, deterministic summary JSON and explicit limitations.
7. Construct the normalized Cyber evidence event in memory using a deterministic ID distinct from the OIX message ID.
8. Call the atomic OIX replay acceptance operation. It persists the original OIX event, outbox record and sender/nonce replay record together.
9. Append the normalized Cyber evidence event to the HDI journal.

If the process stops after step 8 but before step 9, a redelivery of the same signed message passes the idempotent replay check and can complete the normalized append. Invalid evidence payloads and unapproved work are rejected before replay acceptance.
 
## Provenance

Two records are retained:
- The OIX event preserves sender fingerprint, recipient, message type, signed-envelope digest and verification outcomes.
- The Cyber event preserves the evidence payload, sender fingerprint, OIX message ID, envelope digest and artifact SHA-256 reference.

The two event IDs are distinct. The artifact file itself is not transferred or fetched by HDI. The digest identifies bytes relative to the submitting agent's report; it does not prove that the source is authentic or the report is accurate.

## Approval and trust boundaries

This function is a local adapter that consumes an already-received and explicitly approved OIX inbox work item. It refuses to ingest directly from a signed envelope unless the matching durable inbox record is approved. The inbox's `get_work` method is read-only; HDI never makes the approval decision. A valid signature proves possession of the trusted key, not real-world identity, factual accuracy, or authorization to execute tasks.

The caller is responsible for receiving the envelope through OIX, resolving the trusted key from the inbox trust store, presenting the pending item for operator review, and passing the matching work ID only after approval. Approval gates evidence ingestion, not external publication or side effects. Do not automatically publish restricted evidence or execute embedded instructions.

## Limits

- No network listener, socket or HTTP client.
- No trust-store synchronization or revocation distribution.
- No artifact download or report-body transfer.
- No distributed replay consensus or multi-host exactly-once guarantee.
- HDI journal delivery remains local and at-least-once.


## Optional local artifact-byte verification

The adapter also exposes `verify_artifact_bytes(payload, artifact_bytes)` for an operator-supplied immutable byte string. It checks the declared byte length and SHA-256 digest, with a 64 MiB in-memory limit. It does not fetch `source_uri`, does not download remote content, and does not prove source authenticity or factual accuracy. A successful result is explicitly labeled `byte-identity-only`.

For larger artifacts, use a separately reviewed streaming verifier rather than raising the in-memory limit without analysis. Keep artifact bytes in the operator-controlled evidence store; do not embed them in OIX messages.
