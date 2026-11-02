import base64
import hashlib
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdi.adapters.cyber_observatory import CyberObservatoryAdapter
from hdi.adapters.oix import canonical_oix_json
from hdi.model import EventValidationError
from hdi.sqlite_journal import ReplayDetectedError, SQLiteJournal


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_peer():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fingerprint = "ed25519:" + hashlib.sha256(public).hexdigest()
    card = {
        "protocol": "OIX",
        "protocol_version": "0.1",
        "agent_id": fingerprint,
        "display_name": "Cyber Evidence Publisher",
        "public_key": b64url(public),
        "key_algorithm": "ed25519",
        "capabilities": ["public.research"],
    }
    signed_card = {
        "card": card,
        "signature": b64url(private.sign(canonical_oix_json(card))),
    }
    return private, public, fingerprint, signed_card


def evidence_payload(*, evidence_id=None):
    return {
        "schema_version": "1.0",
        "evidence_id": evidence_id or str(uuid.uuid4()),
        "evidence_type": "sbom_analysis",
        "source_uri": "https://example.org/reports/sbom.json",
        "source_timestamp": None,
        "collected_at": "2026-11-02T12:00:00Z",
        "collector": {"name": "huffman-cyber-observatory", "version": "0.1.0"},
        "method": {"name": "sbom-correlate", "version": "0.1.0"},
        "artifact": {
            "sha256": "a" * 64,
            "size_bytes": 4096,
            "media_type": "application/json",
        },
        "classification": "internal",
        "status": "derived",
        "summary": {"matched_kev_entries": 2},
        "limitations": ["A metadata match does not prove exploitability."],
    }


def make_envelope(private, sender, payload, *, message_type="evidence.submit",
                  nonce="E" * 32, message_id=None, now=1000):
    body = {
        "protocol": "OIX",
        "version": "0.1",
        "message_id": message_id or str(uuid.uuid4()),
        "sender": sender,
        "recipient": "hdi-local-agent",
        "type": message_type,
        "issued_at": now,
        "expires_at": now + 300,
        "nonce": nonce,
        "requested_capability": "public.research",
        "payload": payload,
    }
    return {"body": body, "signature": b64url(private.sign(canonical_oix_json(body)))}


def ingest(envelope, public, card, journal, *, now=1100):
    return CyberObservatoryAdapter().verify_and_ingest_evidence_submit(
        envelope,
        card,
        trusted_signing_public_key=public,
        local_agent_id="hdi-local-agent",
        journal=journal,
        now=now,
    )


def test_signed_cyber_evidence_submit_persists_oix_and_normalized_events(tmp_path):
    private, public, sender, card = make_peer()
    envelope = make_envelope(private, sender, evidence_payload())
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    receipt = ingest(envelope, public, card, journal)
    repeated = ingest(envelope, public, card, journal)

    assert receipt == repeated
    assert len(list(journal.read_all())) == 2
    oix_event = journal.get(receipt["oix_message_id"])
    evidence_event = journal.get(receipt["evidence_event_id"])
    assert oix_event.source_project == "oix"
    assert oix_event.payload["verification"]["replay_checked"] is True
    assert evidence_event.source_project == "cyber_observatory"
    assert evidence_event.payload["oix_sender_fingerprint"] == sender
    assert evidence_event.evidence[0].sha256 == "a" * 64
    assert evidence_event.payload["evidence_submission"]["limitations"]


def test_invalid_evidence_schema_is_rejected_before_replay_acceptance(tmp_path):
    private, public, sender, card = make_peer()
    payload = evidence_payload()
    payload["limitations"] = []
    envelope = make_envelope(private, sender, payload)
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    with pytest.raises(EventValidationError, match="limitations"):
        ingest(envelope, public, card, journal)

    assert list(journal.read_all()) == []
    assert journal.outbox_counts() == {"pending": 0, "leased": 0, "delivered": 0}


def test_non_evidence_oix_message_is_rejected(tmp_path):
    private, public, sender, card = make_peer()
    envelope = make_envelope(
        private, sender, {"task": "not an evidence submission"}, message_type="task.request"
    )
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    with pytest.raises(EventValidationError, match="not evidence.submit"):
        ingest(envelope, public, card, journal)

    assert list(journal.read_all()) == []


def test_tampered_cyber_evidence_signature_is_rejected(tmp_path):
    private, public, sender, card = make_peer()
    envelope = make_envelope(private, sender, evidence_payload())
    envelope["body"]["payload"]["summary"]["matched_kev_entries"] = 999
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    with pytest.raises(EventValidationError, match="signature"):
        ingest(envelope, public, card, journal)

    assert list(journal.read_all()) == []


def test_reused_sender_nonce_cannot_create_second_evidence_event(tmp_path):
    private, public, sender, card = make_peer()
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    first = make_envelope(private, sender, evidence_payload())
    ingest(first, public, card, journal)

    replay = make_envelope(
        private,
        sender,
        evidence_payload(),
        nonce=first["body"]["nonce"],
    )
    with pytest.raises(ReplayDetectedError, match="nonce"):
        ingest(replay, public, card, journal)

    assert len(list(journal.read_all())) == 2
