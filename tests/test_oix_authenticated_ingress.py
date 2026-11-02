import base64
import hashlib
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdi.adapters.oix import OIXAdapter, canonical_oix_json
from hdi.model import EventValidationError
from hdi.sqlite_journal import ReplayDetectedError, SQLiteJournal


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_peer():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    agent_id = "ed25519:" + hashlib.sha256(public).hexdigest()
    card = {
        "protocol": "OIX",
        "protocol_version": "0.1",
        "agent_id": agent_id,
        "display_name": "Test Research Agent",
        "public_key": b64url(public),
        "key_algorithm": "ed25519",
        "capabilities": ["public.research"],
    }
    signed_card = {
        "card": card,
        "signature": b64url(private.sign(canonical_oix_json(card))),
    }
    return private, public, agent_id, signed_card


def make_envelope(private, sender, recipient, *, nonce="N" * 32, message_id=None, now=1000):
    body = {
        "protocol": "OIX",
        "version": "0.1",
        "message_id": message_id or str(uuid.uuid4()),
        "sender": sender,
        "recipient": recipient,
        "type": "task.request",
        "issued_at": now,
        "expires_at": now + 300,
        "nonce": nonce,
        "requested_capability": "public.research",
        "payload": {"task": "summarize a public advisory", "correlation_id": "case-001"},
    }
    return {"body": body, "signature": b64url(private.sign(canonical_oix_json(body)))}


def verify(envelope, public, card, *, local_id="local-agent", now=1100):
    return OIXAdapter().verify_and_normalize_envelope(
        envelope, card, trusted_signing_public_key=public, local_agent_id=local_id, now=now
    )


def test_valid_oix_message_is_verified_then_atomically_replay_accepted(tmp_path):
    private, public, sender, card = make_peer()
    envelope = make_envelope(private, sender, "local-agent")
    verified = verify(envelope, public, card)
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    first = journal.append_verified_oix(
        verified.event, sender=verified.sender, nonce=verified.nonce,
        envelope_sha256=verified.envelope_sha256, expires_at=verified.expires_at,
    )
    second = journal.append_verified_oix(
        verified.event, sender=verified.sender, nonce=verified.nonce,
        envelope_sha256=verified.envelope_sha256, expires_at=verified.expires_at,
    )

    assert first == second
    saved = journal.get(verified.event.event_id)
    assert saved.payload["verification"]["signature_valid"] is True
    assert saved.payload["verification"]["sender_trusted"] is True
    assert saved.payload["verification"]["recipient_valid"] is True
    assert saved.payload["verification"]["replay_checked"] is True
    assert journal.outbox_counts() == {"pending": 1, "leased": 0, "delivered": 0}


def test_invalid_message_signature_is_rejected(tmp_path):
    private, public, sender, card = make_peer()
    envelope = make_envelope(private, sender, "local-agent")
    envelope["body"]["payload"]["task"] = "tampered after signing"
    with pytest.raises(EventValidationError, match="signature"):
        verify(envelope, public, card)


def test_card_key_must_match_operator_trusted_key():
    private, _, sender, card = make_peer()
    _, other_public, _, _ = make_peer()
    envelope = make_envelope(private, sender, "local-agent")
    with pytest.raises(EventValidationError, match="operator-trusted"):
        verify(envelope, other_public, card)


def test_exact_local_recipient_is_required():
    private, public, sender, card = make_peer()
    envelope = make_envelope(private, sender, "another-agent")
    with pytest.raises(EventValidationError, match="recipient"):
        verify(envelope, public, card)


def test_expired_and_far_future_messages_are_rejected():
    private, public, sender, card = make_peer()
    expired = make_envelope(private, sender, "local-agent", now=1000)
    with pytest.raises(EventValidationError, match="currently valid"):
        verify(expired, public, card, now=1400)
    future = make_envelope(private, sender, "local-agent", now=2000)
    with pytest.raises(EventValidationError, match="currently valid"):
        verify(future, public, card, now=1000)


def test_reused_sender_nonce_is_rejected_durably(tmp_path):
    private, public, sender, card = make_peer()
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    first = verify(make_envelope(private, sender, "local-agent"), public, card)
    journal.append_verified_oix(
        first.event, sender=first.sender, nonce=first.nonce,
        envelope_sha256=first.envelope_sha256, expires_at=first.expires_at,
    )

    replay = verify(
        make_envelope(private, sender, "local-agent", nonce=first.nonce),
        public, card,
    )
    with pytest.raises(ReplayDetectedError, match="nonce"):
        journal.append_verified_oix(
            replay.event, sender=replay.sender, nonce=replay.nonce,
            envelope_sha256=replay.envelope_sha256, expires_at=replay.expires_at,
        )


def test_reused_sender_message_id_is_rejected_even_with_new_nonce(tmp_path):
    private, public, sender, card = make_peer()
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    message_id = str(uuid.uuid4())
    first = verify(
        make_envelope(private, sender, "local-agent", message_id=message_id),
        public, card,
    )
    journal.append_verified_oix(
        first.event, sender=first.sender, nonce=first.nonce,
        envelope_sha256=first.envelope_sha256, expires_at=first.expires_at,
    )
    second = verify(
        make_envelope(
            private, sender, "local-agent", message_id=message_id, nonce="M" * 32
        ),
        public, card,
    )
    with pytest.raises(ReplayDetectedError, match="message ID"):
        journal.append_verified_oix(
            second.event, sender=second.sender, nonce=second.nonce,
            envelope_sha256=second.envelope_sha256, expires_at=second.expires_at,
        )
