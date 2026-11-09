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


class ApprovedInboxFixture:
    def __init__(self, envelope, public, *, status="approved", overrides=None):
        self.sender = envelope["body"]["sender"]
        self.public = public
        self.work = {
            "work_id": "work-fixture-001",
            "sender": self.sender,
            "message_id": envelope["body"]["message_id"],
            "work_type": envelope["body"]["type"],
            "payload": envelope["body"]["payload"],
            "status": status,
            "decided_at": 1100 if status in {"approved", "rejected"} else None,
        }
        self.work.update(overrides or {})

    def trusted_peer_public_key(self, sender):
        if sender != self.sender:
            raise ValueError("untrusted peer")
        return self.public

    def get_work(self, work_id):
        if work_id != self.work["work_id"]:
            raise ValueError("unknown work")
        return dict(self.work)


def ingest(envelope, public, card, journal, *, now=1100, status="approved",
           work_overrides=None, inbox=None, artifact_bytes=None):
    inbox = inbox or ApprovedInboxFixture(
        envelope, public, status=status, overrides=work_overrides
    )
    return CyberObservatoryAdapter().verify_and_ingest_evidence_submit(
        envelope,
        card,
        trusted_signing_public_key=public,
        local_agent_id="hdi-local-agent",
        journal=journal,
        inbox=inbox,
        work_id="work-fixture-001",
        artifact_bytes=artifact_bytes,
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


def test_pending_or_rejected_oix_work_cannot_enter_hdi(tmp_path):
    private, public, sender, card = make_peer()
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    envelope = make_envelope(private, sender, evidence_payload())

    with pytest.raises(EventValidationError, match="lacks operator approval"):
        ingest(envelope, public, card, journal, status="pending_review")
    with pytest.raises(EventValidationError, match="lacks operator approval"):
        ingest(envelope, public, card, journal, status="rejected")

    assert list(journal.read_all()) == []


def test_approval_must_match_sender_message_type_and_payload(tmp_path):
    private, public, sender, card = make_peer()
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    envelope = make_envelope(private, sender, evidence_payload())

    with pytest.raises(EventValidationError, match="lacks operator approval"):
        ingest(
            envelope, public, card, journal,
            work_overrides={"message_id": str(uuid.uuid4())},
        )
    with pytest.raises(EventValidationError, match="lacks operator approval"):
        ingest(
            envelope, public, card, journal,
            work_overrides={"payload": {"evidence_id": "different"}},
        )

    assert list(journal.read_all()) == []


def test_normalized_event_recovers_after_crash_following_oix_replay_acceptance(tmp_path):
    private, public, sender, card = make_peer()
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    envelope = make_envelope(private, sender, evidence_payload())
    inbox = ApprovedInboxFixture(envelope, public)
    original_append = journal.append
    failed = {"once": False}

    def fail_once(event):
        if event.source_project == "cyber_observatory" and not failed["once"]:
            failed["once"] = True
            raise RuntimeError("simulated crash before normalized append")
        return original_append(event)

    journal.append = fail_once
    with pytest.raises(RuntimeError, match="simulated crash"):
        ingest(envelope, public, card, journal, inbox=inbox)

    journal.append = original_append
    receipt = ingest(envelope, public, card, journal, inbox=inbox)
    assert len(list(journal.read_all())) == 2
    assert journal.get(receipt["evidence_event_id"]).source_project == "cyber_observatory"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update({"source_uri": "https://user:pass@example.org/a"}),
        lambda p: p.update({"source_uri": "https://example.org/" + "x" * 2050}),
        lambda p: p.update({"collected_at": "2026-11-02T12:00:00"}),
        lambda p: p.update({"source_timestamp": "not-a-timestamp"}),
        lambda p: p["collector"].update({"version": "v" * 33}),
        lambda p: p["artifact"].update({"media_type": "not-a-mime"}),
        lambda p: p["artifact"].update({"size_bytes": 1_000_000_000_001}),
        lambda p: p.update({"limitations": ["x" * 513]}),
    ],
)
def test_upstream_evidence_field_limits_are_enforced_before_ingest(tmp_path, mutate):
    private, public, sender, card = make_peer()
    payload = evidence_payload()
    mutate(payload)
    envelope = make_envelope(private, sender, payload)
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    with pytest.raises(EventValidationError):
        ingest(envelope, public, card, journal)

    assert list(journal.read_all()) == []


def test_oix_canonical_payload_rejects_floats_before_signature_creation():
    private, _, sender, _ = make_peer()
    payload = evidence_payload()
    payload["summary"]["unsafe_float"] = 1.25

    with pytest.raises(EventValidationError, match="cannot contain floats"):
        make_envelope(private, sender, payload)


def test_supplied_artifact_bytes_are_verified_against_metadata():
    adapter = CyberObservatoryAdapter()
    payload = evidence_payload()
    artifact_bytes = b"synthetic evidence artifact"
    payload["artifact"]["sha256"] = hashlib.sha256(artifact_bytes).hexdigest()
    payload["artifact"]["size_bytes"] = len(artifact_bytes)

    result = adapter.verify_artifact_bytes(payload, artifact_bytes)

    assert result == {
        "verified": True,
        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "size_bytes": len(artifact_bytes),
        "verification_scope": "byte-identity-only",
        "source_authenticity_verified": False,
    }


def test_supplied_artifact_bytes_reject_digest_mismatch():
    adapter = CyberObservatoryAdapter()
    payload = evidence_payload()
    payload["artifact"]["size_bytes"] = 4

    with pytest.raises(EventValidationError, match="SHA-256"):
        adapter.verify_artifact_bytes(payload, b"data")


def test_supplied_artifact_bytes_reject_size_mismatch():
    adapter = CyberObservatoryAdapter()
    payload = evidence_payload()
    payload["artifact"]["size_bytes"] = 5
    payload["artifact"]["sha256"] = hashlib.sha256(b"data").hexdigest()

    with pytest.raises(EventValidationError, match="byte length"):
        adapter.verify_artifact_bytes(payload, b"data")


def test_supplied_artifact_bytes_reject_mutable_and_oversized_values(monkeypatch):
    import hdi.adapters.cyber_observatory as cyber_module

    adapter = CyberObservatoryAdapter()
    payload = evidence_payload()
    with pytest.raises(EventValidationError, match="immutable bytes"):
        adapter.verify_artifact_bytes(payload, bytearray(b"data"))

    monkeypatch.setattr(cyber_module, "MAX_LOCAL_ARTIFACT_BYTES", 3)
    with pytest.raises(EventValidationError, match="local verification limit"):
        adapter.verify_artifact_bytes(payload, b"four")


def test_ingress_records_local_artifact_byte_verification(tmp_path):
    private, public, sender, card = make_peer()
    payload = evidence_payload()
    artifact_bytes = b"synthetic evidence artifact"
    payload["artifact"]["sha256"] = hashlib.sha256(artifact_bytes).hexdigest()
    payload["artifact"]["size_bytes"] = len(artifact_bytes)
    envelope = make_envelope(private, sender, payload)
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    receipt = ingest(envelope, public, card, journal, artifact_bytes=artifact_bytes)

    assert receipt["artifact_byte_verification"]["verified"] is True
    evidence_event = journal.get(receipt["evidence_event_id"])
    assert evidence_event.payload["artifact_byte_verification"]["verification_scope"] == "byte-identity-only"
    assert evidence_event.payload["artifact_byte_verification"]["source_authenticity_verified"] is False


def test_ingress_rejects_supplied_artifact_bytes_before_replay_acceptance(tmp_path):
    private, public, sender, card = make_peer()
    payload = evidence_payload()
    payload["artifact"]["size_bytes"] = 4
    envelope = make_envelope(private, sender, payload)
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    with pytest.raises(EventValidationError, match="SHA-256"):
        ingest(envelope, public, card, journal, artifact_bytes=b"data")

    assert list(journal.read_all()) == []
