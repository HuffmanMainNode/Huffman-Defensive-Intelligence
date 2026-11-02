import base64
import hashlib
import json
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdi.adapters.cyber_observatory import CyberObservatoryAdapter
from hdi.adapters.halloween_osint import HalloweenManifestImporter
from hdi.adapters.oix import OIXAdapter, canonical_oix_json
from hdi.adapters.open_swarm import OpenSwarmAdapter
from hdi.sqlite_journal import SQLiteJournal


def b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def make_signed_peer():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    sender = "ed25519:" + hashlib.sha256(public).hexdigest()
    card = {
        "protocol": "OIX",
        "protocol_version": "0.1",
        "agent_id": sender,
        "display_name": "Conformance Agent",
        "public_key": b64url(public),
        "key_algorithm": "ed25519",
        "capabilities": ["public.research"],
    }
    signed_card = {
        "card": card,
        "signature": b64url(private.sign(canonical_oix_json(card))),
    }
    return private, public, sender, signed_card


def signed_envelope(private, sender, message_type, payload, *, nonce):
    body = {
        "protocol": "OIX",
        "version": "0.1",
        "message_id": str(uuid.uuid4()),
        "sender": sender,
        "recipient": "hdi-conformance-agent",
        "type": message_type,
        "issued_at": 1000,
        "expires_at": 1300,
        "nonce": nonce,
        "requested_capability": "public.research",
        "payload": payload,
    }
    return {"body": body, "signature": b64url(private.sign(canonical_oix_json(body)))}


def test_four_project_outputs_share_one_validated_idempotent_journal(tmp_path):
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    private, public, sender, card = make_signed_peer()

    # OIX: authenticate a task request and durably accept its sender/nonce.
    oix_envelope = signed_envelope(
        private,
        sender,
        "task.request",
        {"task": "summarize a public advisory"},
        nonce="O" * 32,
    )
    verified_oix = OIXAdapter().verify_and_normalize_envelope(
        oix_envelope,
        card,
        trusted_signing_public_key=public,
        local_agent_id="hdi-conformance-agent",
        now=1100,
    )
    journal.append_verified_oix(
        verified_oix.event,
        sender=verified_oix.sender,
        nonce=verified_oix.nonce,
        envelope_sha256=verified_oix.envelope_sha256,
        expires_at=verified_oix.expires_at,
    )

    # Open-Swarm: normalize a versioned task lifecycle event.
    swarm_raw = {
        "event_id": str(uuid.uuid4()),
        "event_type": "swarm.task.completed",
        "source": "open-swarm",
        "payload": {"task_id": "task-001", "status": "completed"},
        "schema_version": "1.0",
        "classification": "internal",
        "evidence_refs": ["sha256:" + "1" * 64],
        "correlation_id": "case-001",
        "causation_id": None,
        "occurred_at": "2026-11-02T12:00:00Z",
    }
    swarm_event = OpenSwarmAdapter().normalize_platform_event(swarm_raw)
    journal.append(swarm_event)

    # Halloween OSINT: import a manifest, not its evidence directory.
    manifest = {
        "schema_version": "1.0",
        "created_at": "2026-11-02T12:00:00Z",
        "algorithm": "sha256",
        "root": "/private/evidence/case-001",
        "files": [
            {"path": "capture/report.json", "size_bytes": 64, "sha256": "2" * 64}
        ],
    }
    manifest_path = tmp_path / "evidence-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    halloween_importer = HalloweenManifestImporter(manifest_path)
    halloween_receipt = halloween_importer.import_into(journal)

    # Cyber Observatory: verify an OIX evidence.submit and retain both layers.
    cyber_payload = {
        "schema_version": "1.0",
        "evidence_id": str(uuid.uuid4()),
        "evidence_type": "sbom_analysis",
        "source_uri": "https://example.org/sbom-report.json",
        "source_timestamp": None,
        "collected_at": "2026-11-02T12:00:00Z",
        "collector": {"name": "huffman-cyber-observatory", "version": "0.1.0"},
        "method": {"name": "sbom-correlate", "version": "0.1.0"},
        "artifact": {
            "sha256": "3" * 64,
            "size_bytes": 512,
            "media_type": "application/json",
        },
        "classification": "internal",
        "status": "derived",
        "summary": {"matched_kev_entries": 1},
        "limitations": ["A metadata match does not prove exploitability."],
    }
    cyber_envelope = signed_envelope(
        private,
        sender,
        "evidence.submit",
        cyber_payload,
        nonce="C" * 32,
    )
    cyber_receipt = CyberObservatoryAdapter().verify_and_ingest_evidence_submit(
        cyber_envelope,
        card,
        trusted_signing_public_key=public,
        local_agent_id="hdi-conformance-agent",
        journal=journal,
        now=1100,
    )

    events = list(journal.read_all())
    projects = {event.source_project for event in events}
    assert projects == {"oix", "open_swarm", "halloween_osint", "cyber_observatory"}
    assert len(events) == 5
    assert all(event.validate() is None for event in events)
    assert journal.outbox_counts() == {"pending": 5, "leased": 0, "delivered": 0}

    # Re-ingest the same stable source records. No duplicate events or outbox rows.
    repeated_oix = OIXAdapter().verify_and_normalize_envelope(
        oix_envelope,
        card,
        trusted_signing_public_key=public,
        local_agent_id="hdi-conformance-agent",
        now=1100,
    )
    journal.append_verified_oix(
        repeated_oix.event,
        sender=repeated_oix.sender,
        nonce=repeated_oix.nonce,
        envelope_sha256=repeated_oix.envelope_sha256,
        expires_at=repeated_oix.expires_at,
    )
    journal.append(OpenSwarmAdapter().normalize_platform_event(swarm_raw))
    assert halloween_importer.import_into(journal)["event_id"] == halloween_receipt["event_id"]
    repeated_cyber = CyberObservatoryAdapter().verify_and_ingest_evidence_submit(
        cyber_envelope,
        card,
        trusted_signing_public_key=public,
        local_agent_id="hdi-conformance-agent",
        journal=journal,
        now=1100,
    )
    assert repeated_cyber == cyber_receipt
    assert len(list(journal.read_all())) == 5
    assert journal.outbox_counts() == {"pending": 5, "leased": 0, "delivered": 0}
