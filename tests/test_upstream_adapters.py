from hdi.adapters.oix import OIXAdapter, REQUIRED_CHECKS as OIX_CHECKS, canonical_envelope_sha256
from hdi.adapters.open_swarm import OpenSwarmAdapter
from hdi.adapters.halloween_osint import HalloweenOSINTAdapter
from hdi.adapters.cyber_observatory import CyberObservatoryAdapter
from hdi.model import EventValidationError

VERIFIED = {key: True for key in OIX_CHECKS}
DIGEST = "a" * 64


def test_oix_adapter_requires_upstream_verification():
    envelope = {
        "body": {
            "protocol": "OIX", "version": "0.1", "message_id": "12345678-1234-1234-1234-123456789abc",
            "sender": "fingerprint-demo", "recipient": "agent:receiver",
            "type": "task.request", "issued_at": 1793620800, "expires_at": 1793621100,
            "nonce": "n" * 24, "requested_capability": "public.research",
            "payload": {"task": "summarize a public advisory"},
        },
        "signature": "verified-by-upstream",
    }
    adapter = OIXAdapter()
    try:
        adapter.normalize_verified_envelope(
            envelope, verification={}, envelope_sha256=DIGEST
        )
    except EventValidationError:
        pass
    else:
        raise AssertionError("unverified OIX envelope was accepted")
    event = adapter.normalize_verified_envelope(
        envelope, verification=VERIFIED, envelope_sha256=canonical_envelope_sha256(envelope)
    )
    assert event.source_project == "oix"
    assert event.event_type == "swarm.task.request_received"


def test_open_swarm_platform_event_preserves_policy_and_provenance():
    raw = {
        "event_id": "12345678-1234-1234-1234-123456789abc",
        "event_type": "osint.indicator.observed",
        "source": "halloween-osint",
        "payload": {"indicator_type": "domain", "indicator": "example.org"},
        "schema_version": "1.0",
        "classification": "public",
        "evidence_refs": ["sha256:" + DIGEST],
        "correlation_id": "case-123",
        "causation_id": None,
        "occurred_at": "2026-11-02T12:00:00Z",
    }
    event = OpenSwarmAdapter().normalize_platform_event(raw)
    assert event.source_project == "open_swarm"
    assert event.payload["classification"] == "public"
    assert event.payload["evidence_refs"] == raw["evidence_refs"]
    assert event.correlation_id == "case-123"


def test_halloween_manifest_normalization_is_deterministic():
    manifest = {
        "schema_version": "1.0",
        "created_at": "2026-11-02T12:00:00Z",
        "algorithm": "sha256",
        "root": "/evidence/case-1",
        "files": [{"path": "capture/report.json", "size_bytes": 42, "sha256": DIGEST}],
    }
    adapter = HalloweenOSINTAdapter()
    first = adapter.normalize_manifest(manifest)
    second = adapter.normalize_manifest(manifest)
    assert first.event_id == second.event_id
    assert first.evidence[0].sha256 == second.evidence[0].sha256
    assert first.payload["files"] == manifest["files"]


def test_cyber_observatory_requires_verified_oix_submission():
    payload = {
        "schema_version": "1.0",
        "evidence_id": "12345678-1234-1234-1234-123456789abc",
        "evidence_type": "sbom_analysis",
        "source_uri": "https://example.org/bom.json",
        "source_timestamp": None,
        "collected_at": "2026-11-02T12:00:00Z",
        "collector": {"name": "huffman-cyber-observatory", "version": "0.1.0"},
        "method": {"name": "sbom-correlate", "version": "0.1.0"},
        "artifact": {"sha256": DIGEST, "size_bytes": 42, "media_type": "application/json"},
        "classification": "internal",
        "status": "derived",
        "summary": {"matched_kev_entries": 0},
        "limitations": ["A metadata match does not prove exploitability."],
    }
    adapter = CyberObservatoryAdapter()
    event = adapter.normalize_verified_evidence_submit(
        payload, message_id="12345678-1234-1234-1234-123456789abc",
        sender_fingerprint="oix-fingerprint", envelope_sha256=DIGEST,
        verification=VERIFIED,
    )
    assert event.source_project == "cyber_observatory"
    assert event.evidence[0].sha256 == DIGEST
    assert event.payload["evidence_submission"]["evidence_type"] == "sbom_analysis"
