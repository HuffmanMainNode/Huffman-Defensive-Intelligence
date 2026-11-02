import re

from hdi.adapters.base import Adapter
from hdi.model import HASH, EventValidationError, EvidenceReference, HDIEvent

CLASSIFICATIONS = {"public", "internal", "restricted"}
STATUSES = {"observed", "derived", "unverified"}
REQUIRED_CHECKS = (
    "signature_valid", "sender_trusted", "recipient_valid",
    "replay_checked", "payload_schema_valid",
)


class CyberObservatoryAdapter(Adapter):
    """Normalize OIX-verified Cyber Observatory evidence submissions."""

    project_id = "cyber_observatory"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("Cyber Observatory adapter received another project's event")
        return event

    def normalize_verified_evidence_submit(
        self, payload, *, message_id, sender_fingerprint, envelope_sha256, verification
    ):
        if not isinstance(verification, dict) or any(
            verification.get(check) is not True for check in REQUIRED_CHECKS
        ):
            raise EventValidationError("evidence submission lacks complete OIX verification")
        if not isinstance(payload, dict):
            raise EventValidationError("evidence submission payload must be an object")
        required = {
            "schema_version", "evidence_id", "evidence_type", "source_uri",
            "source_timestamp", "collected_at", "collector", "method", "artifact",
            "classification", "status", "summary", "limitations",
        }
        if set(payload) != required:
            raise EventValidationError("incomplete or unknown OIX evidence.submit fields")
        if payload["schema_version"] != "1.0":
            raise EventValidationError("unsupported evidence.submit schema")
        if not isinstance(payload["evidence_type"], str) or payload["evidence_type"] not in {"sbom_analysis", "file_manifest"}:
            raise EventValidationError("unsupported Cyber Observatory evidence type")
        if (not isinstance(payload["classification"], str)
                or payload["classification"] not in CLASSIFICATIONS
                or not isinstance(payload["status"], str)
                or payload["status"] not in STATUSES):
            raise EventValidationError("invalid evidence classification or status")
        for label in ("collector", "method"):
            value = payload[label]
            if (not isinstance(value, dict) or set(value) != {"name", "version"}
                    or not isinstance(value["name"], str) or not value["name"].strip()
                    or not isinstance(value["version"], str) or not value["version"].strip()):
                raise EventValidationError(f"{label} must contain non-empty name and version")
        if (not isinstance(payload["summary"], dict) or not payload["summary"]
                or len(payload["summary"]) > 64
                or not isinstance(payload["limitations"], list)
                or len(payload["limitations"]) > 32):
            raise EventValidationError("summary and limitations have invalid types or sizes")
        if not payload["limitations"] or any(
            not isinstance(item, str) or not item.strip() or len(item) > 512
            for item in payload["limitations"]
        ):
            raise EventValidationError("evidence limitations must be explicit")
        artifact = payload["artifact"]
        if (not isinstance(artifact, dict)
                or set(artifact) != {"sha256", "size_bytes", "media_type"}
                or not isinstance(artifact.get("sha256"), str)
                or not HASH.fullmatch(artifact["sha256"])):
            raise EventValidationError("artifact SHA-256 is invalid")
        size = artifact.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise EventValidationError("artifact size_bytes must be a non-negative integer")
        if not isinstance(artifact.get("media_type"), str) or not artifact["media_type"]:
            raise EventValidationError("artifact media_type is required")
        if not isinstance(sender_fingerprint, str) or not sender_fingerprint:
            raise EventValidationError("verified sender fingerprint is required")
        if not isinstance(envelope_sha256, str) or not HASH.fullmatch(envelope_sha256):
            raise EventValidationError("envelope_sha256 must be lowercase SHA-256")
        if payload["source_uri"] is not None and (
            not isinstance(payload["source_uri"], str)
            or not payload["source_uri"].startswith("https://")
        ):
            raise EventValidationError("source_uri must be HTTPS or null")
        evidence_id = payload["evidence_id"]
        if not isinstance(evidence_id, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", evidence_id
        ):
            raise EventValidationError("evidence_id must be a lowercase UUID")
        event = HDIEvent(
            event_id=message_id,
            event_type="cyber.evidence.submitted",
            source_project=self.project_id,
            occurred_at=payload["collected_at"],
            payload={
                "upstream": "cyber_observatory",
                "evidence_submission": payload,
                "oix_message_id": message_id,
                "oix_sender_fingerprint": sender_fingerprint,
                "oix_envelope_sha256": envelope_sha256,
                "oix_verification": {key: True for key in REQUIRED_CHECKS},
            },
            evidence=(EvidenceReference(
                source_project=self.project_id,
                source_id=evidence_id,
                sha256=artifact["sha256"],
                uri=payload["source_uri"],
            ),),
        )
        event.validate()
        return event
