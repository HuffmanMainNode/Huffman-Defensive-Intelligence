import hashlib
import hmac
import re
from datetime import datetime
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from hdi.adapters.base import Adapter
from hdi.adapters.oix import OIXAdapter, canonical_oix_json
from hdi.model import HASH, EventValidationError, EvidenceReference, HDIEvent

CLASSIFICATIONS = {"public", "internal", "restricted"}
STATUSES = {"observed", "derived", "unverified"}
MAX_LOCAL_ARTIFACT_BYTES = 64 * 1024 * 1024

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
        self, payload, *, message_id, sender_fingerprint, envelope_sha256, verification,
        normalized_event_id=None,
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
            if (
                not isinstance(value, dict)
                or set(value) != {"name", "version"}
                or not isinstance(value.get("name"), str)
                or not 1 <= len(value["name"].strip()) <= 128
                or not isinstance(value.get("version"), str)
                or not 1 <= len(value["version"].strip()) <= 32
            ):
                raise EventValidationError(f"{label} must contain bounded name and version fields")
        for field, nullable in (("source_timestamp", True), ("collected_at", False)):
            value = payload[field]
            if nullable and value is None:
                continue
            if not isinstance(value, str) or not value or len(value) > 64:
                raise EventValidationError(f"{field} must be an RFC 3339 timestamp")
            try:
                parsed = datetime.fromisoformat(value)
                if parsed.tzinfo is None:
                    raise ValueError("timezone required")
            except ValueError as exc:
                raise EventValidationError(
                    f"{field} must be an RFC 3339 timestamp with timezone"
                ) from exc
        if not isinstance(payload["summary"], dict) or not 1 <= len(payload["summary"]) <= 64:
            raise EventValidationError("summary must be an object with 1 to 64 properties")
        try:
            if len(canonical_oix_json(payload["summary"])) > 32_768:
                raise EventValidationError("summary exceeds 32768 bytes")
        except (TypeError, ValueError, RecursionError) as exc:
            raise EventValidationError("summary must contain deterministic JSON values") from exc
        if (
            not isinstance(payload["limitations"], list)
            or not 1 <= len(payload["limitations"]) <= 32
            or any(
                not isinstance(item, str) or not 1 <= len(item) <= 512
                for item in payload["limitations"]
            )
        ):
            raise EventValidationError("evidence limitations must contain 1 to 32 bounded strings")
        artifact = payload["artifact"]
        if (not isinstance(artifact, dict)
                or set(artifact) != {"sha256", "size_bytes", "media_type"}
                or not isinstance(artifact.get("sha256"), str)
                or not HASH.fullmatch(artifact["sha256"])):
            raise EventValidationError("artifact SHA-256 is invalid")
        size = artifact.get("size_bytes")
        if (
            not isinstance(size, int) or isinstance(size, bool)
            or not 0 <= size <= 1_000_000_000_000
        ):
            raise EventValidationError("artifact size_bytes must be a bounded non-negative integer")
        media_type = artifact.get("media_type")
        if (
            not isinstance(media_type, str) or "/" not in media_type
            or any(char.isspace() for char in media_type) or len(media_type) > 128
        ):
            raise EventValidationError("artifact media_type must be a bounded MIME type")
        if not isinstance(sender_fingerprint, str) or not re.fullmatch(
            r"ed25519:[a-f0-9]{64}", sender_fingerprint
        ):
            raise EventValidationError("verified sender fingerprint is invalid")
        if not isinstance(envelope_sha256, str) or not HASH.fullmatch(envelope_sha256):
            raise EventValidationError("envelope_sha256 must be lowercase SHA-256")
        source_uri = payload["source_uri"]
        if source_uri is not None:
            if not isinstance(source_uri, str) or len(source_uri) > 2048:
                raise EventValidationError("source_uri must be null or a bounded HTTPS URL")
            try:
                parsed_uri = urlsplit(source_uri)
                hostname = parsed_uri.hostname
                _ = parsed_uri.port
            except ValueError as exc:
                raise EventValidationError("source_uri is malformed") from exc
            if (
                parsed_uri.scheme != "https" or not hostname
                or parsed_uri.username is not None or parsed_uri.password is not None
                or any(char.isspace() for char in source_uri)
            ):
                raise EventValidationError(
                    "source_uri must be an HTTPS URL without embedded credentials"
                )
        evidence_id = payload["evidence_id"]
        if not isinstance(evidence_id, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", evidence_id
        ):
            raise EventValidationError("evidence_id must be a lowercase UUID")
        event = HDIEvent(
            event_id=normalized_event_id or message_id,
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


    def verify_artifact_bytes(self, payload, artifact_bytes):
        """Verify operator-supplied artifact bytes against declared evidence metadata.

        This performs byte-identity verification only. It does not fetch source_uri,
        establish who created the artifact, or establish that its contents are true.
        """
        if not isinstance(payload, dict):
            raise EventValidationError("evidence payload must be an object")
        artifact = payload.get("artifact")
        if not isinstance(artifact, dict):
            raise EventValidationError("evidence artifact metadata is required")
        if not isinstance(artifact_bytes, bytes):
            raise EventValidationError("artifact bytes must be supplied as immutable bytes")
        if len(artifact_bytes) > MAX_LOCAL_ARTIFACT_BYTES:
            raise EventValidationError(
                f"artifact exceeds local verification limit of {MAX_LOCAL_ARTIFACT_BYTES} bytes"
            )
        expected_size = artifact.get("size_bytes")
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
        ):
            raise EventValidationError("artifact size_bytes must be a non-negative integer")
        if len(artifact_bytes) != expected_size:
            raise EventValidationError("artifact byte length does not match declared size_bytes")
        expected_digest = artifact.get("sha256")
        if not isinstance(expected_digest, str) or not HASH.fullmatch(expected_digest):
            raise EventValidationError("artifact SHA-256 metadata is invalid")
        actual_digest = hashlib.sha256(artifact_bytes).hexdigest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise EventValidationError("artifact bytes do not match declared SHA-256")
        return {
            "verified": True,
            "sha256": actual_digest,
            "size_bytes": len(artifact_bytes),
            "verification_scope": "byte-identity-only",
            "source_authenticity_verified": False,
        }

    def verify_and_ingest_evidence_submit(
        self,
        envelope,
        signed_card,
        *,
        trusted_signing_public_key,
        local_agent_id,
        journal,
        inbox,
        work_id,
        artifact_bytes=None,
        now=None,
    ):
        """Verify a signed OIX evidence.submit, replay-accept it, then journal its evidence event.

        The trusted public key and inbox must come from the operator-controlled
        OIX receiver. The matching inbound evidence work item must already be
        approved. The OIX envelope event and normalized Cyber evidence event
        use distinct deterministic IDs so both provenance layers coexist.
        """
        verified = OIXAdapter().verify_and_normalize_envelope(
            envelope,
            signed_card,
            trusted_signing_public_key=trusted_signing_public_key,
            local_agent_id=local_agent_id,
            now=now,
        )
        if verified.event.payload.get("message_type") != "evidence.submit":
            raise EventValidationError("OIX message is not evidence.submit")
        if not isinstance(work_id, str) or not work_id:
            raise EventValidationError("approved OIX evidence work_id is required")
        try:
            current_trusted_key = inbox.trusted_peer_public_key(verified.sender)
            work = inbox.get_work(work_id)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise EventValidationError("a live OIX inbox with a trusted peer and work lookup is required") from exc
        if current_trusted_key != trusted_signing_public_key:
            raise EventValidationError("OIX peer is no longer trusted by the supplied inbox")
        if (
            not isinstance(work, dict)
            or work.get("status") != "approved"
            or work.get("work_type") != "evidence.submit"
            or work.get("sender") != verified.sender
            or work.get("message_id") != verified.event.event_id
            or work.get("payload") != verified.event.payload.get("message_payload")
            or not isinstance(work.get("decided_at"), int)
            or isinstance(work.get("decided_at"), bool)
        ):
            raise EventValidationError("matching OIX evidence submission lacks operator approval")
        message_payload = verified.event.payload.get("message_payload")
        verification = {
            "signature_valid": True,
            "sender_trusted": True,
            "recipient_valid": True,
            "replay_checked": True,
            "payload_schema_valid": True,
        }
        evidence_event = self.normalize_verified_evidence_submit(
            message_payload,
            message_id=verified.event.event_id,
            sender_fingerprint=verified.sender,
            envelope_sha256=verified.envelope_sha256,
            verification=verification,
            normalized_event_id=str(
                uuid5(NAMESPACE_URL, "hdi:cyber-evidence-submit:" + verified.event.event_id)
            ),
        )
        artifact_verification = None
        if artifact_bytes is not None:
            artifact_verification = self.verify_artifact_bytes(message_payload, artifact_bytes)
            evidence_event.payload["artifact_byte_verification"] = artifact_verification
            evidence_event.validate()
        # This is the durable replay gate. The evidence event is appended only
        # after the OIX envelope has been accepted by that atomic gate.
        journal.append_verified_oix(
            verified.event,
            sender=verified.sender,
            nonce=verified.nonce,
            envelope_sha256=verified.envelope_sha256,
            expires_at=verified.expires_at,
        )
        evidence_digest = journal.append(evidence_event)
        return {
            "oix_message_id": verified.event.event_id,
            "oix_envelope_sha256": verified.envelope_sha256,
            "evidence_event_id": evidence_event.event_id,
            "evidence_event_sha256": evidence_digest,
            "artifact_byte_verification": artifact_verification,
        }
