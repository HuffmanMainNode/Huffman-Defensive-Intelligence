import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime

from hdi.adapters.base import Adapter
from hdi.model import EventValidationError, HDIEvent


MESSAGE_TYPES = {
    "agent.hello": "oix.peer.hello_received",
    "agent.hello_ack": "oix.peer.handshake_completed",
    "task.request": "swarm.task.request_received",
    "task.accepted": "swarm.task.accepted_remote",
    "task.progress": "swarm.task.progress_remote",
    "task.result": "swarm.task.result_received",
    "evidence.submit": "intelligence.evidence.received",
    "error": "oix.message.error_received",
    "delivery.receipt": "oix.delivery.receipt_received",
}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
REQUIRED_CHECKS = (
    "signature_valid", "sender_trusted", "recipient_valid",
    "replay_checked", "payload_schema_valid",
)



def _normalize_canonical(value, depth=0):
    if depth > 32:
        raise EventValidationError("OIX envelope nesting exceeds 32 levels")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise EventValidationError("OIX canonical data cannot contain floats")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        if len(value) > 10_000:
            raise EventValidationError("OIX envelope array exceeds item limit")
        return [_normalize_canonical(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 10_000:
            raise EventValidationError("OIX envelope object exceeds member limit")
        normalized = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise EventValidationError("OIX envelope keys must be strings")
            key = unicodedata.normalize("NFC", key)
            if key in normalized:
                raise EventValidationError("duplicate key after Unicode normalization")
            normalized[key] = _normalize_canonical(item, depth + 1)
        return normalized
    raise EventValidationError("OIX envelope contains a non-canonical value")


def canonical_envelope_sha256(envelope):
    normalized = _normalize_canonical(envelope)
    encoded = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

class OIXAdapter(Adapter):
    """Normalize OIX envelopes only after the upstream verifier has approved them."""

    project_id = "oix"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("OIX adapter received another project's event")
        return event

    def normalize_verified_envelope(self, envelope, *, verification, envelope_sha256):
        if not isinstance(verification, dict) or any(
            verification.get(check) is not True for check in REQUIRED_CHECKS
        ):
            raise EventValidationError("OIX envelope lacks complete upstream verification")
        if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
            raise EventValidationError("malformed OIX envelope")
        body = envelope["body"]
        expected_body_fields = {
            "protocol", "version", "message_id", "sender", "recipient", "type",
            "issued_at", "expires_at", "nonce", "requested_capability", "payload",
        }
        if not isinstance(body, dict) or set(body) != expected_body_fields:
            raise EventValidationError("malformed OIX message body fields")
        if body.get("protocol") != "OIX" or body.get("version") != "0.1":
            raise EventValidationError("unsupported OIX envelope")
        message_type = body.get("type")
        if message_type not in MESSAGE_TYPES:
            raise EventValidationError("unsupported OIX message type")
        if not isinstance(body.get("payload"), dict):
            raise EventValidationError("OIX payload must be an object")
        if not isinstance(body.get("message_id"), str) or not isinstance(body.get("sender"), str):
            raise EventValidationError("OIX message identity is missing")
        if not isinstance(body.get("recipient"), str) or not body["recipient"]:
            raise EventValidationError("OIX recipient is missing")
        if not isinstance(body.get("nonce"), str) or not 20 <= len(body["nonce"]) <= 128:
            raise EventValidationError("invalid OIX nonce")
        if body.get("requested_capability") is not None and not isinstance(
            body["requested_capability"], str
        ):
            raise EventValidationError("invalid OIX requested capability")
        if not isinstance(envelope.get("signature"), str) or not envelope["signature"]:
            raise EventValidationError("OIX signature field is missing")
        if not SHA256.fullmatch(envelope_sha256 or ""):
            raise EventValidationError("envelope_sha256 must be lowercase SHA-256")
        if canonical_envelope_sha256(envelope) != envelope_sha256:
            raise EventValidationError("OIX envelope digest does not match supplied digest")
        issued_at = body.get("issued_at")
        expires_at = body.get("expires_at")
        if (not isinstance(issued_at, int) or isinstance(issued_at, bool)
                or not isinstance(expires_at, int) or isinstance(expires_at, bool)):
            raise EventValidationError("OIX timestamps must be integer Unix seconds")
        if not 1 <= expires_at - issued_at <= 86_400:
            raise EventValidationError("OIX message validity window is invalid")
        try:
            occurred_at = datetime.fromtimestamp(issued_at, UTC).isoformat().replace("+00:00", "Z")
        except (KeyError, TypeError, ValueError, OverflowError, OSError) as exc:
            raise EventValidationError("invalid OIX issued_at timestamp") from exc
        payload = {
            "upstream": "oix",
            "message_type": message_type,
            "sender_fingerprint": body["sender"],
            "recipient": body["recipient"],
            "requested_capability": body.get("requested_capability"),
            "message_payload": body["payload"],
            "envelope_sha256": envelope_sha256,
            "verification": {key: True for key in REQUIRED_CHECKS},
        }
        event = HDIEvent(
            event_id=body["message_id"],
            event_type=MESSAGE_TYPES[message_type],
            source_project="oix",
            occurred_at=occurred_at,
            payload=payload,
            correlation_id=body["payload"].get("correlation_id")
            if isinstance(body["payload"].get("correlation_id"), str) else None,
        )
        event.validate()
        return event
