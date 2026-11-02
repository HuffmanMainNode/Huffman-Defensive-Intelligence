from datetime import UTC, datetime
import hashlib
import json
import re

from hdi.adapters.base import Adapter
from hdi.model import HDIEvent, EventValidationError

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
        if not isinstance(body, dict) or body.get("protocol") != "OIX" or body.get("version") != "0.1":
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
        if not SHA256.fullmatch(envelope_sha256 or ""):
            raise EventValidationError("envelope_sha256 must be lowercase SHA-256")
        try:
            occurred_at = datetime.fromtimestamp(body["issued_at"], UTC).isoformat().replace("+00:00", "Z")
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
