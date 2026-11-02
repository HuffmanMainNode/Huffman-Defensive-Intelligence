import base64
import binascii
import hashlib
import json
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
FINGERPRINT = re.compile(r"^ed25519:[a-f0-9]{64}$")
MESSAGE_FIELDS = {
    "protocol", "version", "message_id", "sender", "recipient", "type",
    "issued_at", "expires_at", "nonce", "requested_capability", "payload",
}
CARD_FIELDS = {
    "protocol", "protocol_version", "agent_id", "display_name",
    "public_key", "key_algorithm", "capabilities",
}
REQUIRED_CHECKS = (
    "signature_valid", "sender_trusted", "recipient_valid",
    "replay_checked", "payload_schema_valid",
)


@dataclass(frozen=True)
class VerifiedOIXMessage:
    """Cryptographically verified OIX message awaiting durable replay acceptance."""

    event: HDIEvent
    sender: str
    nonce: str
    envelope_sha256: str
    expires_at: int


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


def canonical_oix_json(value):
    """Match OIX v0.1 restricted canonical JSON exactly."""
    normalized = _normalize_canonical(value)
    return json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def canonical_envelope_sha256(envelope):
    return hashlib.sha256(canonical_oix_json(envelope)).hexdigest()


def _decode_b64url(value, *, expected_length=None):
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise EventValidationError("invalid base64url field")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise EventValidationError("invalid base64url field") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise EventValidationError("base64url field has an invalid decoded length")
    return decoded


def _fingerprint(public_key):
    return "ed25519:" + hashlib.sha256(public_key).hexdigest()


def _verify_trusted_card(signed_card, trusted_signing_public_key):
    if not isinstance(trusted_signing_public_key, bytes) or len(trusted_signing_public_key) != 32:
        raise EventValidationError("trusted OIX Ed25519 public key must be 32 bytes")
    if not isinstance(signed_card, dict) or set(signed_card) != {"card", "signature"}:
        raise EventValidationError("malformed signed OIX agent card")
    card = signed_card["card"]
    if not isinstance(card, dict) or set(card) != CARD_FIELDS:
        raise EventValidationError("OIX agent card fields do not match protocol v0.1")
    if (
        card["protocol"] != "OIX"
        or card["protocol_version"] != "0.1"
        or card["key_algorithm"] != "ed25519"
    ):
        raise EventValidationError("unsupported OIX agent card")
    if (
        not isinstance(card["display_name"], str)
        or not 1 <= len(card["display_name"]) <= 128
        or not isinstance(card["capabilities"], list)
        or len(card["capabilities"]) > 128
        or any(not isinstance(item, str) or not 1 <= len(item) <= 128
               for item in card["capabilities"])
        or len(set(card["capabilities"])) != len(card["capabilities"])
    ):
        raise EventValidationError("OIX agent card metadata is invalid")
    public_key = _decode_b64url(card["public_key"], expected_length=32)
    if public_key != trusted_signing_public_key:
        raise EventValidationError("agent card key does not match operator-trusted peer key")
    if card["agent_id"] != _fingerprint(public_key):
        raise EventValidationError("OIX agent card fingerprint does not match its public key")
    signature = _decode_b64url(signed_card["signature"], expected_length=64)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, canonical_oix_json(card)
        )
    except (InvalidSignature, ValueError) as exc:
        raise EventValidationError("OIX agent card signature is invalid") from exc
    return public_key, card["agent_id"]


class OIXAdapter(Adapter):
    """Normalize OIX envelopes after explicit peer trust and cryptographic checks."""

    project_id = "oix"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("OIX adapter received another project's event")
        return event

    def verify_and_normalize_envelope(
        self,
        envelope,
        signed_card,
        *,
        trusted_signing_public_key,
        local_agent_id,
        now=None,
    ):
        """Verify an OIX v0.1 Ed25519 envelope against an operator-trusted peer key.

        The trusted key must be resolved from an operator-controlled OIX trust
        store. The key inside the untrusted card is never trusted by itself.
        Replay acceptance is a separate atomic SQLiteJournal operation.
        """
        public_key, trusted_sender = _verify_trusted_card(
            signed_card, trusted_signing_public_key
        )
        if not isinstance(local_agent_id, str) or not local_agent_id:
            raise EventValidationError("local_agent_id is required")
        if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
            raise EventValidationError("malformed OIX envelope")
        body = envelope["body"]
        if not isinstance(body, dict) or set(body) != MESSAGE_FIELDS:
            raise EventValidationError("OIX message body fields do not match protocol v0.1")
        if body["protocol"] != "OIX" or body["version"] != "0.1":
            raise EventValidationError("unsupported OIX envelope")
        message_type = body["type"]
        if not isinstance(message_type, str) or message_type not in MESSAGE_TYPES:
            raise EventValidationError("unsupported OIX message type")
        if not isinstance(body["payload"], dict):
            raise EventValidationError("OIX payload must be an object")
        if body["sender"] != trusted_sender or not FINGERPRINT.fullmatch(body["sender"]):
            raise EventValidationError("OIX sender does not match the operator-trusted peer")
        if body["recipient"] != local_agent_id:
            raise EventValidationError("OIX message recipient does not match this local agent")
        if not isinstance(body["nonce"], str) or not 20 <= len(body["nonce"]) <= 128:
            raise EventValidationError("invalid OIX nonce")
        capability = body["requested_capability"]
        if capability is not None and (
            not isinstance(capability, str) or not 1 <= len(capability) <= 128
        ):
            raise EventValidationError("invalid OIX requested capability")
        try:
            if not isinstance(body["message_id"], str) or str(uuid.UUID(body["message_id"])) != body["message_id"]:
                raise ValueError
        except (ValueError, AttributeError) as exc:
            raise EventValidationError("OIX message_id must be a canonical UUID") from exc
        issued_at = body["issued_at"]
        expires_at = body["expires_at"]
        if (
            not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 0
            or not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at < 1
        ):
            raise EventValidationError("OIX timestamps must be positive integer Unix seconds")
        if not 1 <= expires_at - issued_at <= 86_400:
            raise EventValidationError("OIX message validity window is invalid")
        current = int(datetime.now(UTC).timestamp()) if now is None else now
        if not isinstance(current, int) or isinstance(current, bool):
            raise TypeError("now must be an integer Unix timestamp")
        if issued_at > current + 60 or expires_at < current:
            raise EventValidationError("OIX message is not currently valid")
        try:
            envelope_bytes = canonical_oix_json(envelope)
            body_bytes = canonical_oix_json(body)
        except (TypeError, ValueError, RecursionError) as exc:
            raise EventValidationError("OIX envelope is outside the canonical JSON model") from exc
        if len(envelope_bytes) > 1_000_000:
            raise EventValidationError("OIX message exceeds the 1 MB limit")
        signature = _decode_b64url(envelope["signature"], expected_length=64)
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, body_bytes)
        except (InvalidSignature, ValueError) as exc:
            raise EventValidationError("OIX message signature is invalid") from exc
        envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
        try:
            occurred_at = datetime.fromtimestamp(issued_at, UTC).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError) as exc:
            raise EventValidationError("invalid OIX issued_at timestamp") from exc
        payload = {
            "upstream": "oix",
            "message_type": message_type,
            "sender_fingerprint": trusted_sender,
            "recipient": local_agent_id,
            "requested_capability": capability,
            "message_payload": body["payload"],
            "envelope_sha256": envelope_sha256,
            "verification": {
                "signature_valid": True,
                "sender_trusted": True,
                "recipient_valid": True,
                "payload_schema_valid": True,
            },
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
        return VerifiedOIXMessage(
            event=event, sender=trusted_sender, nonce=body["nonce"],
            envelope_sha256=envelope_sha256, expires_at=expires_at,
        )

    def normalize_verified_envelope(self, envelope, *, verification, envelope_sha256):
        """Legacy attestation-based normalizer. Prefer verify_and_normalize_envelope."""
        if not isinstance(verification, dict) or any(
            verification.get(check) is not True for check in REQUIRED_CHECKS
        ):
            raise EventValidationError("OIX envelope lacks complete upstream verification")
        if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
            raise EventValidationError("malformed OIX envelope")
        body = envelope["body"]
        if not isinstance(body, dict) or set(body) != MESSAGE_FIELDS:
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
        except (ValueError, OverflowError, OSError) as exc:
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
