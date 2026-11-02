from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
import re
from typing import Any

PROJECTS = {"oix", "open_swarm", "halloween_osint", "cyber_observatory", "hdi"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
HASH = re.compile(r"^[a-f0-9]{64}$")
MAX_PAYLOAD_BYTES = 256_000


class EventValidationError(ValueError):
    """An event violates the HDI event contract."""


def _validate_json_value(value, depth=0):
    if depth > 32:
        raise EventValidationError("payload nesting exceeds 32 levels")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise EventValidationError("floating-point values are prohibited; use integers or strings")
    if isinstance(value, list):
        if len(value) > 10_000:
            raise EventValidationError("payload arrays may contain at most 10000 items")
        for item in value:
            _validate_json_value(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 10_000:
            raise EventValidationError("payload objects may contain at most 10000 members")
        for key, item in value.items():
            if not isinstance(key, str):
                raise EventValidationError("payload object keys must be strings")
            _validate_json_value(item, depth + 1)
        return
    raise EventValidationError("payload contains a value outside the deterministic JSON model")


@dataclass(frozen=True)
class EvidenceReference:
    source_project: str
    source_id: str
    sha256: str
    uri: str | None = None

    def validate(self):
        if not isinstance(self.source_project, str) or self.source_project not in PROJECTS:
            raise EventValidationError("unknown evidence source project")
        if not isinstance(self.source_id, str) or not IDENTIFIER.fullmatch(self.source_id):
            raise EventValidationError("invalid evidence source_id")
        if not isinstance(self.sha256, str) or not HASH.fullmatch(self.sha256):
            raise EventValidationError("evidence sha256 must be 64 lowercase hex characters")
        if self.uri is not None and (
            not isinstance(self.uri, str) or len(self.uri) > 2048
            or not self.uri.startswith(("https://", "file://"))
        ):
            raise EventValidationError("evidence URI must be bounded https:// or file://")


@dataclass(frozen=True)
class HDIEvent:
    event_id: str
    event_type: str
    source_project: str
    occurred_at: str
    payload: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[EvidenceReference, ...] = ()
    schema_version: str = "1.0"
    correlation_id: str | None = None

    def validate(self):
        if not isinstance(self.event_id, str) or not IDENTIFIER.fullmatch(self.event_id):
            raise EventValidationError("invalid event_id")
        if not isinstance(self.event_type, str) or not re.fullmatch(
            r"[a-z][a-z0-9_.-]{2,95}", self.event_type
        ):
            raise EventValidationError("invalid event_type")
        if not isinstance(self.source_project, str) or self.source_project not in PROJECTS:
            raise EventValidationError("unknown source_project")
        if self.schema_version != "1.0":
            raise EventValidationError("unsupported schema_version")
        if self.correlation_id is not None and (
            not isinstance(self.correlation_id, str)
            or not IDENTIFIER.fullmatch(self.correlation_id)
        ):
            raise EventValidationError("invalid correlation_id")
        if not isinstance(self.occurred_at, str):
            raise EventValidationError("occurred_at must be ISO-8601")
        try:
            stamp = datetime.fromisoformat(self.occurred_at)
        except ValueError as exc:
            raise EventValidationError("occurred_at must be ISO-8601") from exc
        if stamp.tzinfo is None:
            raise EventValidationError("occurred_at must include a timezone")
        if not isinstance(self.payload, dict):
            raise EventValidationError("payload must be an object")
        _validate_json_value(self.payload)
        try:
            encoded = json.dumps(
                self.payload, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False
            ).encode()
        except (TypeError, ValueError, RecursionError) as exc:
            raise EventValidationError("payload must be JSON-serializable") from exc
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise EventValidationError("payload exceeds maximum size")
        if not isinstance(self.evidence, (list, tuple)):
            raise EventValidationError("evidence must be a list or tuple")
        for item in self.evidence:
            if not isinstance(item, EvidenceReference):
                raise EventValidationError("evidence entries must be EvidenceReference objects")
            item.validate()

    def to_dict(self):
        result = asdict(self)
        result["evidence"] = [asdict(item) for item in self.evidence]
        return result

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise EventValidationError("event must be a JSON object")
        allowed = {
            "event_id", "event_type", "source_project", "occurred_at", "payload",
            "evidence", "schema_version", "correlation_id",
        }
        unknown = set(value) - allowed
        if unknown:
            raise EventValidationError(f"unknown event fields: {sorted(unknown)}")
        try:
            evidence_raw = value.get("evidence", [])
            if not isinstance(evidence_raw, list):
                raise EventValidationError("evidence must be a JSON array")
            evidence = tuple(EvidenceReference(**item) for item in evidence_raw)
            event = cls(
                event_id=value["event_id"], event_type=value["event_type"],
                source_project=value["source_project"], occurred_at=value["occurred_at"],
                payload=value.get("payload", {}), evidence=evidence,
                schema_version=value.get("schema_version", "1.0"),
                correlation_id=value.get("correlation_id"))
        except (KeyError, TypeError) as exc:
            raise EventValidationError("missing or malformed event fields") from exc
        event.validate()
        return event

    def canonical_sha256(self):
        raw = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False
        ).encode()
        return hashlib.sha256(raw).hexdigest()
