from hdi.adapters.base import Adapter
from hdi.model import HDIEvent, EventValidationError

CLASSIFICATIONS = {"public", "internal", "restricted"}


class OpenSwarmAdapter(Adapter):
    """Normalize the upstream Open-Swarm PlatformEvent contract."""

    project_id = "open_swarm"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("Open-Swarm adapter received another project's event")
        return event

    def normalize_platform_event(self, raw):
        required = {
            "event_id", "event_type", "source", "payload", "schema_version",
            "classification", "evidence_refs", "correlation_id", "causation_id",
            "occurred_at",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise EventValidationError("incomplete or unknown Open-Swarm PlatformEvent fields")
        if raw["schema_version"] != "1.0":
            raise EventValidationError("unsupported Open-Swarm event schema")
        if (not isinstance(raw["classification"], str)
                or raw["classification"] not in CLASSIFICATIONS):
            raise EventValidationError("invalid Open-Swarm classification")
        if not isinstance(raw["source"], str) or not raw["source"].strip():
            raise EventValidationError("Open-Swarm source is required")
        if not isinstance(raw["payload"], dict):
            raise EventValidationError("Open-Swarm payload must be an object")
        if not isinstance(raw["evidence_refs"], list) or len(raw["evidence_refs"]) > 100:
            raise EventValidationError("invalid Open-Swarm evidence_refs")
        if any(not isinstance(ref, str) or not ref.strip() or len(ref) > 512
               for ref in raw["evidence_refs"]):
            raise EventValidationError("invalid Open-Swarm evidence reference")
        event = HDIEvent(
            event_id=raw["event_id"],
            event_type=raw["event_type"],
            source_project="open_swarm",
            occurred_at=raw["occurred_at"],
            correlation_id=raw.get("correlation_id"),
            payload={
                "upstream": "open_swarm",
                "upstream_schema_version": raw["schema_version"],
                "source": raw["source"],
                "classification": raw["classification"],
                "payload": raw["payload"],
                "evidence_refs": raw["evidence_refs"],
                "causation_id": raw.get("causation_id"),
            },
        )
        event.validate()
        return event
