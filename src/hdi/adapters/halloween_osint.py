import hashlib
import json
from pathlib import PurePosixPath
from uuid import NAMESPACE_URL, uuid5

from hdi.adapters.base import Adapter
from hdi.model import HASH, EventValidationError, EvidenceReference, HDIEvent


class HalloweenOSINTAdapter(Adapter):
    """Normalize a Halloween OSINT SHA-256 evidence manifest."""

    project_id = "halloween_osint"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("OSINT adapter received another project's event")
        return event

    def normalize_manifest(self, manifest):
        required = {"schema_version", "created_at", "algorithm", "root", "files"}
        if not isinstance(manifest, dict) or set(manifest) != required:
            raise EventValidationError("incomplete or unknown Halloween OSINT manifest fields")
        if manifest["schema_version"] != "1.0" or manifest["algorithm"] != "sha256":
            raise EventValidationError("unsupported Halloween OSINT manifest version or algorithm")
        if not isinstance(manifest["root"], str) or not manifest["root"]:
            raise EventValidationError("manifest root must be a non-empty string")
        files = manifest["files"]
        if not isinstance(files, list) or len(files) > 10_000:
            raise EventValidationError("manifest files must be a list of at most 10000 items")
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256"}:
                raise EventValidationError("malformed manifest file record")
            rel = PurePosixPath(item["path"]) if isinstance(item["path"], str) else None
            if (rel is None or rel.is_absolute() or ".." in rel.parts or not item["path"]
                    or "\\" in item["path"] or "\x00" in item["path"]):
                raise EventValidationError("manifest paths must be safe relative POSIX paths")
            if (not isinstance(item["size_bytes"], int) or isinstance(item["size_bytes"], bool)
                    or item["size_bytes"] < 0):
                raise EventValidationError("manifest size_bytes must be a non-negative integer")
            if not isinstance(item["sha256"], str) or not HASH.fullmatch(item["sha256"]):
                raise EventValidationError("manifest file SHA-256 is invalid")
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        event = HDIEvent(
            event_id=str(uuid5(NAMESPACE_URL, "hdi:halloween-manifest:" + digest)),
            event_type="osint.evidence_manifest.created",
            source_project=self.project_id,
            occurred_at=manifest["created_at"],
            payload={
                "upstream": "halloween_osint",
                "manifest_sha256": digest,
                "algorithm": "sha256",
                "classification": "internal",
                "root_path_redacted": True,
                "files": files,
            },
            evidence=(EvidenceReference(
                source_project=self.project_id,
                source_id="manifest-" + digest[:32],
                sha256=digest,
            ),),
        )
        event.validate()
        return event
