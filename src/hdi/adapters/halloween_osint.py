import hashlib
import json
from pathlib import Path, PurePosixPath
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
        seen_paths = set()
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256"}:
                raise EventValidationError("malformed manifest file record")
            rel = PurePosixPath(item["path"]) if isinstance(item["path"], str) else None
            if (
                rel is None or rel.is_absolute() or ".." in rel.parts or not item["path"]
                or "\\" in item["path"] or "\x00" in item["path"]
                or len(item["path"]) > 1024 or rel.as_posix() != item["path"]
                or (rel.parts and ":" in rel.parts[0])
            ):
                raise EventValidationError("manifest paths must be canonical safe relative POSIX paths")
            if item["path"] in seen_paths:
                raise EventValidationError("manifest contains duplicate file paths")
            seen_paths.add(item["path"])
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


def _reject_duplicate_manifest_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EventValidationError(f"duplicate JSON object key in manifest: {key}")
        result[key] = value
    return result


class HalloweenManifestImporter:
    """Read and normalize a bounded Halloween OSINT manifest file.

    The importer reads only the manifest itself. It does not follow the
    manifest's root path or open any evidence files listed inside it.
    """

    def __init__(self, manifest_path, *, max_bytes=1_000_000):
        if (
            not isinstance(max_bytes, int) or isinstance(max_bytes, bool)
            or not 1 <= max_bytes <= 4_000_000
        ):
            raise ValueError("max_bytes must be between 1 and 4000000")
        path = Path(manifest_path).expanduser()
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise EventValidationError("manifest path must not traverse symlinks")
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise EventValidationError("manifest file does not exist") from exc
        if not resolved.is_file():
            raise EventValidationError("manifest path must be a regular file")
        if resolved.stat().st_size > max_bytes:
            raise EventValidationError("manifest file exceeds configured size limit")
        self.manifest_path = resolved
        self.max_bytes = max_bytes

    def read_manifest(self):
        """Read strict UTF-8 JSON, rejecting duplicate keys and oversized input."""
        try:
            raw = self.manifest_path.read_bytes()
        except OSError as exc:
            raise EventValidationError("manifest file could not be read") from exc
        if len(raw) > self.max_bytes:
            raise EventValidationError("manifest file exceeds configured size limit")
        try:
            manifest = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_manifest_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EventValidationError("manifest must be valid UTF-8 JSON") from exc
        if not isinstance(manifest, dict):
            raise EventValidationError("manifest root must be a JSON object")
        return manifest

    def normalize(self):
        """Return a deterministic HDI event without opening referenced evidence."""
        manifest = self.read_manifest()
        return HalloweenOSINTAdapter().normalize_manifest(manifest)

    def import_into(self, journal):
        """Append the normalized manifest idempotently to an HDI journal."""
        event = self.normalize()
        digest = journal.append(event)
        return {"event_id": event.event_id, "digest": digest}
