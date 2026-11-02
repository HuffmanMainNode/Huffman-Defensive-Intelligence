# Halloween OSINT manifest import

HDI 0.6.0 adds a bounded importer for the upstream Halloween OSINT evidence-manifest v1.0 format.

## Usage

```python
from hdi.adapters.halloween_osint import HalloweenManifestImporter
from hdi.sqlite_journal import SQLiteJournal

journal = SQLiteJournal("./hdi-state/events.sqlite")
importer = HalloweenManifestImporter(
    "./case/evidence-manifest.json",
    max_bytes=1_000_000,
)
receipt = importer.import_into(journal)
print(receipt["event_id"], receipt["digest"])
```

The deterministic event ID and canonical event digest make repeated imports of an unchanged manifest idempotent.

## Input checks

- Manifest path must resolve to a regular file and must not traverse symlinks.
- File size is checked before and after reading.
- Input must be strict UTF-8 JSON.
- Duplicate JSON object keys are rejected rather than silently overwritten.
- The manifest must contain exactly the upstream v1.0 fields.
- File records must contain exactly path, size and SHA-256.
- Evidence paths must be canonical, unique, relative POSIX paths. Absolute paths, traversal, Windows drive prefixes, backslashes, control characters and non-canonical separators are rejected.
- The normalized HDI event must pass payload-size, timestamp, evidence-reference and digest validation.

## Privacy and evidence boundary

The upstream manifest includes a root directory path. HDI hashes the complete manifest for stable provenance but does not copy the root path into the normalized event. The event contains a `root_path_redacted` marker and the relative file records.

The importer reads only the manifest JSON file. It does not open the root directory or any evidence file named in the manifest. It therefore does not independently establish that the listed evidence files still exist or currently match their recorded digests.

For byte-level verification, run the upstream Halloween OSINT verifier against the evidence directory and manifest. A matching SHA-256 digest establishes byte identity relative to that manifest, not source authenticity, authorship, ownership or truth.

## Operational limits

- Local file import only. No network client, daemon or scheduled watcher.
- No modification of the source manifest or evidence files.
- No trust or authenticity claim based solely on the manifest.
- HDI journal delivery remains at-least-once and single-host.
- The source root path is not exported, but the manifest digest remains stable for the exact source manifest, including its root field.
