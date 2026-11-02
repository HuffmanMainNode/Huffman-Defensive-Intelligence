import json

import pytest

from hdi.adapters.halloween_osint import HalloweenManifestImporter, HalloweenOSINTAdapter
from hdi.model import EventValidationError
from hdi.sqlite_journal import SQLiteJournal


def manifest(*, root="/private/evidence/case-7", files=None):
    return {
        "schema_version": "1.0",
        "created_at": "2026-11-02T12:00:00+00:00",
        "algorithm": "sha256",
        "root": root,
        "files": files if files is not None else [
            {"path": "captures/report.json", "size_bytes": 42, "sha256": "a" * 64}
        ],
    }


def write_manifest(path, value):
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    return path


def test_manifest_import_is_deterministic_and_idempotent(tmp_path):
    source = write_manifest(tmp_path / "manifest.json", manifest())
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    importer = HalloweenManifestImporter(source)

    first = importer.import_into(journal)
    second = importer.import_into(journal)

    assert first == second
    assert len(list(journal.read_all())) == 1
    saved = journal.get(first["event_id"])
    assert saved.source_project == "halloween_osint"
    assert saved.payload["root_path_redacted"] is True
    assert "root" not in saved.payload
    assert saved.evidence[0].sha256 == saved.payload["manifest_sha256"]


def test_importer_does_not_open_manifest_root_or_evidence_files(tmp_path):
    source = write_manifest(
        tmp_path / "manifest.json",
        manifest(root=str(tmp_path / "does-not-exist")),
    )
    event = HalloweenManifestImporter(source).normalize()
    assert event.payload["root_path_redacted"] is True
    assert not (tmp_path / "does-not-exist").exists()


def test_duplicate_json_keys_are_rejected(tmp_path):
    source = tmp_path / "duplicate.json"
    source.write_text(
        '{"schema_version":"1.0","schema_version":"1.0","created_at":"2026-11-02T12:00:00Z",'
        '"algorithm":"sha256","root":"/private","files":[]}',
        encoding="utf-8",
    )
    with pytest.raises(EventValidationError, match="duplicate JSON object key"):
        HalloweenManifestImporter(source).normalize()


def test_oversized_manifest_is_rejected_before_parsing(tmp_path):
    source = tmp_path / "large.json"
    source.write_text(" " * 128, encoding="utf-8")
    with pytest.raises(EventValidationError, match="size limit"):
        HalloweenManifestImporter(source, max_bytes=64)


def test_symlinked_manifest_is_rejected(tmp_path):
    target = write_manifest(tmp_path / "real.json", manifest())
    link = tmp_path / "alias.json"
    link.symlink_to(target)
    with pytest.raises(EventValidationError, match="symlinks"):
        HalloweenManifestImporter(link)


@pytest.mark.parametrize("unsafe_path", [
    "../escape.txt",
    "/absolute.txt",
    "C:/windows/file.txt",
    "folder//file.txt",
    "folder/./file.txt",
    "folder\\file.txt",
])
def test_unsafe_manifest_paths_are_rejected(unsafe_path):
    value = manifest(files=[
        {"path": unsafe_path, "size_bytes": 1, "sha256": "b" * 64}
    ])
    with pytest.raises(EventValidationError, match="safe relative POSIX"):
        HalloweenOSINTAdapter().normalize_manifest(value)


def test_duplicate_manifest_file_paths_are_rejected():
    record = {"path": "same.txt", "size_bytes": 1, "sha256": "c" * 64}
    value = manifest(files=[record, record])
    with pytest.raises(EventValidationError, match="duplicate file paths"):
        HalloweenOSINTAdapter().normalize_manifest(value)


def test_invalid_utf8_manifest_is_rejected(tmp_path):
    source = tmp_path / "invalid.json"
    source.write_bytes(b"\xff\xfe")
    with pytest.raises(EventValidationError, match="UTF-8 JSON"):
        HalloweenManifestImporter(source).normalize()
