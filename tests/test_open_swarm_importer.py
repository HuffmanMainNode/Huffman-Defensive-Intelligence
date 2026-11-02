import json
import sqlite3
import uuid

import pytest

from hdi.adapters.open_swarm import OpenSwarmAdapter, OpenSwarmSQLiteImporter
from hdi.model import EventValidationError
from hdi.sqlite_journal import EventConflictError, SQLiteJournal

COLUMNS = """
CREATE TABLE platform_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    source TEXT NOT NULL,
    classification TEXT NOT NULL,
    correlation_id TEXT,
    causation_id TEXT,
    evidence_refs_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    canonical_json TEXT NOT NULL
)
"""


def make_raw(event_id=None, *, indicator="example.org"):
    return {
        "event_id": event_id or str(uuid.uuid4()),
        "event_type": "osint.indicator.observed",
        "source": "halloween-osint",
        "payload": {"indicator_type": "domain", "indicator": indicator},
        "schema_version": "1.0",
        "classification": "public",
        "evidence_refs": ["sha256:" + "a" * 64],
        "correlation_id": "case-001",
        "causation_id": None,
        "occurred_at": "2026-11-02T12:00:00Z",
    }


def create_source(path, events):
    with sqlite3.connect(path) as db:
        db.execute(COLUMNS)
        for event in events:
            canonical = json.dumps(
                event, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            db.execute(
                """INSERT INTO platform_events(
                    event_id,event_type,schema_version,occurred_at,source,classification,
                    correlation_id,causation_id,evidence_refs_json,payload_json,canonical_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event["event_id"], event["event_type"], event["schema_version"],
                    event["occurred_at"], event["source"], event["classification"],
                    event["correlation_id"], event["causation_id"],
                    json.dumps(event["evidence_refs"], ensure_ascii=False, separators=(",", ":")),
                    json.dumps(event["payload"], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    canonical,
                ),
            )


def test_read_only_import_advances_cursor_atomically_and_resumes(tmp_path):
    source = tmp_path / "openswarm.sqlite"
    events = [make_raw(), make_raw(indicator="second.example")]
    create_source(source, events)
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    importer = OpenSwarmSQLiteImporter(source, source_id="openswarm-local")

    first = importer.import_into(journal, limit=1)
    assert first.imported_count == 1
    assert first.last_sequence == 1
    assert journal.source_offset("openswarm-local") == 1

    second = importer.import_into(journal, limit=10)
    assert second.imported_count == 1
    assert second.last_sequence == 2
    assert journal.source_offset("openswarm-local") == 2

    empty = importer.import_into(journal)
    assert empty.imported_count == 0
    assert empty.last_sequence == 2
    saved = list(journal.read_all())
    assert len(saved) == 2
    assert saved[0].source_project == "open_swarm"
    assert saved[0].payload["source"] == "halloween-osint"
    assert journal.outbox_counts() == {"pending": 2, "leased": 0, "delivered": 0}


def test_source_database_is_opened_read_only(tmp_path):
    source = tmp_path / "openswarm.sqlite"
    create_source(source, [make_raw()])
    importer = OpenSwarmSQLiteImporter(source, source_id="read-only-check")
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    importer.import_into(journal)
    with pytest.raises(sqlite3.OperationalError), sqlite3.connect(
        f"{source.as_uri()}?mode=ro", uri=True
    ) as db:
        db.execute("INSERT INTO platform_events(event_id) VALUES('blocked')")


def test_corrupt_source_row_does_not_advance_cursor_or_partially_import(tmp_path):
    source = tmp_path / "openswarm.sqlite"
    raw = make_raw()
    create_source(source, [raw])
    with sqlite3.connect(source) as db:
        db.execute(
            "UPDATE platform_events SET payload_json=? WHERE event_id=?",
            ('{"tampered":true}', raw["event_id"]),
        )
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    importer = OpenSwarmSQLiteImporter(source, source_id="corrupt-source")
    with pytest.raises(EventValidationError, match="disagree"):
        importer.import_into(journal)
    assert journal.source_offset("corrupt-source") == 0
    assert list(journal.read_all()) == []


def test_import_conflict_rolls_back_entire_batch_and_cursor(tmp_path):
    source = tmp_path / "openswarm.sqlite"
    first = make_raw()
    second = make_raw(indicator="different.example")
    create_source(source, [first, second])
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    conflicting = OpenSwarmSQLiteImporter(source, source_id="conflict-source")
    existing = OpenSwarmAdapter().normalize_platform_event(
        {**second, "payload": {"indicator_type": "domain", "indicator": "wrong.example"}}
    )
    journal.append(existing)
    with pytest.raises(EventConflictError):
        conflicting.import_into(journal, limit=2)
    assert journal.source_offset("conflict-source") == 0
    assert len(list(journal.read_all())) == 1


def test_symlinked_source_database_is_rejected(tmp_path):
    source = tmp_path / "real.sqlite"
    create_source(source, [make_raw()])
    link = tmp_path / "alias.sqlite"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="symlink"):
        OpenSwarmSQLiteImporter(link, source_id="symlink-source")


def test_source_id_cannot_be_reused_for_a_different_database(tmp_path):
    first_source = tmp_path / "first.sqlite"
    second_source = tmp_path / "second.sqlite"
    create_source(first_source, [make_raw()])
    create_source(second_source, [make_raw()])
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    OpenSwarmSQLiteImporter(
        first_source, source_id="same-logical-source"
    ).import_into(journal)
    second_importer = OpenSwarmSQLiteImporter(
        second_source, source_id="same-logical-source"
    )
    with pytest.raises(ValueError, match="different source identity"):
        second_importer.import_into(journal)
