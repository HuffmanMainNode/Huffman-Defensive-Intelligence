import json
from dataclasses import replace
from pathlib import Path

import pytest

from hdi.adapters import ALL_ADAPTERS
from hdi.journal import EventConflictError, Journal, JournalError
from hdi.model import HDIEvent
from hdi.router import Router


def event():
    return HDIEvent.from_dict(json.loads(Path("examples/sample-event.json").read_text()))


def test_adapters_enforce_source_identity():
    item = event()
    adapters = [cls() for cls in ALL_ADAPTERS]
    assert [a.project_id for a in adapters if a.accepts(item)] == ["halloween_osint"]


def test_router():
    assert Router().matching_adapters(event()) == ["halloween_osint"]


def test_journal_round_trip(tmp_path):
    journal = Journal(tmp_path / "events.jsonl")
    item = event()
    digest = journal.append(item)
    loaded = list(journal.read_all())
    assert len(loaded) == 1
    assert loaded[0].canonical_sha256() == digest


def test_journal_detects_invalid_record(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"wrong":"shape"}\n')
    with pytest.raises(ValueError, match="line 1"):
        list(Journal(path).read_all())


def test_journal_duplicate_event_is_idempotent(tmp_path):
    journal = Journal(tmp_path / "events.jsonl")
    item = event()
    first = journal.append(item)
    second = journal.append(item)
    assert first == second
    assert len(list(journal.read_all())) == 1


def test_journal_rejects_same_id_with_different_content(tmp_path):
    journal = Journal(tmp_path / "events.jsonl")
    item = event()
    journal.append(item)
    changed = replace(item, payload={**item.payload, "changed": True})
    with pytest.raises(EventConflictError, match="different content"):
        journal.append(changed)
    assert len(list(journal.read_all())) == 1


def test_journal_separates_valid_record_without_final_newline(tmp_path):
    path = tmp_path / "events.jsonl"
    journal = Journal(path)
    first = event()
    journal.append(first)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    second = replace(first, event_id="hdi-second-event", payload={"sequence": 2})
    journal.append(second)
    loaded = list(journal.read_all())
    assert [item.event_id for item in loaded] == [first.event_id, second.event_id]


def test_journal_rejects_conflicting_existing_ids(tmp_path):
    path = tmp_path / "events.jsonl"
    first = event()
    second = replace(first, payload={**first.payload, "changed": True})
    path.write_text(
        json.dumps(first.to_dict()) + "\n" + json.dumps(second.to_dict()) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(JournalError, match="conflicting records"):
        Journal(path).append(replace(first, event_id="hdi-new-event"))
