import json
from pathlib import Path

import pytest

from hdi.adapters import ALL_ADAPTERS
from hdi.journal import Journal
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
