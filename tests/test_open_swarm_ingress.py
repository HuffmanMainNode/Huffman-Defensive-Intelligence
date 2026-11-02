from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from hdi.adapters.open_swarm import ingest_open_swarm_batch
from hdi.model import EventValidationError
from hdi.sqlite_journal import SQLiteJournal


@dataclass
class FakeEvent:
    raw: dict

    def to_dict(self):
        return self.raw


@dataclass
class FakeRecord:
    sequence: int
    event: FakeEvent


class FakeBus:
    def __init__(self, records):
        self.records = records
        self.acknowledged = []
        self.fail_ack_once = False

    def read(self, consumer_id, *, limit=100):
        assert consumer_id
        return self.records[:limit]

    def acknowledge(self, consumer_id, sequence):
        if self.fail_ack_once:
            self.fail_ack_once = False
            raise RuntimeError("simulated crash before source acknowledgement")
        self.acknowledged.append((consumer_id, sequence))


def platform_event(*, classification="internal"):
    return {
        "event_id": str(uuid4()),
        "event_type": "swarm.task.completed",
        "source": "open-swarm",
        "payload": {"task_id": "task-123", "status": "completed"},
        "schema_version": "1.0",
        "classification": classification,
        "evidence_refs": ["sha256:" + "a" * 64],
        "correlation_id": "case-123",
        "causation_id": None,
        "occurred_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def test_consumer_appends_before_acknowledging(tmp_path):
    raw = platform_event()
    bus = FakeBus([FakeRecord(1, FakeEvent(raw))])
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    receipts = ingest_open_swarm_batch(bus, journal, consumer_id="hdi-test")

    assert len(receipts) == 1
    assert receipts[0]["event_id"] == raw["event_id"]
    assert bus.acknowledged == [("hdi-test", 1)]
    saved = journal.get(raw["event_id"])
    assert saved is not None
    assert saved.source_project == "open_swarm"
    assert saved.payload["classification"] == "internal"
    assert saved.payload["evidence_refs"] == raw["evidence_refs"]


def test_crash_before_ack_retries_idempotently(tmp_path):
    raw = platform_event()
    record = FakeRecord(7, FakeEvent(raw))
    bus = FakeBus([record])
    bus.fail_ack_once = True
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    with pytest.raises(RuntimeError, match="before source acknowledgement"):
        ingest_open_swarm_batch(bus, journal, consumer_id="hdi-test")

    assert journal.get(raw["event_id"]) is not None
    assert bus.acknowledged == []

    receipts = ingest_open_swarm_batch(bus, journal, consumer_id="hdi-test")
    assert len(receipts) == 1
    assert bus.acknowledged == [("hdi-test", 7)]
    assert len(list(journal.read_all())) == 1


def test_invalid_source_event_is_not_acknowledged(tmp_path):
    raw = platform_event(classification="secret")
    bus = FakeBus([FakeRecord(2, FakeEvent(raw))])
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    with pytest.raises(EventValidationError, match="classification"):
        ingest_open_swarm_batch(bus, journal, consumer_id="hdi-test")

    assert bus.acknowledged == []
    assert journal.get(raw["event_id"]) is None


def test_consumer_validates_batch_limit(tmp_path):
    bus = FakeBus([])
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")

    with pytest.raises(ValueError, match="limit"):
        ingest_open_swarm_batch(bus, journal, limit=0)
