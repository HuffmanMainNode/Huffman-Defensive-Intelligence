import json
from pathlib import Path

import pytest

from hdi.journal import EventConflictError, LeaseError, SQLiteJournal
from hdi.model import HDIEvent


def sample_event():
    return HDIEvent.from_dict(
        json.loads(Path("examples/sample-event.json").read_text(encoding="utf-8"))
    )


def test_append_is_idempotent_and_creates_one_outbox_item(tmp_path):
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    event = sample_event()
    first = journal.append(event)
    second = journal.append(event)
    assert first == second
    assert len(list(journal.read_all())) == 1
    assert journal.outbox_counts() == {"pending": 1, "leased": 0, "delivered": 0}


def test_same_event_id_with_different_content_is_rejected(tmp_path):
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    event = sample_event()
    journal.append(event)
    changed = HDIEvent(
        event_id=event.event_id, event_type=event.event_type,
        source_project=event.source_project, occurred_at=event.occurred_at,
        payload={"different": "content"},
    )
    with pytest.raises(EventConflictError):
        journal.append(changed)


def test_delivery_lease_acknowledgement_and_redelivery(tmp_path):
    now = [1000.0]
    journal = SQLiteJournal(tmp_path / "hdi.sqlite", clock=lambda: now[0])
    event = sample_event()
    journal.append(event)

    first = journal.claim_next("worker-a", lease_seconds=10)
    assert first is not None and first.attempts == 1
    assert journal.claim_next("worker-b", lease_seconds=10) is None

    now[0] = 1011.0
    second = journal.claim_next("worker-b", lease_seconds=10)
    assert second is not None and second.attempts == 2
    with pytest.raises(LeaseError):
        journal.acknowledge(event.event_id, "worker-a")

    assert journal.acknowledge(event.event_id, "worker-b") is True
    assert journal.acknowledge(event.event_id, "worker-b") is False
    assert journal.claim_next("worker-c") is None
    assert journal.outbox_counts() == {"pending": 0, "leased": 0, "delivered": 1}


def test_release_returns_item_to_pending(tmp_path):
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    event = sample_event()
    journal.append(event)
    delivery = journal.claim_next("worker-a")
    journal.release(event.event_id, "worker-a")
    assert journal.outbox_counts()["pending"] == 1
    assert journal.claim_next("worker-b").event_id == delivery.event_id


def test_unknown_event_acknowledgement_fails(tmp_path):
    journal = SQLiteJournal(tmp_path / "hdi.sqlite")
    with pytest.raises(KeyError):
        journal.acknowledge("missing-event", "worker-a")
