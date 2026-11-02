import json
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from hdi.model import HDIEvent
from hdi.sqlite_journal import EventConflictError, LeaseError, SQLiteJournal




def _append_in_process(args):
    database, event_data = args
    journal = SQLiteJournal(database)
    return journal.append(HDIEvent.from_dict(event_data))


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


def test_separate_journal_instances_share_idempotency_and_leases(tmp_path):
    database = tmp_path / "shared.sqlite"
    first = SQLiteJournal(database)
    second = SQLiteJournal(database)
    event = sample_event()
    assert first.append(event) == second.append(event)
    claim = first.claim_next("worker-a")
    assert claim is not None
    assert second.claim_next("worker-b") is None
    with pytest.raises(LeaseError):
        second.release(event.event_id, "worker-b")
    second.acknowledge(event.event_id, "worker-a")
    assert first.outbox_counts()["delivered"] == 1


def test_lease_expiry_can_be_reclaimed_after_worker_restart(tmp_path):
    now = [50.0]
    first = SQLiteJournal(tmp_path / "shared.sqlite", clock=lambda: now[0])
    event = sample_event()
    first.append(event)
    assert first.claim_next("worker-before-crash", lease_seconds=5) is not None
    now[0] = 56.0
    restarted = SQLiteJournal(tmp_path / "shared.sqlite", clock=lambda: now[0])
    recovered = restarted.claim_next("worker-after-restart", lease_seconds=5)
    assert recovered is not None
    assert recovered.attempts == 2


def test_concurrent_connections_append_same_event_once(tmp_path):
    database = tmp_path / "concurrent.sqlite"
    journals = [SQLiteJournal(database) for _ in range(12)]
    event = sample_event()
    with ThreadPoolExecutor(max_workers=len(journals)) as pool:
        digests = list(pool.map(lambda journal: journal.append(event), journals))
    assert len(set(digests)) == 1
    assert len(list(journals[0].read_all())) == 1
    assert journals[0].outbox_counts() == {
        "pending": 1, "leased": 0, "delivered": 0
    }


def test_concurrent_conflicting_content_has_one_winner(tmp_path):
    database = tmp_path / "conflicting.sqlite"
    journals = [SQLiteJournal(database), SQLiteJournal(database)]
    original = sample_event()
    changed = replace(original, payload={"different": "content"})

    def append_or_conflict(args):
        journal, item = args
        try:
            return ("accepted", journal.append(item))
        except EventConflictError:
            return ("conflict", None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(append_or_conflict, zip(journals, (original, changed))))
    assert sorted(result[0] for result in results) == ["accepted", "conflict"]
    assert len(list(journals[0].read_all())) == 1
    assert journals[0].outbox_counts()["pending"] == 1


def test_concurrent_processes_append_same_event_once(tmp_path):
    database = str(tmp_path / "processes.sqlite")
    event = sample_event()
    args = [(database, event.to_dict()) for _ in range(8)]
    with ProcessPoolExecutor(max_workers=8) as pool:
        digests = list(pool.map(_append_in_process, args))
    journal = SQLiteJournal(database)
    assert len(set(digests)) == 1
    assert len(list(journal.read_all())) == 1
    assert journal.outbox_counts() == {
        "pending": 1, "leased": 0, "delivered": 0
    }
