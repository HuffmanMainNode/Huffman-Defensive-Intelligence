import json
import os
from pathlib import Path

from hdi.model import HDIEvent


class JournalError(ValueError):
    """The local journal cannot safely accept an event."""


class EventConflictError(JournalError):
    """An event ID is already associated with different canonical content."""


class Journal:
    """Local single-writer JSONL journal with event-ID idempotency.

    Appends are flushed and fsynced before returning. The read-before-append
    duplicate check is intentionally single-writer only: concurrent processes
    must use an external single-writer supervisor or a future transactional store.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _existing_digests(self):
        digests = {}
        for existing in self.read_all() or ():
            digest = existing.canonical_sha256()
            previous = digests.get(existing.event_id)
            if previous is not None and previous != digest:
                raise JournalError(
                    f"journal contains conflicting records for event_id {existing.event_id!r}"
                )
            digests[existing.event_id] = digest
        return digests

    def append(self, event: HDIEvent):
        event.validate()
        digest = event.canonical_sha256()
        existing = self._existing_digests()
        previous = existing.get(event.event_id)
        if previous is not None:
            if previous != digest:
                raise EventConflictError(
                    f"event_id {event.event_id!r} already exists with different content"
                )
            return digest

        line = json.dumps(
            event.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        # A process may have stopped after writing a complete JSON record but
        # before writing its newline. Separate that record before appending.
        if self.path.exists() and self.path.stat().st_size:
            with self.path.open("rb+") as stream:
                stream.seek(-1, os.SEEK_END)
                if stream.read(1) != b"\n":
                    stream.seek(0, os.SEEK_END)
                    stream.write(b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())

        with self.path.open("a", encoding="utf-8", newline="") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return digest

    def read_all(self):
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    yield HDIEvent.from_dict(json.loads(line))
                except (ValueError, TypeError, KeyError) as exc:
                    raise JournalError(f"invalid journal record at line {number}") from exc
