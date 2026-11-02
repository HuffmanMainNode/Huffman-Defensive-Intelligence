import json
from pathlib import Path

from hdi.model import HDIEvent

class Journal:
    """Local single-writer JSONL journal, not a distributed event broker."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: HDIEvent):
        event.validate()
        line = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
        return event.canonical_sha256()

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
                    raise ValueError(f"invalid journal record at line {number}") from exc
