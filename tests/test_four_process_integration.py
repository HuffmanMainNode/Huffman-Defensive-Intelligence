import json
import subprocess
import sys
from pathlib import Path

from hdi.sqlite_journal import SQLiteJournal


def test_four_process_demo_normalizes_and_persists_all_projects(tmp_path):
    database = tmp_path / "four-process.sqlite"
    script = Path("examples/four_process_integration_demo.py")
    completed = subprocess.run(
        [sys.executable, str(script), "--database", str(database)],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    report = json.loads(completed.stdout)
    assert report["synthetic_fixtures"] is True
    assert report["process_count"] == 4
    assert report["event_count"] == 4
    assert report["projects"] == [
        "cyber_observatory",
        "halloween_osint",
        "oix",
        "open_swarm",
    ]
    journal = SQLiteJournal(database)
    assert len(list(journal.read_all())) == 4
    assert journal.outbox_counts() == {
        "pending": 4,
        "leased": 0,
        "delivered": 0,
    }
