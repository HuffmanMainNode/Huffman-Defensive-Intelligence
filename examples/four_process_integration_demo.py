"""Run four independent adapter workers against one local HDI SQLite journal.

All records in this demonstration are synthetic contract fixtures. The OIX and
Cyber Observatory verification flags are test attestations, not cryptographic
proof or a substitute for the authenticated OIX ingress workflow.
"""
import argparse
import json
import multiprocessing
import tempfile
import uuid
from pathlib import Path

from hdi.adapters.cyber_observatory import CyberObservatoryAdapter
from hdi.adapters.halloween_osint import HalloweenOSINTAdapter
from hdi.adapters.oix import REQUIRED_CHECKS, OIXAdapter, canonical_envelope_sha256
from hdi.adapters.open_swarm import OpenSwarmAdapter
from hdi.model import HDIEvent
from hdi.sqlite_journal import SQLiteJournal

STAMP = "2026-11-02T12:00:00Z"
DIGEST = "a" * 64


def build_synthetic_events():
    """Normalize one synthetic upstream-contract fixture per project."""
    oix_body = {
        "protocol": "OIX",
        "version": "0.1",
        "message_id": str(uuid.uuid4()),
        "sender": "synthetic-peer-fingerprint",
        "recipient": "synthetic-local-agent",
        "type": "task.request",
        "issued_at": 1793620800,
        "expires_at": 1793621100,
        "nonce": "synthetic-nonce-" + uuid.uuid4().hex,
        "requested_capability": "public.research",
        "payload": {"task": "summarize a public advisory"},
    }
    oix_envelope = {"body": oix_body, "signature": "synthetic-test-attestation"}
    oix_event = OIXAdapter().normalize_verified_envelope(
        oix_envelope,
        verification={key: True for key in REQUIRED_CHECKS},
        envelope_sha256=canonical_envelope_sha256(oix_envelope),
    )

    swarm_event = OpenSwarmAdapter().normalize_platform_event({
        "event_id": str(uuid.uuid4()),
        "event_type": "osint.indicator.observed",
        "source": "synthetic-open-swarm-fixture",
        "payload": {"indicator_type": "domain", "indicator": "example.org"},
        "schema_version": "1.0",
        "classification": "public",
        "evidence_refs": ["sha256:" + DIGEST],
        "correlation_id": "case-001",
        "causation_id": None,
        "occurred_at": STAMP,
    })

    halloween_event = HalloweenOSINTAdapter().normalize_manifest({
        "schema_version": "1.0",
        "created_at": STAMP,
        "algorithm": "sha256",
        "root": "/synthetic/evidence",
        "files": [{
            "path": "capture/report.json",
            "size_bytes": 42,
            "sha256": DIGEST,
        }],
    })

    cyber_payload = {
        "schema_version": "1.0",
        "evidence_id": str(uuid.uuid4()),
        "evidence_type": "sbom_analysis",
        "source_uri": "https://example.org/synthetic-bom.json",
        "source_timestamp": None,
        "collected_at": STAMP,
        "collector": {"name": "synthetic-observatory", "version": "0.1.0"},
        "method": {"name": "synthetic-sbom-check", "version": "0.1.0"},
        "artifact": {
            "sha256": DIGEST,
            "size_bytes": 42,
            "media_type": "application/json",
        },
        "classification": "internal",
        "status": "derived",
        "summary": {"matched_kev_entries": 0},
        "limitations": ["Synthetic fixture; no vulnerability conclusion is implied."],
    }
    cyber_event = CyberObservatoryAdapter().normalize_verified_evidence_submit(
        cyber_payload,
        message_id=str(uuid.uuid4()),
        sender_fingerprint="ed25519:" + DIGEST,
        envelope_sha256=DIGEST,
        verification={key: True for key in REQUIRED_CHECKS},
    )
    return [oix_event, swarm_event, halloween_event, cyber_event]


def _append_worker(database, event_data, result_queue):
    try:
        event = HDIEvent.from_dict(event_data)
        digest = SQLiteJournal(database).append(event)
        result_queue.put({
            "ok": True,
            "source_project": event.source_project,
            "event_id": event.event_id,
            "sha256": digest,
        })
    except Exception as exc:
        result_queue.put({
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
        })


def run_demo(database):
    events = build_synthetic_events()
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_append_worker,
            args=(str(database), event.to_dict(), result_queue),
            name=f"hdi-{event.source_project}",
        )
        for event in events
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        if process.is_alive():
            process.terminate()
            process.join()
            raise TimeoutError(f"{process.name} did not finish within 30 seconds")

    results = [result_queue.get(timeout=5) for _ in processes]
    result_queue.close()
    failed = [result for result in results if not result["ok"]]
    failed_processes = [
        {"name": process.name, "exitcode": process.exitcode}
        for process in processes if process.exitcode != 0
    ]
    if failed or failed_processes:
        raise RuntimeError(json.dumps({
            "worker_errors": failed,
            "process_errors": failed_processes,
        }, sort_keys=True))

    journal = SQLiteJournal(database)
    stored = list(journal.read_all())
    expected_projects = {
        "oix", "open_swarm", "halloween_osint", "cyber_observatory"
    }
    actual_projects = {event.source_project for event in stored}
    if len(stored) != 4 or actual_projects != expected_projects:
        raise AssertionError("journal contents do not match the four expected projects")
    return {
        "synthetic_fixtures": True,
        "process_count": len(processes),
        "event_count": len(stored),
        "projects": sorted(actual_projects),
        "outbox": journal.outbox_counts(),
        "database": str(database),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", help="SQLite database path; temporary database if omitted")
    args = parser.parse_args()
    if args.database:
        result = run_demo(Path(args.database))
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    with tempfile.TemporaryDirectory(prefix="hdi-four-process-") as directory:
        result = run_demo(Path(directory) / "hdi.sqlite")
        result["database"] = "temporary database (removed on exit)"
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
