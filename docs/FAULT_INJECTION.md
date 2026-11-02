# Fault-injection and recovery coverage

This matrix separates behaviors exercised by automated tests from failure modes that still require a transport or deployment environment. A passing local test is not a production certification.

## Automated coverage

| Failure or adversarial condition | Current behavior | Test coverage |
|---|---|---|
| Duplicate HDI event ID with identical canonical content | Idempotent append; one event and one outbox row | `tests/test_sqlite_journal.py` |
| Reused event ID with different content | Reject with `EventConflictError`; do not overwrite | `tests/test_sqlite_journal.py` |
| Concurrent local writer processes | SQLite initialization retries lock/busy collisions; transactional append serializes writers | `tests/test_sqlite_journal.py`, `tests/test_four_process_integration.py` |
| Worker stops after claiming a delivery | Lease expires and a restarted worker can reclaim the same event | `tests/test_sqlite_journal.py` |
| Transient delivery failure | Explicit release returns the item to pending | `tests/test_sqlite_journal.py` |
| Wrong worker, stale token, expired lease or reused worker ID acknowledges/releases | Reject with `LeaseError`; each claim has a distinct fencing token | `tests/test_sqlite_journal.py` |
| Child process exits abruptly after event insert but before commit | SQLite recovery rolls back the uncommitted event and outbox transaction; a subsequent normal append succeeds | `tests/test_sqlite_journal.py::test_process_death_before_commit_rolls_back_entire_append` |
| Replayed OIX sender nonce or message ID | Durable replay gate rejects reuse; identical accepted envelope retry is idempotent | `tests/test_oix_authenticated_ingress.py` |
| Expired or too-far-future OIX message | Reject during message verification | `tests/test_oix_authenticated_ingress.py` |
| Invalid signature or untrusted peer key | Reject before durable OIX acceptance | `tests/test_oix_authenticated_ingress.py` |
| Malformed or tampered Open-Swarm source row | Reject import; source cursor does not advance | `tests/test_open_swarm_importer.py` |
| Conflicting event in an imported source batch | Roll back the whole HDI batch and source cursor | `tests/test_open_swarm_importer.py` |
| Repeated Open-Swarm import | Stable event identity and source cursor prevent duplicate event/outbox rows | `tests/test_open_swarm_importer.py` |
| Cross-project adapter contract mismatch | Reject invalid source shape, verification or digest | `tests/test_upstream_adapters.py` |

The abrupt-exit test covers process death before SQLite commit at two transaction points. It does not simulate power loss, storage-controller failure, filesystem corruption, or a kill during the commit syscall.

## Not yet tested or implemented

- **Commit-boundary and power-loss testing:** no hardware-level power-cut or storage-controller failure test has been completed.
- **Network disconnect/reconnect and delayed delivery:** HDI does not currently provide a network listener or supervised WAN relay. These require a real transport test harness.
- **Storage exhaustion, filesystem errors, database corruption and restore drills:** no operational disaster-recovery test has been completed.
- **External side-effect deduplication:** HDI provides at-least-once outbox delivery. It cannot guarantee exactly-once effects in downstream systems.
- **Peer key rotation/revocation and replay-record retention operations:** these remain operator-managed and are not automated.

## Run the relevant checks

```bash
pytest -q tests/test_sqlite_journal.py
pytest -q tests/test_oix_authenticated_ingress.py
pytest -q tests/test_open_swarm_importer.py
pytest -q tests/test_four_process_integration.py
pytest -q tests/test_upstream_adapters.py
```

All test data is synthetic unless a test explicitly states otherwise. Do not use production secrets, private keys or restricted evidence in fault-injection fixtures.
