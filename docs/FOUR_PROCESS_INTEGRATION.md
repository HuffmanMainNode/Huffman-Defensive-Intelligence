# Four-process local integration demo

The demo launches four independent operating-system processes, one for each upstream adapter contract:

- OIX
- Open-Swarm
- Halloween OSINT
- Cyber Observatory

Each worker normalizes a synthetic fixture, opens its own `SQLiteJournal` connection, and appends to the same local database. The parent process verifies that all four source projects are present and that exactly four outbox records were created.

## Run

From the repository root:

```bash
python examples/four_process_integration_demo.py
```

To retain the database for inspection:

```bash
python examples/four_process_integration_demo.py --database ./state/four-process-demo.sqlite
```

Expected output includes `synthetic_fixtures: true`, `process_count: 4`, `event_count: 4`, all four project identifiers, and four pending outbox entries.

## Important limits

- All fixtures are synthetic and contain no live intelligence.
- OIX and Cyber Observatory verification flags in this demonstration are explicit test attestations. They are not cryptographic proof. Use the authenticated OIX ingress and Cyber evidence approval paths for real inputs.
- The demo tests local process isolation and concurrent SQLite persistence. It does not start the upstream projects, connect to networks, or validate a WAN agent mesh.
- A pending outbox item is not evidence that a task was executed or an external side effect occurred.
- Downstream delivery remains at least once. Consumers must use stable idempotency keys.

The companion test `tests/test_four_process_integration.py` runs the demo under CI.