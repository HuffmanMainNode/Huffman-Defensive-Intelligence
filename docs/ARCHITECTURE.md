# Architecture

OIX owns peer identity and transport. Open-Swarm owns task lifecycle. Halloween OSINT owns source acquisition and evidence analysis. Cyber Observatory owns defensive findings and integrity. HDI owns normalized contracts, provenance requirements, routing policy and conformance tests.

The adapters validate and classify upstream records. HDI 0.4.0 includes an explicit local Open-Swarm consumer over its documented SQLiteEventBus interface. It does not start a daemon, open sockets, or call undocumented APIs. Production connectors must target documented upstream interfaces and pass contract fixtures before enablement.

HDI provides two local journal backends. The JSONL `Journal` is a simple single-writer reference implementation with event-ID deduplication, conflicting-content rejection, fsync-backed appends and explicit invalid-record handling. Its read-before-append check is not safe for concurrent writers.

The optional SQLite `SQLiteJournal` is the transactional backend for concurrent local processes. It uses SQLite write transactions, WAL mode, full synchronous commits and a busy timeout. Event insertion and outbox creation are atomic. The same event ID and canonical digest are idempotent; a conflicting digest is rejected. Lease claims, acknowledgements, releases, OIX replay acceptance and Open-Swarm source-offset advancement are persisted in the same local database. The Open-Swarm importer appends events and advances its source cursor atomically before acknowledging the upstream consumer sequence.

Both backends are local. SQLite supports concurrent writers on one host, but neither backend provides multi-host replication, distributed consensus, exactly-once external side effects or a broker cluster. Delivery is at least once, so downstream consumers must use stable idempotency keys.
