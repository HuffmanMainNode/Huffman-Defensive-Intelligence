# Architecture

OIX owns peer identity and transport. Open-Swarm owns task lifecycle. Halloween OSINT owns source acquisition and evidence analysis. Cyber Observatory owns defensive findings and integrity. HDI owns normalized contracts, provenance requirements, routing policy and conformance tests.

The adapters validate and classify upstream records. HDI 0.4.0 includes an explicit local Open-Swarm consumer over its documented SQLiteEventBus interface. It does not start a daemon, open sockets, or call undocumented APIs. Production connectors must target documented upstream interfaces and pass contract fixtures before enablement.

The HDI JSONL journal remains local. The Open-Swarm connector uses a stable consumer ID, appends to HDI before acknowledging the source offset, and relies on idempotent event IDs to recover from a crash between those two operations. This is at-least-once delivery.

The JSONL journal is local and single-writer. It deduplicates by event ID and canonical event digest: an identical retry returns the original digest without appending, while the same ID with different content is rejected. Each append is flushed and fsynced before success is returned. A valid final record without a newline is separated before the next append. Invalid or truncated JSON records are reported, not silently discarded. The read-before-append idempotency check is not safe under concurrent multi-process writers. This is at-least-once delivery with local deduplication, not distributed exactly-once delivery or multi-host consensus.
