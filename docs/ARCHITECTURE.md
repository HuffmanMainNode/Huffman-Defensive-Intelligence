# Architecture

OIX owns peer identity and transport. Open-Swarm owns task lifecycle. Halloween OSINT owns source acquisition and evidence analysis. Cyber Observatory owns defensive findings and integrity. HDI owns normalized contracts, provenance requirements, routing policy and conformance tests.

The initial adapters validate and classify events only. They do not call undocumented upstream APIs. Production connectors must target documented upstream interfaces and pass contract fixtures before enablement.

The JSONL journal is local and single-writer. It does not provide multi-host consensus, exactly-once delivery or safe concurrent multi-process writes.
