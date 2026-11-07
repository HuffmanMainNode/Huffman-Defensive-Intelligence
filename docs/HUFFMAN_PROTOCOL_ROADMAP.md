# Huffman Protocol Development Roadmap

**Status:** Engineering roadmap. Items are proposals until implemented and verified.

## Mission

Build an open, vendor-neutral assurance layer that tests whether independently operated agents and their supporting systems preserve identity, delegated authority, revocation, evidence provenance, and durable execution guarantees when composed across protocol boundaries.

Huffman Protocol is not intended to replace A2A, MCP, OIX, identity standards, model runtimes, or message transports. It should reuse their interfaces and test their composition.

## Existing foundation

The following components already exist in the Huffman repository ecosystem:

- **OIX:** Ed25519 agent identities and signed messages, capability labels, approval-gated inbox, encryption primitives, discovery, receipts, replay controls, and experimental local/network transports.
- **AAP:** external authorization specification and broker model to evaluate for delegated grants, resource scoping, revocation, and credential confinement. No AAP adapter is currently implemented in the Huffman repositories.
- **Open-Swarm:** local task orchestration, model adapters, approval gates, SQLite task lifecycle, durable outbox, and event journal.
- **HDI:** evidence normalization, authenticated OIX ingress, durable SQLite journal, idempotent delivery, source adapters, and cross-project conformance tests.
- **Huffman Assurance v0.1:** signed portable test-run receipts, challenge binding, evidence digests, and PASS/FAIL/INCOMPLETE result classification.

These components have different maturity levels. Local tests and loopback demonstrations must not be described as production WAN deployment or independent security certification.

## Prior-art rule

Do not rebuild capabilities that already have mature open implementations. Evaluate and integrate:

- OAP RFC 0019 for signed conformance receipts, receipt verification, live re-verification, and peer witnesses.
- OpenA2A AAP for scoped capability grants, cross-agent delegation, revocation propagation, and broker-side credential confinement. AAP is an active Internet-Draft; its current draft and reference implementation maturity must be checked at each integration.
- A2A TCK for A2A transport and behavior conformance.
- HandoffProbe for A2A-to-MCP handoff security scenarios.
- AgentRFC/AgentConform and AgentThread for specification-derived invariants, formal modeling, and counterexample replay.

Huffman work should concentrate on a practical integration profile spanning AAP authorization, A2A agent collaboration, MCP tool access, and the OIX/Open-Swarm/HDI execution and evidence components. The key test question is whether the combined system preserves authority, revocation, approval, and evidence lineage across every boundary. Where an upstream standard already solves a problem, prefer compatibility or contribution upstream over a competing identity, authorization, transport, or receipt format.

## Architecture

### 1. Protocol adapters

The first target profile should map AAP authorization decisions to A2A task delegation and MCP tool calls, while preserving OIX message identity and HDI evidence lineage. It must not mint a parallel Huffman authorization token if an AAP credential can be verified and enforced by the operator-controlled broker.

The first implementation target is a local, disposable test environment. Do not claim AAP interoperability until the exact draft version, schema, cryptographic profile, and conformance fixtures have been pinned and tested.

A common adapter contract should expose:
- implementation identity and version;
- protocol and schema versions;
- declared capabilities and supported operations;
- read-only discovery and health checks;
- explicitly authorized test actions;
- normalized observations and evidence references;
- cleanup and test-environment reset operations.

Adapters must not silently turn a read-only test into task execution. Remote side effects require explicit operator authorization and disposable targets.

### 2. Scenario engine

Scenarios describe actors, trust boundaries, initial state, permitted actions, adversarial actions, expected invariants, and evidence requirements.

A scenario must distinguish:
- protocol-mandated behavior;
- implementation-specific behavior;
- environment assumptions;
- adversary-controlled actions;
- optional hardening requirements.

Each finding must identify which category was violated. Do not report a missing optional hardening feature as protocol non-conformance.

### 3. Delegation and authority model

The first high-value scenario family should test a bounded delegation chain:

1. Principal A grants agent B a narrowly scoped task.
2. B may delegate only if its grant explicitly permits delegation.
3. B's child grant to C must be no broader than B's grant.
4. Child expiry must not exceed parent expiry.
5. The task, audience, resource scope, and capability set must remain bound across hops.
6. Revoking an ancestor grant must invalidate descendant authority.
7. A verifier with stale or unavailable revocation state must fail closed for consequential actions.

Candidate grant fields include grant ID, issuer, subject, parent grant ID, task ID, audience, capability set, resource scope, issue/expiry times, delegation depth, and issuer signature. The wire format is not frozen. The design must be compared with existing delegation and authorization standards before implementation.

### 4. Durable execution and evidence lineage

Test that a delegated task, its approval, execution event, evidence, result, and delivery receipt remain linked across OIX, Open-Swarm, and HDI.

Required invariants:
- an authenticated message is not automatically authorized;
- a capability label is not itself an OS-level permission;
- no event is acknowledged before durable acceptance;
- duplicate delivery is idempotent;
- reusing an event ID with changed content is rejected;
- replay protection survives process restart;
- cancellation and revocation reach downstream work before a new protected effect;
- evidence provenance and uncertainty are never silently upgraded.

### 5. Assurance receipts

The current v0.1 receipt is a basic signed record. The next version should not add fields until the runner and adapter contracts are stable.

The runner should bind a result to:
- immutable test-suite manifest and digest;
- target implementation and version;
- protocol/schema versions;
- scenario and run identifiers;
- fresh verifier challenge;
- individual outcomes and evidence hashes;
- verifier key and signature;
- explicit assumptions, exclusions, and inconclusive checks.

A future interoperability study should map this record to OAP RFC 0019 rather than assume a new receipt standard is necessary.

### 6. Formal model and counterexample replay

Formal modeling should target a small number of critical invariants before adding broad scenario counts.

Initial invariants:
- **Authority monotonicity:** no descendant grant exceeds the authority of its parent.
- **Revocation safety:** a revoked ancestor cannot authorize a new protected action through a descendant.
- **Audience binding:** a grant for one subject, task, or resource cannot be replayed for another.
- **Durable acknowledgement:** a consumer acknowledgement cannot precede durable journal acceptance.
- **Idempotency:** identical retries do not create duplicate effects; changed content under the same identity is rejected.
- **Evidence lineage:** every derived result retains references to its source observations.

Use model-generated counterexamples as inputs to executable regression tests. Formal model success is bounded by the model's assumptions and is not a proof that an entire deployment is secure.

## Delivery stages

### Stage 0: Existing foundation and receipt primitive

**Status: implemented, subject to the current CI evidence.**

- OIX, Open-Swarm, and HDI already provide reusable components.
- HDI contains the first assurance receipt implementation.
- The receipt tests cover signing, verification, freshness, challenge mismatch, tampering, evidence requirements, and outcome classification.

### Stage 1: Prior-art and adapter inventory

**Acceptance criteria:**
- Document supported protocol versions and exact adapter boundaries.
- Compare OAP, A2A TCK, HandoffProbe, AgentConform, and AgentThread.
- Identify what can be reused, wrapped, or contributed upstream.
- No duplicate transport or receipt implementation without a documented interoperability gap.

### Stage 2: Local executable composition runner

**Acceptance criteria:**
- At least two independent OS processes.
- OIX identity and signed request.
- Open-Swarm task execution behind its existing approval boundary.
- HDI durable event ingestion.
- Restart and retry tests against real SQLite state.
- One machine-readable run report with evidence digests.
- No synthetic success presented as a live network result.

### Stage 3: Delegation and revocation

**Acceptance criteria:**
- Three-agent A-to-B-to-C delegation scenario.
- Explicit scope attenuation and audience binding.
- Ancestor revocation invalidates descendants.
- Stale revocation data blocks consequential execution.
- Revocation and authorization outcomes persist across restart.
- Negative tests prove unauthorized actions are rejected.

### Stage 4: Cross-protocol adversarial suite

Initial scenarios:
- stale authorization reused for a new effect;
- child agent attempts capability amplification;
- ancestor revocation while a descendant is queued;
- replay after process restart;
- duplicate message with identical content;
- same identifier reused with altered content;
- crash between durable append and upstream acknowledgement;
- expired lease and competing consumer;
- key rotation and revoked peer key;
- clock skew and expired credentials;
- prompt-injection content crossing a protocol bridge;
- evidence digest mismatch or missing source provenance.

Each scenario must include a vulnerable fixture, a secure fixture, an expected result, and a regression test. A test harness must report its own failures separately from a detected security failure.

### Stage 5: Independent verification and reproducibility

**Acceptance criteria:**
- Separate verifier process can validate the receipt and evidence bundle.
- Test-suite manifest is content-addressed and reproducible.
- Randomized live re-checks are bounded and operator-authorized.
- Verifier trust policy is explicit and configurable.
- OAP receipt interoperability is tested before expanding Huffman receipt semantics.
- Results preserve inconclusive and not-run states.

### Stage 6: External interoperability

**Acceptance criteria:**
- A2A and MCP adapters tested against official conformance tooling where possible.
- At least one independent implementation outside the Huffman ecosystem participates.
- Reproducible setup instructions work without a Huffman-hosted service.
- Compatibility and limitations are published by protocol version.
- Independent security review is invited before any production claim.

## Non-goals

- Creating a new general-purpose agent transport.
- Replacing A2A, MCP, OIX, or existing identity systems.
- Creating a centralized global trust authority.
- Claiming model consciousness or access to private model reasoning.
- Treating majority vote, reputation, or a signed statement as proof of truth.
- Executing arbitrary code or remote side effects as part of default tests.
- Claiming certification, production security, or cryptographic proof of execution from a signed report alone.

## Release discipline

Every release must include:
- implemented code, not documentation alone;
- tests for success, failure, malformed input, and recovery;
- supported-version matrix;
- threat model and explicit non-claims;
- reproducible local commands;
- CI results;
- evidence artifacts and known limitations.

A feature is not complete because a branch or pull request exists. It is complete only after tests pass, the change is reviewed, merged when appropriate, and the merged files are verified on the default branch.
