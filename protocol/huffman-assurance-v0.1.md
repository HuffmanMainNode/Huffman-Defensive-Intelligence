# Huffman Protocol Assurance Profile v0.1

**Status:** Experimental implementation profile. Not a ratified standard, certification program, or security guarantee.

## 1. Purpose

Huffman Protocol Assurance defines a portable, machine-verifiable record of a bounded agent or protocol test run. It lets an independent consumer inspect which implementation was tested, which test suite and version were used, which checks ran, what outcomes were recorded, and which evidence digests support those outcomes.

The first implementation is a receipt format and verifier library in HDI. It is deliberately not a new agent transport, identity system, discovery service, authorization authority, or orchestration runtime.

## 2. Design boundary

Huffman Protocol reuses upstream identity, message, and execution systems. It does not replace OIX, A2A, MCP, Open-Swarm, or HDI's event journal.

A receipt signature proves that the holder of the verifier private key signed the receipt bytes. It does **not** prove that:
- the verifier ran the claimed tests honestly;
- the test suite is complete or unbiased;
- evidence is factually true or authentic at source;
- the tested implementation is safe outside the declared scope;
- a subject identifier maps to a real-world person or organization;
- a passing result constitutes certification.

Consumers must decide which verifier keys, test suites, versions, evidence sources, and freshness windows they accept.

## 3. Receipt contents

The v0.1 receipt contains:
- schema identifier and unique receipt ID;
- issue and expiry timestamps;
- verifier key fingerprint;
- tested subject identifier, implementation name, and version;
- test suite identifier, version, and SHA-256 digest;
- run identifier and challenge nonce;
- individual check identifiers, requirement descriptions, outcomes, and evidence digests;
- Ed25519 signature over the canonical receipt body.

Check outcomes are PASS, FAIL, INCONCLUSIVE, and NOT_RUN. A PASS or FAIL must include at least one evidence digest. A missing required check, an inconclusive check, or a not-run check prevents an overall PASS. Any recorded FAIL makes the overall result FAIL.

## 4. Canonicalization and signatures

The reference implementation uses a restricted deterministic JSON profile:
- UTF-8 encoding;
- object keys sorted lexicographically;
- compact separators;
- Unicode NFC normalization;
- no floating-point values;
- maximum nesting depth 32;
- maximum 10,000 members per object or array;
- maximum encoded receipt size 1,000,000 bytes.

Ed25519 signs the canonical body with the signature field excluded. The verifier key ID is ed25519: followed by the lowercase hexadecimal SHA-256 digest of the raw 32-byte Ed25519 public key.

## 5. Freshness and challenge binding

Receipts have an integer Unix-time validity window no longer than 86,400 seconds. Verification rejects receipts issued more than 60 seconds in the future and receipts that have expired.

Online verifiers SHOULD supply an unpredictable challenge nonce and require an exact match. A signature without a verifier-supplied expected nonce authenticates the signed receipt but does not prevent an otherwise valid receipt from being replayed.

## 6. Trust model

The receipt signer is the verifier, not necessarily the tested agent or its operator. A verifier key must be trusted out-of-band or through a separately governed trust mechanism. Self-asserted verifier identity is not sufficient for high-assurance use.

Evidence digests provide integrity references only. They do not establish provenance, availability, authenticity, or truth. Future profiles may add signed evidence manifests, source attestations, transparency logs, and independent verifier quorum; none are claimed in v0.1.

## 7. Interoperability roadmap

The next implementation stages are:
1. protocol adapters that execute bounded conformance checks against OIX, A2A, and MCP endpoints;
2. cross-protocol delegation and revocation scenarios;
3. portable evidence bundles and reproducible test-suite manifests;
4. verifier trust policies and receipt transparency;
5. independent-process and network fault-injection harnesses.

Adapters must be read-only by default. Tests that submit tasks, invoke tools, or cause external side effects require explicit operator authorization and a disposable target environment.

## 8. Prior art and differentiation

This profile does not claim to invent agent conformance testing. Existing work includes the A2A Technology Compatibility Kit, HandoffProbe's A2A-to-MCP handoff security tests, and research such as AgentRFC/AgentThread on protocol security analysis and composition.

The proposed contribution is a small, portable receipt contract that can carry independently inspectable results across these tools and future adapters. That distinction must be validated through implementation and external review, not asserted as proven novelty.

## 9. Maturity

v0.1 is an experimental receipt primitive. It is not a full protocol test harness, a distributed trust network, a cryptographic proof of execution, or a certification authority.
