import copy
import hashlib
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hdi.assurance import AssuranceError, build_receipt, evaluate_receipt, verify_receipt


def _fixture(outcome="PASS"):
    key = Ed25519PrivateKey.generate()
    evidence = hashlib.sha256(b"test evidence").hexdigest()
    receipt = build_receipt(
        key,
        subject={
            "subject_id": "agent:test-01",
            "implementation": "example-agent",
            "version": "1.2.3",
        },
        suite={
            "suite_id": "huffman.core",
            "version": "0.1.0",
            "sha256": hashlib.sha256(b"immutable test suite").hexdigest(),
        },
        run_id=str(uuid.uuid4()),
        challenge_nonce="0123456789abcdef0123456789abcdef",
        checks=[
            {
                "check_id": "AUTH-001",
                "requirement": "A revoked capability must not authorize a new action.",
                "outcome": outcome,
                "evidence": [{"kind": "test-log", "sha256": evidence}],
            }
        ],
        issued_at=1_800_000_000,
        ttl_seconds=300,
    )
    public_key = key.public_key().public_bytes_raw()
    return receipt, public_key


def test_signed_receipt_verifies_with_matching_key_and_challenge():
    receipt, public_key = _fixture()
    assert verify_receipt(
        receipt, public_key, now=1_800_000_100,
        expected_nonce="0123456789abcdef0123456789abcdef",
    )


def test_receipt_rejects_wrong_verifier_key():
    receipt, _ = _fixture()
    wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(AssuranceError, match="does not match"):
        verify_receipt(receipt, wrong_key, now=1_800_000_100)


def test_receipt_rejects_challenge_replay():
    receipt, public_key = _fixture()
    with pytest.raises(AssuranceError, match="nonce"):
        verify_receipt(
            receipt, public_key, now=1_800_000_100,
            expected_nonce="ffffffffffffffffffffffffffffffff",
        )


def test_receipt_rejects_expired_window():
    receipt, public_key = _fixture()
    with pytest.raises(AssuranceError, match="not currently valid"):
        verify_receipt(receipt, public_key, now=1_800_000_301)


def test_receipt_rejects_tampered_check_outcome():
    receipt, public_key = _fixture()
    tampered = copy.deepcopy(receipt)
    tampered["checks"][0]["outcome"] = "FAIL"
    with pytest.raises(AssuranceError, match="signature"):
        verify_receipt(tampered, public_key, now=1_800_000_100)


def test_overall_result_passes_only_when_required_checks_pass():
    receipt, public_key = _fixture()
    assert evaluate_receipt(receipt, public_key, {"AUTH-001"}, now=1_800_000_100) == "PASS"


def test_missing_required_check_is_incomplete():
    receipt, public_key = _fixture()
    assert evaluate_receipt(
        receipt, public_key, {"AUTH-001", "REPLAY-001"}, now=1_800_000_100
    ) == "INCOMPLETE"


def test_failed_check_fails_overall_result():
    receipt, public_key = _fixture(outcome="FAIL")
    assert evaluate_receipt(receipt, public_key, {"AUTH-001"}, now=1_800_000_100) == "FAIL"


def test_not_run_check_is_incomplete():
    receipt, public_key = _fixture(outcome="NOT_RUN")
    assert evaluate_receipt(
        receipt, public_key, {"AUTH-001"}, now=1_800_000_100
    ) == "INCOMPLETE"


def test_receipt_rejects_floating_point_values():
    receipt, public_key = _fixture()
    tampered = copy.deepcopy(receipt)
    tampered["checks"][0]["detail"] = 1.25
    with pytest.raises(AssuranceError, match="floating-point"):
        verify_receipt(tampered, public_key, now=1_800_000_100)


def test_receipt_rejects_pass_without_evidence():
    receipt, public_key = _fixture()
    tampered = copy.deepcopy(receipt)
    tampered["checks"][0]["evidence"] = []
    with pytest.raises(AssuranceError, match="evidence"):
        verify_receipt(tampered, public_key, now=1_800_000_100)


def test_receipt_ttl_is_bounded():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(AssuranceError, match="ttl_seconds"):
        build_receipt(
            key,
            subject={"subject_id": "agent:x", "implementation": "x", "version": "1"},
            suite={
                "suite_id": "suite", "version": "1",
                "sha256": hashlib.sha256(b"x").hexdigest(),
            },
            run_id=str(uuid.uuid4()),
            challenge_nonce="0123456789abcdef",
            checks=[{
                "check_id": "CHECK-01", "requirement": "A check", "outcome": "PASS",
                "evidence": [{"kind": "log", "sha256": hashlib.sha256(b"y").hexdigest()}],
            }],
            ttl_seconds=86_401,
        )
