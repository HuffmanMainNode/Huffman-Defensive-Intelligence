"""Portable, signed assurance receipts for independently verifiable test runs."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
import unicodedata
import uuid
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA = "huffman-assurance-receipt/0.1"
MAX_RECEIPT_BYTES = 1_000_000
MAX_TTL_SECONDS = 86_400
ALLOWED_OUTCOMES = {"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN"}
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
CHECK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")


class AssuranceError(ValueError):
    """A receipt is malformed, invalid, expired, or not bound to the challenge."""


def _canonical_value(value: Any, depth: int = 0) -> Any:
    if depth > 32:
        raise AssuranceError("receipt nesting exceeds 32 levels")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise AssuranceError("floating-point values are prohibited")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        if len(value) > 10_000:
            raise AssuranceError("receipt array exceeds 10000 items")
        return [_canonical_value(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 10_000:
            raise AssuranceError("receipt object exceeds 10000 members")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AssuranceError("receipt object keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise AssuranceError("duplicate object key after Unicode normalization")
            normalized[normalized_key] = _canonical_value(item, depth + 1)
        return normalized
    raise AssuranceError("receipt contains a value outside the deterministic JSON model")


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for the restricted receipt data model."""
    normalized = _canonical_value(value)
    try:
        encoded = json.dumps(
            normalized, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AssuranceError("receipt is not canonical-JSON encodable") from exc
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise AssuranceError("receipt exceeds the 1 MB limit")
    return encoded


def _fingerprint(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise AssuranceError("Ed25519 public key must be exactly 32 bytes")
    return "ed25519:" + hashlib.sha256(public_key).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise AssuranceError("signature must be a non-empty base64url string")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _validate_body(body: Mapping[str, Any]) -> None:
    required = {
        "schema", "receipt_id", "issued_at", "expires_at", "verifier",
        "subject", "suite", "run", "checks",
    }
    if not isinstance(body, Mapping) or set(body) != required:
        raise AssuranceError("receipt body has missing or unknown fields")
    if body["schema"] != SCHEMA:
        raise AssuranceError("unsupported receipt schema")
    if not _is_uuid(body["receipt_id"]):
        raise AssuranceError("receipt_id must be a canonical UUID")
    issued_at, expires_at = body["issued_at"], body["expires_at"]
    if (
        not isinstance(issued_at, int) or isinstance(issued_at, bool)
        or not isinstance(expires_at, int) or isinstance(expires_at, bool)
        or issued_at < 0 or expires_at <= issued_at
        or expires_at - issued_at > MAX_TTL_SECONDS
    ):
        raise AssuranceError("receipt validity window is invalid")

    verifier = body["verifier"]
    if (
        not isinstance(verifier, dict) or set(verifier) != {"key_id"}
        or not isinstance(verifier["key_id"], str)
        or not re.fullmatch(r"ed25519:[a-f0-9]{64}", verifier["key_id"])
    ):
        raise AssuranceError("verifier key identity is malformed")

    subject = body["subject"]
    if (
        not isinstance(subject, dict)
        or set(subject) != {"subject_id", "implementation", "version"}
        or not all(isinstance(subject[key], str) and subject[key] for key in subject)
        or len(subject["subject_id"]) > 256
        or len(subject["implementation"]) > 128
        or len(subject["version"]) > 128
    ):
        raise AssuranceError("subject descriptor is malformed")

    suite = body["suite"]
    if (
        not isinstance(suite, dict) or set(suite) != {"suite_id", "version", "sha256"}
        or not all(isinstance(suite[key], str) and suite[key] for key in ("suite_id", "version"))
        or not isinstance(suite["sha256"], str)
        or not SHA256_RE.fullmatch(suite["sha256"])
    ):
        raise AssuranceError("test suite descriptor is malformed")

    run = body["run"]
    if (
        not isinstance(run, dict) or set(run) != {"run_id", "challenge_nonce"}
        or not _is_uuid(run["run_id"])
        or not isinstance(run["challenge_nonce"], str)
        or not 16 <= len(run["challenge_nonce"]) <= 256
    ):
        raise AssuranceError("run descriptor is malformed")

    checks = body["checks"]
    if not isinstance(checks, list) or not checks:
        raise AssuranceError("checks must be a non-empty array")
    seen: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            raise AssuranceError("each check must be an object")
        if not {"check_id", "requirement", "outcome", "evidence"} <= set(check):
            raise AssuranceError("check is missing required fields")
        if set(check) - {"check_id", "requirement", "outcome", "evidence", "detail"}:
            raise AssuranceError("check contains unknown fields")
        check_id = check["check_id"]
        if not isinstance(check_id, str) or not CHECK_ID_RE.fullmatch(check_id):
            raise AssuranceError("check_id is malformed")
        if check_id in seen:
            raise AssuranceError("duplicate check_id")
        seen.add(check_id)
        if not isinstance(check["requirement"], str) or not check["requirement"]:
            raise AssuranceError("check requirement must be a non-empty string")
        if len(check["requirement"]) > 512:
            raise AssuranceError("check requirement is too long")
        if not isinstance(check["outcome"], str) or check["outcome"] not in ALLOWED_OUTCOMES:
            raise AssuranceError("unsupported check outcome")
        if "detail" in check and (
            not isinstance(check["detail"], str) or len(check["detail"]) > 1000
        ):
            raise AssuranceError("check detail must be a string of at most 1000 characters")
        evidence = check["evidence"]
        if not isinstance(evidence, list) or len(evidence) > 100:
            raise AssuranceError("check evidence must be an array of at most 100 items")
        if check["outcome"] in {"PASS", "FAIL"} and not evidence:
            raise AssuranceError("PASS and FAIL checks require at least one evidence digest")
        for item in evidence:
            if (
                not isinstance(item, dict) or set(item) != {"kind", "sha256"}
                or not isinstance(item["kind"], str) or not 1 <= len(item["kind"]) <= 64
                or not isinstance(item["sha256"], str)
                or not SHA256_RE.fullmatch(item["sha256"])
            ):
                raise AssuranceError("evidence reference is malformed")


def build_receipt(
    private_key: Ed25519PrivateKey,
    *,
    subject: dict[str, str],
    suite: dict[str, str],
    run_id: str,
    challenge_nonce: str,
    checks: list[dict[str, Any]],
    issued_at: int | None = None,
    ttl_seconds: int = 3600,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    """Build and sign a portable receipt using an Ed25519 verifier key."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise AssuranceError("private_key must be an Ed25519PrivateKey")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
        raise AssuranceError("ttl_seconds must be an integer")
    if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise AssuranceError("ttl_seconds must be between 1 and 86400")
    current = int(time.time()) if issued_at is None else issued_at
    if not isinstance(current, int) or isinstance(current, bool) or current < 0:
        raise AssuranceError("issued_at must be a non-negative integer")
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    body = {
        "schema": SCHEMA,
        "receipt_id": receipt_id or str(uuid.uuid4()),
        "issued_at": current,
        "expires_at": current + ttl_seconds,
        "verifier": {"key_id": _fingerprint(public_raw)},
        "subject": subject,
        "suite": suite,
        "run": {"run_id": run_id, "challenge_nonce": challenge_nonce},
        "checks": checks,
    }
    _validate_body(body)
    signature = private_key.sign(canonical_json(body))
    return {**body, "signature": _b64(signature)}


def verify_receipt(
    receipt: dict[str, Any],
    public_key: bytes,
    *,
    now: int | None = None,
    expected_nonce: str | None = None,
) -> bool:
    """Verify structure, verifier identity, signature, validity, and optional challenge.

    Supplying expected_nonce is recommended for online challenge-response verification.
    Without it, the signature authenticates the receipt but does not prevent replay.
    """
    if not isinstance(receipt, dict) or "signature" not in receipt:
        raise AssuranceError("receipt must contain a signature")
    body = {key: value for key, value in receipt.items() if key != "signature"}
    _validate_body(body)
    if body["verifier"]["key_id"] != _fingerprint(public_key):
        raise AssuranceError("receipt verifier does not match supplied public key")
    current = int(time.time()) if now is None else now
    if not isinstance(current, int) or isinstance(current, bool):
        raise AssuranceError("verification time must be an integer")
    if body["issued_at"] > current + 60 or body["expires_at"] < current:
        raise AssuranceError("receipt is not currently valid")
    if expected_nonce is not None and body["run"]["challenge_nonce"] != expected_nonce:
        raise AssuranceError("receipt challenge nonce does not match")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _unb64(receipt["signature"]), canonical_json(body)
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise AssuranceError("receipt signature verification failed") from exc
    return True


def evaluate_receipt(
    receipt: dict[str, Any],
    public_key: bytes,
    required_check_ids: set[str] | None = None,
    *,
    now: int | None = None,
    expected_nonce: str | None = None,
) -> str:
    """Verify the receipt, then return PASS, FAIL, or INCOMPLETE.

    This is a test-result classification, not a certification decision.
    """
    verify_receipt(
        receipt, public_key, now=now, expected_nonce=expected_nonce
    )
    body = {key: value for key, value in receipt.items() if key != "signature"}
    checks = {item["check_id"]: item["outcome"] for item in body["checks"]}
    if any(outcome == "FAIL" for outcome in checks.values()):
        return "FAIL"
    if any(outcome != "PASS" for outcome in checks.values()):
        return "INCOMPLETE"
    required = required_check_ids or set()
    if not required <= set(checks):
        return "INCOMPLETE"
    return "PASS"
