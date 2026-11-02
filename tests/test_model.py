import json
from pathlib import Path
import pytest
from hdi.model import HDIEvent, EventValidationError


def sample():
    return json.loads(Path("examples/sample-event.json").read_text())


def test_sample_validates():
    event = HDIEvent.from_dict(sample())
    assert len(event.canonical_sha256()) == 64


def test_rejects_naive_timestamp():
    raw = sample()
    raw["occurred_at"] = "2026-11-02T12:00:00"
    with pytest.raises(EventValidationError):
        HDIEvent.from_dict(raw)


def test_rejects_unknown_fields():
    raw = sample()
    raw["unexpected"] = "data"
    with pytest.raises(EventValidationError):
        HDIEvent.from_dict(raw)


def test_rejects_bad_evidence_hash():
    raw = sample()
    raw["evidence"][0]["sha256"] = "bad"
    with pytest.raises(EventValidationError):
        HDIEvent.from_dict(raw)


def test_rejects_oversized_payload():
    raw = sample()
    raw["payload"] = {"blob": "x" * 260000}
    with pytest.raises(EventValidationError):
        HDIEvent.from_dict(raw)


def test_rejects_floating_point_payload_values():
    raw = sample()
    raw["payload"] = {"confidence": 0.5}
    with pytest.raises(EventValidationError):
        HDIEvent.from_dict(raw)


def test_rejects_non_string_payload_keys():
    raw = sample()
    raw["payload"] = {1: "invalid"}
    with pytest.raises(EventValidationError):
        HDIEvent.from_dict(raw)
