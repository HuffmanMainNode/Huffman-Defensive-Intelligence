import json
import sys

from hdi import __version__
from hdi.cli import main


def test_guide_shows_human_and_agent_entry_points(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["hdi", "guide"])

    assert main() == 0
    output = capsys.readouterr().out
    assert "docs/USER-ONBOARDING.md" in output
    assert "docs/AGENT-ONBOARDING.md" in output
    assert "not an MCP server" in output


def test_capabilities_is_valid_packaged_json(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["hdi", "capabilities"])

    assert main() == 0
    catalogue = json.loads(capsys.readouterr().out)
    assert catalogue["catalogue_version"] == "1.0"
    assert catalogue["package_version"] == __version__
    assert catalogue["mcp_server"] is False
    assert {backend["name"] for backend in catalogue["journal_backends"]} == {
        "jsonl_reference", "sqlite_outbox"
    }
    assert catalogue["journal_backends"][1]["concurrent_local_writers"] is True
    assert catalogue["journal_backends"][1]["delivery_semantics"] == "at_least_once"
    assert (
        "per_claim_lease_fencing_token_required_for_ack_and_release"
        in catalogue["journal_backends"][1]["features"]
    )
    assert catalogue["integration_demos"][0]["fixtures"] == "synthetic"
    assert {adapter["name"] for adapter in catalogue["adapters"]} == {
        "oix",
        "open_swarm",
        "halloween_osint",
        "cyber_observatory",
    }


def test_validate_command_still_works(monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv", ["hdi", "validate", "examples/sample-event.json"]
    )

    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert len(result["sha256"]) == 64
