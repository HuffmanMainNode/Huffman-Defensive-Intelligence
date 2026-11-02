import argparse
import json
import sys
from importlib.resources import files

from hdi import __version__
from hdi.model import EventValidationError, HDIEvent


def main():
    parser = argparse.ArgumentParser(
        prog="hdi",
        description="Local-first event validation and integration guidance.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    guide = sub.add_parser("guide", help="show the human and agent onboarding entry points")
    guide.set_defaults(handler="guide")

    capabilities = sub.add_parser(
        "capabilities", help="print the machine-readable adapter capability catalogue"
    )
    capabilities.set_defaults(handler="capabilities")

    validate = sub.add_parser("validate", help="validate an HDI event JSON file")
    validate.add_argument("path")
    validate.set_defaults(handler="validate")

    args = parser.parse_args()
    try:
        if args.handler == "guide":
            print(
                "Huffman Defensive Intelligence (HDI)\n"
                f"Version: {__version__}\n\n"
                "Human onboarding: docs/USER-ONBOARDING.md\n"
                "Agent onboarding: docs/AGENT-ONBOARDING.md\n"
                "Repository agent contract: AGENTS.md\n"
                "Architecture: docs/ARCHITECTURE.md\n"
                "Integration boundaries: docs/INTEGRATION_CONTRACT.md\n\n"
                "First safe checks:\n"
                "  hdi --version\n"
                "  hdi capabilities\n"
                "  hdi validate examples/sample-event.json\n\n"
                "HDI is a local library and CLI, not an MCP server or hosted service.\n"
                "Read the relevant upstream guide before connecting an adapter."
            )
            return 0
        if args.handler == "capabilities":
            resource = files("hdi").joinpath("agent-capabilities.json")
            catalogue = json.loads(resource.read_text(encoding="utf-8"))
            print(json.dumps(catalogue, indent=2, sort_keys=True))
            return 0

        with open(args.path, encoding="utf-8") as stream:
            event = HDIEvent.from_dict(json.load(stream))
        print(
            json.dumps(
                {
                    "valid": True,
                    "event_id": event.event_id,
                    "sha256": event.canonical_sha256(),
                },
                indent=2,
            )
        )
        return 0
    except (OSError, json.JSONDecodeError, EventValidationError, ValueError) as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
