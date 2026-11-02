import argparse
import json
import sys
from hdi.model import HDIEvent, EventValidationError


def main():
    parser = argparse.ArgumentParser(prog="hdi")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate an HDI event JSON file")
    validate.add_argument("path")
    args = parser.parse_args()
    try:
        with open(args.path, encoding="utf-8") as stream:
            event = HDIEvent.from_dict(json.load(stream))
        print(json.dumps({"valid": True, "event_id": event.event_id,
                          "sha256": event.canonical_sha256()}, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, EventValidationError) as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
