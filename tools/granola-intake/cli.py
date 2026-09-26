"""Granola detector CLI. Scheduler commands print definitions only."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import plistlib
import sys

from adapters import GranolaAPI, queue_wake
from detector import (DetectorError, iso, locked, private_file, reconcile,
                      run_once, status, validate_config)


def load_config(path):
    try:
        path = Path(path)
        if not path.is_absolute():
            raise ValueError()
        private_file(path)
        if path.stat().st_size > 8192:
            raise ValueError()
        config = json.loads(path.read_text())
        validate_config(config)
        return config
    except (OSError, ValueError, TypeError):
        raise DetectorError("invalid configuration file") from None


def scheduler_definition(config_path):
    return plistlib.dumps({
        "Label": "org.example.granola-intake-detector",
        "ProgramArguments": ["/usr/bin/python3", str(Path(__file__).resolve()),
                             "--config", str(config_path), "run-once"],
        "StartInterval": 60, "RunAtLoad": True, "ProcessType": "Background",
        "EnvironmentVariables": {"PYTHONDONTWRITEBYTECODE": "1"},
        "Umask": 0o077, "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
    }, sort_keys=True).decode()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Absolute private JSON config path; never a token.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run-once", help="LIVE bounded API discovery and eligible wake; requires configured credentials.")
    inspect = commands.add_parser("status", help="Inspect metadata; no credential file, network or queue call.")
    inspect.add_argument("--operation", help="Inspect one exact operation ID.")
    inspect.add_argument("--offset", type=int, default=0, help="Bounded 100-operation page offset; actionable states first.")
    commands.add_parser("scheduler-definition", help="Print a plist only; does not install or load it.")
    reset = commands.add_parser("reset-discovery", help="Restart full discovery from the original cutoff; preserve operations.")
    reset.add_argument("--confirm-reset", action="store_true")
    recover = commands.add_parser("reconcile", help="Apply explicitly confirmed operator-attested native evidence.")
    recover.add_argument("--operation", required=True)
    recover.add_argument("--evidence", required=True, help="Private JSON evidence file, not a source transcript.")
    recover.add_argument("--confirm-native-evidence", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "scheduler-definition":
            print(scheduler_definition(args.config), end="")
            return 0
        if args.command == "run-once":
            result = run_once(config, GranolaAPI(config), lambda payload: queue_wake(config, payload),
                              iso(datetime.now(timezone.utc)))
        elif args.command == "status":
            result = status(config, operation=args.operation, offset=args.offset)
        elif args.command == "reset-discovery":
            if not args.confirm_reset:
                raise DetectorError("discovery reset confirmation required")
            with locked(config) as db:
                if db is None:
                    raise DetectorError("worker busy")
                with db:
                    db.execute("DELETE FROM metadata WHERE key='cycle'")
                    db.execute("DELETE FROM cursors")
            result = {"outcome": "discovery-reset", "operations_preserved": True}
        else:
            reconcile(config, args.operation, args.evidence, args.confirm_native_evidence)
            result = {"outcome": "operator-attested-reconciliation"}
        print(json.dumps(result, sort_keys=True))
        return 0
    except DetectorError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"error": "detector operation failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
