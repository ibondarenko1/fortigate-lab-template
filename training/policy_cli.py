#!/usr/bin/env python3
"""JSON CLI for the offline FortiGate policy exercises.

The command reads only local files. It never connects to a FortiGate and never
interprets credentials. Set ``--scenario-dir`` to a directory containing
``<scenario-id>/scenario.json``, ``starter.conf`` and ``reference.conf`` to
exercise a local scenario collection.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import sys


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        help="scenario collection root, default training/scenarios",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list available scenario bundles")

    grade = subparsers.add_parser("grade", help="grade one local FortiOS config")
    grade.add_argument("scenario_id")
    grade.add_argument("config", type=Path)

    compare = subparsers.add_parser("compare", help="compare two local configs")
    compare.add_argument("scenario_id")
    compare.add_argument("before", type=Path)
    compare.add_argument("after", type=Path)
    compare.add_argument(
        "--fail-on-change",
        action="store_true",
        help="exit 1 when any flow or effective scope changes",
    )
    return parser


def _write(payload: object) -> None:
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read configuration {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.scenario_dir is not None:
        os.environ["FORTIGATE_SCENARIO_DIR"] = str(args.scenario_dir.resolve())

    # Import after setting the optional collection root so external bundles are
    # discovered by the same engine used by the worksheet.
    try:
        policy_lab = importlib.import_module("policy_lab")
        if args.scenario_dir is not None:
            policy_lab = importlib.reload(policy_lab)
        catalog = policy_lab.catalog
        compare = policy_lab.compare
        grade = policy_lab.grade
    except (ImportError, OSError, ValueError) as exc:
        _write({"error": str(exc)})
        return 2

    if args.command == "list":
        _write({
            "schema_version": 1,
            "scenarios": [
                {
                    "id": item["id"],
                    "title": item["title"],
                    "starter": f"{item['id']}/starter.conf",
                    "reference": f"{item['id']}/reference.conf",
                    "boundary_flows": len(item.get("boundary_flows", [])),
                }
                for item in catalog()
            ],
        })
        return 0

    try:
        if args.command == "grade":
            result = grade(args.scenario_id, _read(args.config))
            _write(result)
            if result.get("errors"):
                return 2
            return 0 if result.get("pass") else 1
        result = compare(args.scenario_id, _read(args.before), _read(args.after))
    except ValueError as exc:
        _write({"schema_version": 1, "errors": [{"side": "request", "code": "invalid_input", "line": 0, "message": str(exc)}]})
        return 2
    _write(result)
    if result.get("errors"):
        return 2
    if args.fail_on_change and (result["summary"]["changed"] or result["scope_changes"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
