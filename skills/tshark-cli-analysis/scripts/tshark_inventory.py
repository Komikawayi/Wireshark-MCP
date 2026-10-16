#!/usr/bin/env python3
"""Discover installed TShark CLI capabilities and compare with the reviewed catalog."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[1] / "references" / "capability-catalog.json"


def parse_options(text: str) -> list[str]:
    # Only option declaration lines, not examples, paths or prose mentioning flags.
    return sorted(
        {
            flag
            for line in text.splitlines()
            if re.match(r"\s+-[A-Za-z0-9-]", line)
            for flag in re.findall(
                r"(?<!\w)--[a-z][a-z0-9-]*|(?<![-\w])-[A-Za-z0-9](?![A-Za-z0-9])",
                line.lstrip().split("  ", 1)[0],
            )
        }
    )


def parse_reports(text: str) -> list[str]:
    return sorted(set(re.findall(r"^\s+-G ([A-Za-z][A-Za-z0-9_-]*)", text, re.MULTILINE)))


def parse_statistics(text: str) -> list[str]:
    return sorted({line.strip() for line in text.splitlines() if re.fullmatch(r"\s+\S+\s*", line)})


def coverage(inventory: dict, catalog: dict) -> dict:
    return {kind: sorted(set(inventory[kind]) - set(catalog[kind])) for kind in ("options", "reports", "statistics")}


def collect(executable: str, timeout: float = 15) -> dict:
    results = {}
    for name, args in (
        ("version", ["--version"]),
        ("help", ["--help"]),
        ("reports", ["-G", "help"]),
        ("statistics", ["-z", "help"]),
    ):
        p = subprocess.run(
            [executable, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False
        )
        if len(p.stdout) + len(p.stderr) > 2 * 1024 * 1024:
            raise ValueError(f"unexpectedly large {name} discovery output")
        if p.returncode < 0:
            raise ValueError(f"{name} discovery terminated by signal; inventory is incomplete")
        results[name] = {
            "argv": [executable, *args],
            "returncode": p.returncode,
            "stdout": p.stdout.decode("utf-8", errors="replace"),
            "stderr": p.stderr.decode("utf-8", errors="replace"),
        }
    help_text = results["help"]["stdout"] + results["help"]["stderr"]
    report_text = results["reports"]["stdout"] + results["reports"]["stderr"]
    stats_text = results["statistics"]["stdout"] + results["statistics"]["stderr"]
    if results["version"]["returncode"] or results["help"]["returncode"]:
        raise ValueError("version/help discovery failed; inspect engine/configuration")
    inventory = {
        "schema_version": 1,
        "options": parse_options(help_text),
        "reports": parse_reports(report_text),
        "statistics": parse_statistics(stats_text),
        "discovery": results,
    }
    if not all(inventory[k] for k in ("options", "reports", "statistics")):
        raise ValueError("empty/incompatible discovery; not evidence of capability coverage")
    return inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--output", type=Path, required=True, help="new JSON artifact, not a model-context dump")
    parser.add_argument("--check", action="store_true", help="fail if an installed capability is undocumented")
    args = parser.parse_args(argv)
    try:
        inventory = collect(args.tshark)
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        gaps = coverage(inventory, catalog)
        inventory["documentation_gaps"] = gaps
        inventory["baseline_unavailable"] = {kind: sorted(set(catalog[kind]) - set(inventory[kind])) for kind in gaps}
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(inventory, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "counts": {k: len(inventory[k]) for k in gaps},
                "documentation_gaps": gaps,
                "output": str(args.output.resolve()),
            }
        )
    )
    return 1 if args.check and any(gaps.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
