#!/usr/bin/env python3
"""Apply one bounded offline TShark query to many captures and summarize per-input coverage."""

from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_tshark  # noqa: E402


def collect(inputs: list[Path], directory: Path | None, pattern: str, recursive: bool) -> list[Path]:
    found = [path.resolve(strict=True) for path in inputs]
    if directory is not None:
        matches = directory.rglob(pattern) if recursive else directory.glob(pattern)
        found += [path.resolve() for path in matches if path.is_file()]
    return sorted(set(found), key=str)


def run_one(index: int, capture: Path, root: Path, *, tshark: str, limits: dict) -> dict:
    # Sequence numbers keep run directories unique when captures share a basename.
    run_dir = root / "runs" / f"{index:04d}-{re.sub(r'[^A-Za-z0-9._-]', '_', capture.name)[:60]}"
    entry: dict = {"index": index, "input": str(capture), "run_dir": str(run_dir)}
    try:
        identity = run_tshark.prepare(capture, run_dir, **limits)
    except (OSError, ValueError) as exc:
        return {**entry, "status": "error", "coverage": "partial", "returncode": None, "error": str(exc)}
    record = run_tshark.execute(identity, run_dir, tshark=tshark, **limits)
    return {
        **entry,
        "sha256": identity["sha256"],
        "size": identity["size"],
        "status": record["execution"]["status"],
        "coverage": record["coverage"]["status"],
        "returncode": record["execution"]["returncode"],
        "input_changed": record["input_changed"],
        "record": str(run_dir / "execution.json"),
        "stdout": str(run_dir / "stdout.bin"),
        "stderr": str(run_dir / "stderr.bin"),
    }


def cell(value: object) -> str:
    return "" if value is None else str(value).replace("\t", "\\t").replace("\n", "\\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", default=[], help="capture file; repeatable")
    parser.add_argument("--input-dir", type=Path, help="directory of captures selected by --pattern")
    parser.add_argument("--pattern", default="*.pcap*")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory, never overwritten")
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--timeout", type=float, default=30, help="seconds per input")
    parser.add_argument("--max-output-bytes", type=int, default=1048576, help="stdout+stderr cap per input")
    parser.add_argument("--jobs", type=int, default=1, help="concurrent TShark processes")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    tail = args.args[1:] if args.args[:1] == ["--"] else args.args
    limits = {"timeout": args.timeout, "budget": args.max_output_bytes, "tail": tail}
    try:
        run_tshark.validate_args(tail)
        if args.jobs < 1:
            raise ValueError("--jobs must be at least 1")
        if args.input_dir is not None and not args.input_dir.is_dir():
            raise ValueError(f"{args.input_dir}: not a directory")
        captures = collect(args.input, args.input_dir, args.pattern, args.recursive)
        if not captures:
            raise ValueError("no input captures selected")
        args.output_dir.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    root = args.output_dir.resolve()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        runs = list(
            pool.map(
                lambda item: run_one(item[0], item[1], root, tshark=args.tshark, limits=limits),
                enumerate(captures, start=1),
            )
        )
    counts = {
        "inputs": len(runs),
        "complete": sum(run["coverage"] == "complete" for run in runs),
        "partial": sum(run["coverage"] != "complete" and run["status"] != "error" for run in runs),
        "error": sum(run["status"] == "error" for run in runs),
    }
    batch = {
        "schema_version": 1,
        "tshark": args.tshark,
        "arguments": tail,
        "limits": {"timeout": args.timeout, "max_output_bytes": args.max_output_bytes, "jobs": args.jobs},
        "counts": counts,
        "runs": runs,
    }
    (root / "batch.json").write_text(json.dumps(batch, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    columns = ("index", "coverage", "status", "returncode", "sha256", "input")
    lines = ["\t".join(columns)] + ["\t".join(cell(run.get(name)) for name in columns) for run in runs]
    (root / "summary.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({**counts, "batch": str(root / "batch.json")}))
    return 0 if counts["complete"] == counts["inputs"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
