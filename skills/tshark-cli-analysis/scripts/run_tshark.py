#!/usr/bin/env python3
"""Bound offline TShark console output and retain an auditable execution record."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import threading
import time
from pathlib import Path
from typing import BinaryIO

# Acquisition, extra file outputs and executable extensions need separate supervision.
SEPARATE_WORKFLOW = {
    "-r",
    "-w",
    "-i",
    "-f",
    "-a",
    "-b",
    "-I",
    "-A",
    "-U",
    "-W",
    "-H",
    "-X",
    "-G",
    "-h",
    "-v",
    "-D",
    "-L",
}
LONG_SEPARATE = {
    "--read-file",
    "--interface",
    "--autostop",
    "--ring-buffer",
    "--capture-comment",
    "--export-objects",
    "--export-tls-session-keys",
    "--log-file",
    "--monitor-mode",
    "--help",
    "--version",
    "--list-interfaces",
    "--list-data-link-types",
    "--list-time-stamp-types",
}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def validate_args(args: list[str]) -> None:
    for arg in args:
        if (
            arg.split("=", 1)[0] in LONG_SEPARATE
            or arg in SEPARATE_WORKFLOW
            or any(arg.startswith(flag) and len(arg) > 2 for flag in SEPARATE_WORKFLOW)
        ):
            raise ValueError(f"{arg}: use the separately supervised capture/export/extension workflow")
    # No positional capture filter: this helper always supplies an explicit offline input.
    if any(
        arg.startswith("--hexdump") and (arg.endswith("=help") or "help" in args[index + 1 : index + 2])
        for index, arg in enumerate(args)
    ):
        raise ValueError("use discovery directly; help output is not a completed offline scan")


def run_bounded(argv: list[str], stdout: BinaryIO, stderr: BinaryIO, *, timeout: float, budget: int) -> dict:
    """Drain both pipes without retaining output in memory; stop/reap on limit."""
    if not math.isfinite(timeout) or timeout <= 0 or budget <= 0:
        raise ValueError("timeout and budget must be finite and positive")
    start = time.monotonic()
    used = 0
    overflow = threading.Event()
    io_failed = threading.Event()
    lock = threading.Lock()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def drain(source: BinaryIO, target: BinaryIO) -> None:
        nonlocal used
        try:
            while block := source.read(65536):
                with lock:
                    available = max(0, budget - used)
                    retained = block[:available]
                    used += len(retained)
                    if len(retained) < len(block):
                        overflow.set()
                if retained:
                    target.write(retained)
        except OSError:
            io_failed.set()
        finally:
            source.close()

    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    status = "completed"
    try:
        while process.poll() is None:
            if overflow.is_set() or io_failed.is_set() or time.monotonic() - start >= timeout:
                status = "output_limit" if overflow.is_set() else "error" if io_failed.is_set() else "timeout"
                process.kill()
                break
            time.sleep(0.01)
    finally:
        process.wait()
        for reader in readers:
            reader.join()
    if overflow.is_set():
        status = "output_limit"
    elif io_failed.is_set() or (status == "completed" and process.returncode != 0):
        status = "error"
    return {
        "status": status,
        "returncode": process.returncode,
        "output_bytes": used,
        "elapsed_ms": round((time.monotonic() - start) * 1000, 2),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory, never overwritten")
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-output-bytes", type=int, default=1048576)
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    tail = args.args[1:] if args.args[:1] == ["--"] else args.args
    try:
        validate_args(tail)
        if not math.isfinite(args.timeout) or args.timeout <= 0 or args.max_output_bytes <= 0:
            raise ValueError("timeout and output budget must be finite and positive")
        capture = args.input.resolve(strict=True)
        if not capture.is_file():
            raise ValueError("input must be a regular capture file")
        identity = {"path": str(capture), "sha256": digest(capture), "size": capture.stat().st_size}
        args.output_dir.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    command = [args.tshark, "-n", "-r", str(capture), *tail]
    with (args.output_dir / "stdout.bin").open("xb") as out, (args.output_dir / "stderr.bin").open("xb") as err:
        try:
            execution = run_bounded(command, out, err, timeout=args.timeout, budget=args.max_output_bytes)
        except OSError as exc:
            execution = {"status": "error", "returncode": None, "error": str(exc)}
    try:
        changed = digest(capture) != identity["sha256"]
    except OSError:
        changed = True
    capped_input = any(a == "-c" or a.startswith("-c") and len(a) > 2 for a in tail)
    complete = execution["status"] == "completed" and not changed and not capped_input
    record = {
        "schema_version": 1,
        "input": identity,
        "input_changed": changed,
        "argv": command,
        "execution": execution,
        "coverage": {"status": "complete" if complete else "partial"},
        "artifacts": {
            name: {"path": str((args.output_dir / name).resolve()), "sha256": digest(args.output_dir / name)}
            for name in ("stdout.bin", "stderr.bin")
        },
    }
    (args.output_dir / "execution.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": execution["status"],
                "coverage": record["coverage"]["status"],
                "record": str((args.output_dir / "execution.json").resolve()),
            }
        )
    )
    return {"completed": 0, "timeout": 124, "output_limit": 125}.get(execution["status"], 1) if not changed else 1


if __name__ == "__main__":
    raise SystemExit(main())
