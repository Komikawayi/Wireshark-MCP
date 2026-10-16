#!/usr/bin/env python3
"""Probe installed skill resources from outside the checkout, without registration writes."""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import io
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def probe(*, require_engine: bool = False) -> dict:
    import wireshark_mcp

    package = Path(wireshark_mcp.__file__).resolve().parent
    source = package / "skills"
    manifest = json.loads((source / "manifest.json").read_text())
    names = {item["name"] for item in manifest["skills"]}
    if names != {"wireshark-traffic-analysis", "tshark-cli-analysis"}:
        raise ValueError(f"unexpected packaged skills: {names}")
    checks = []
    executions = []
    for name in sorted(names):
        skill = source / name
        if f"name: {name}\n" not in (skill / "SKILL.md").read_text():
            raise ValueError(f"invalid packaged entrypoint: {name}")
        for document in skill.rglob("*.md"):
            for target in re.findall(r"\]\(([^)]+)\)", document.read_text()):
                if "://" not in target and not (document.parent / target.split("#")[0]).exists():
                    raise ValueError(f"broken packaged reference: {document}: {target}")
        if not (skill / "agents/openai.yaml").is_file():
            raise ValueError(f"missing UI metadata: {name}")
        checks.append(f"packaged:{name}")

    # Disposable discovery copies exercise the installed payload, not repository mirrors.
    # This checks filesystem discovery layout, not a running client's skill selector.
    with tempfile.TemporaryDirectory(prefix="wireshark-skill-install-") as tmp:
        workspace = Path(tmp)
        for client in (".agents", ".claude", ".github"):
            for name in names:
                target = workspace / client / "skills" / name
                shutil.copytree(source / name, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                for resource in (source / name).rglob("*"):
                    if (
                        resource.is_file()
                        and "__pycache__" not in resource.parts
                        and resource.suffix != ".pyc"
                        and resource.read_bytes() != (target / resource.relative_to(source / name)).read_bytes()
                    ):
                        raise ValueError(f"discovery copy changed resource: {resource}")
            checks.append(f"discovery-layout:{client}")

        capture = workspace / "one-arp.pcap"
        frame = bytes.fromhex(
            "ffffffffffff0011223344550806"  # Ethernet broadcast ARP
            "0001080006040001"  # Ethernet/IPv4 ARP request
            "001122334455c0000201000000000000c0000202"
        )
        capture.write_bytes(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, len(frame), len(frame))
            + frame
        )
        original = hashlib.sha256(capture.read_bytes()).hexdigest()
        runner = source / "tshark-cli-analysis/scripts/run_tshark.py"
        missing = workspace / "missing-run"
        result = subprocess.run(
            [
                sys.executable,
                str(runner),
                "--input",
                str(capture),
                "--output-dir",
                str(missing),
                "--tshark",
                str(workspace / "not-installed-tshark"),
                "--",
                "-T",
                "fields",
                "-e",
                "frame.number",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        record = json.loads((missing / "execution.json").read_text())
        executions.append(
            {
                "kind": "missing-engine-simulation",
                "argv": result.args,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "record": record,
            }
        )
        if (
            result.returncode != 1
            or record["execution"]["status"] != "error"
            or record["coverage"]["status"] == "complete"
        ):
            raise ValueError("missing engine was mistaken for a successful scan")
        checks.append("missing-engine:explicit-error-not-zero-matches")
        engine = shutil.which("tshark")
        if engine:
            run = workspace / "success-run"
            result = subprocess.run(
                [
                    sys.executable,
                    str(runner),
                    "--input",
                    str(capture),
                    "--output-dir",
                    str(run),
                    "--tshark",
                    engine,
                    "--",
                    "-T",
                    "fields",
                    "-e",
                    "frame.number",
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode or (run / "stdout.bin").read_bytes().splitlines() != [b"1"]:
                raise ValueError(f"installed CLI smoke failed: {result.stdout} {result.stderr}")
            executions.append(
                {
                    "kind": "native",
                    "argv": result.args,
                    "exit_code": result.returncode,
                    "stdout": (run / "stdout.bin").read_text(),
                    "stderr": (run / "stderr.bin").read_text(),
                    "record": json.loads((run / "execution.json").read_text()),
                }
            )
            checks.append("native:first-offline-query")
            from wireshark_mcp.server import _build_server

            app = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")

            async def call():
                tools = await app.list_tools()
                result = await app.call_tool(
                    "wireshark_extract_fields",
                    {
                        "pcap_file": str(capture),
                        "fields": "frame.number",
                        "display_filter": "frame.number == 1",
                        "limit": 5,
                    },
                )
                return len(tools), result

            count, result = asyncio.run(call())
            text = "\n".join(item.text for item in result.content if hasattr(item, "text"))
            envelope = json.loads(text)
            if getattr(result, "isError", False) or envelope.get("success") is not True:
                raise ValueError(f"installed MCP smoke failed: {text}")
            rows = list(csv.DictReader(io.StringIO(envelope.get("data", "")), delimiter="\t"))
            if rows != [{"frame.number": "1"}]:
                raise ValueError(f"installed MCP smoke did not inspect frame 1: {text}")
            executions.append(
                {
                    "kind": "mcp",
                    "tool": "wireshark_extract_fields",
                    "arguments": {
                        "pcap_file": str(capture),
                        "fields": "frame.number",
                        "display_filter": "frame.number == 1",
                        "limit": 5,
                    },
                    "result": envelope,
                }
            )
            checks.append("mcp:first-offline-query")
        else:
            count = None
            if require_engine:
                raise ValueError("TShark is required for this smoke; install CLI tools and rerun")
        if hashlib.sha256(capture.read_bytes()).hexdigest() != original:
            raise ValueError("installation smoke changed the original capture")
    return {
        "status": "passed",
        "package_path": str(package),
        "checks": checks,
        "executions": executions,
        "engine_smoke": "passed" if engine else "not_run:missing_tshark",
        "tool_count": count,
        "client_ui_selection": "not_tested",
        "global_registration": "not_modified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable, help="Python from the non-editable wheel environment")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-engine", action="store_true")
    parser.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.probe:
        try:
            report = probe(require_engine=args.require_engine)
        except Exception as exc:
            report = {"status": "failed", "error": str(exc)}
        print(json.dumps(report, ensure_ascii=False))
        return int(report["status"] != "passed")
    with tempfile.TemporaryDirectory(prefix="wireshark-installed-cwd-") as tmp:
        command = [args.python, "-I", str(Path(__file__).resolve()), "--probe", "--output", str(args.output.resolve())]
        if args.require_engine:
            command.append("--require-engine")
        result = subprocess.run(command, cwd=tmp, capture_output=True, text=True, timeout=90)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        report = {"status": "failed", "error": "probe returned no JSON", "stdout": result.stdout}
    report.update({"argv": command, "exit_code": result.returncode, "stderr": result.stderr})
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"Installed skill smoke: {report['status']}; report: {args.output.resolve()}")
    return int(result.returncode != 0 or report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
