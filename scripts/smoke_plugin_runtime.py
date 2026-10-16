#!/usr/bin/env python3
"""Cold-start each bundled launcher in disposable unpacked projects over real stdio."""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import tempfile
import traceback
from pathlib import Path
from zipfile import ZipFile

from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client


def unpack(archive: Path, destination: Path) -> None:
    with ZipFile(archive) as bundle:
        for name in bundle.namelist():
            if not (destination / name).resolve().is_relative_to(destination.resolve()):
                raise ValueError(f"archive path escapes disposable project: {name}")
        bundle.extractall(destination)


async def smoke(archive: Path, client_name: str, *, timeout: float) -> dict:
    if not shutil.which("uv") or not shutil.which("tshark"):
        raise ValueError("Install uv and TShark before running the plugin runtime smoke")
    with tempfile.TemporaryDirectory(prefix=f"wireshark-plugin-{client_name}-") as tmp:
        base = Path(tmp)
        root, workspace = base / "plugin with spaces", base / "user workspace"
        root.mkdir()
        workspace.mkdir()
        unpack(archive, root)
        if (root / ".venv").exists():
            raise ValueError("plugin archive includes a pre-existing environment; cold start not established")
        lock_hash = hashlib.sha256((root / "uv.lock").read_bytes()).hexdigest()
        if client_name == "codex":
            manifest = json.loads((root / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
            config = json.loads((root / manifest["mcpServers"]).read_text(encoding="utf-8"))["mcpServers"][
                "wireshark-mcp"
            ]
            cwd = root / config["cwd"]
        else:
            manifest = json.loads((root / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
            config = manifest["mcpServers"]["wireshark-mcp"]
            cwd = workspace
        args = [arg.replace("${CLAUDE_PLUGIN_ROOT}", str(root)) for arg in config["args"]]
        frame = bytes.fromhex("ffffffffffff00112233445508060001080006040001001122334455c0000201000000000000c0000202")
        capture = workspace / "one-arp.pcap"
        capture.write_bytes(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, len(frame), len(frame))
            + frame
        )
        capture_hash = hashlib.sha256(capture.read_bytes()).hexdigest()
        env = os.environ.copy()
        for key in ("VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME", "UV_PROJECT_ENVIRONMENT"):
            env.pop(key, None)
        env["WIRESHARK_MCP_ALLOWED_DIRS"] = str(workspace)
        params = StdioServerParameters(command=config["command"], args=args, cwd=str(cwd), env=env)

        async def investigate(errlog):
            async with Client(stdio_client(params, errlog=errlog), read_timeout_seconds=timeout) as client:
                tools = await client.list_tools()
                result = await client.call_tool(
                    "wireshark_extract_fields",
                    {
                        "pcap_file": str(capture),
                        "fields": "frame.number",
                        "display_filter": "frame.number == 1",
                        "limit": 5,
                    },
                )
                raw = result.model_dump(mode="json")
                envelope = json.loads(next(item.text for item in result.content if hasattr(item, "text")))
                rows = list(csv.DictReader(io.StringIO(envelope.get("data", "")), delimiter="\t"))
                if result.is_error or not envelope.get("success") or rows != [{"frame.number": "1"}]:
                    raise ValueError(f"plugin packet query failed: {raw}")
                return {
                    "protocol_version": client.protocol_version,
                    "server": client.server_info.model_dump(mode="json"),
                    "tool_count": len(tools.tools),
                    "raw_tool_result": raw,
                }

        with (base / "stderr.log").open("w+") as errlog:
            try:
                result = await asyncio.wait_for(investigate(errlog), timeout=timeout)
            except BaseException as exc:
                errlog.flush()
                errlog.seek(0)
                raise RuntimeError(f"{traceback.format_exc()}\nSERVER STDERR:\n{errlog.read()}") from exc
            errlog.seek(0)
            stderr = errlog.read()
        python = root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        installed = subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import importlib.util,json; print(json.dumps({'pytest':importlib.util.find_spec('pytest') is not None}))",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=20,
        )
        if json.loads(installed.stdout)["pytest"]:
            raise ValueError("plugin cold start unexpectedly installed dev dependencies")
        if lock_hash != hashlib.sha256((root / "uv.lock").read_bytes()).hexdigest():
            raise ValueError("plugin startup changed uv.lock")
        if capture_hash != hashlib.sha256(capture.read_bytes()).hexdigest():
            raise ValueError("plugin query changed the original capture")
        return {
            "client": client_name,
            "status": "passed",
            "argv": [config["command"], *args],
            "cwd": str(cwd),
            "cold_start": True,
            "dev_dependencies_installed": False,
            "lock_unchanged": True,
            "input_sha256": capture_hash,
            "stderr": stderr,
            **result,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args(argv)
    report = {
        "plugin_zip": str(args.plugin_zip.resolve()),
        "plugin_sha256": hashlib.sha256(args.plugin_zip.read_bytes()).hexdigest(),
        "results": [],
    }
    for name in ("codex", "claude"):
        try:
            result = asyncio.run(smoke(args.plugin_zip, name, timeout=args.timeout))
        except Exception as exc:
            result = {"client": name, "status": "failed", "error": str(exc)}
        report["results"].append(result)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    passed = sum(item["status"] == "passed" for item in report["results"])
    print(f"Plugin runtime smoke: {passed}/2 cold starts passed; report: {args.output.resolve()}")
    return int(passed != 2)


if __name__ == "__main__":
    raise SystemExit(main())
