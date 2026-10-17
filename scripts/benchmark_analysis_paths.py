#!/usr/bin/env python3
"""Benchmark equivalent Wireshark MCP and direct tshark analysis primitives."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import platform
import random
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on Windows
    resource = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "pcaps"

SCENARIOS: dict[str, dict[str, Any]] = {
    "packet_count": {
        "capture": "plaintext_credentials.pcap",
        "mcp": {},
        "cli_fields": ["frame.number"],
        "filter": "",
        "expected": {"packet_count": 3},
    },
    "primary_source": {
        "capture": "plaintext_credentials.pcap",
        "mcp": {"group_by": "ip.src", "top_k": 1},
        "cli_fields": ["frame.number", "ip.src"],
        "filter": "",
        "expected": {"primary_source": "192.168.1.10", "primary_source_packets": 3},
    },
    "dns_query_count": {
        "capture": "dns_tunnel_candidate.pcap",
        "mcp": {"display_filter": "dns.flags.response == 0"},
        "cli_fields": ["frame.number"],
        "filter": "dns.flags.response == 0",
        "expected": {"dns_query_count": 27},
    },
    "literal_user_agent": {
        "capture": "multivalue_fields.pcap",
        "mcp": {"distinct": "http.user_agent"},
        "cli_fields": ["frame.number", "http.user_agent"],
        "filter": "http.user_agent",
        "expected": {"distinct_http_user_agents": 1},
    },
    "numeric_frame_bytes": {
        "capture": "plaintext_credentials.pcap",
        "mcp": {"sum_fields": "frame.len"},
        "cli_fields": ["frame.number", "frame.len"],
        "filter": "",
        "expected": {"frame_bytes": 304.0},
    },
}


# Synthetic scaling tiers. Every fact is computed while the capture is written,
# so large-capture runs stay accuracy-gated without a slow reference parse.
SCALING_TIERS_MB = (10, 100, 1000)
SYNTHETIC_SEED = 3101
DNS_SERVER = "10.255.0.53"
HEAVY_SOURCE = "10.0.0.7"
FILLER_PORT = 39999
USER_AGENTS = ("curl/8.4.0", "Mozilla/5.0 (X11, Linux x86_64)", "python-requests/2.32")
PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
ETHERNET = bytes.fromhex("020000000002020000000001") + b"\x08\x00"


def _ip(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def _ipv4(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, protocol, 0, _ip(src), _ip(dst))
    total = sum(struct.unpack("!10H", header))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return header[:10] + struct.pack("!H", ~total & 0xFFFF) + header[12:] + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp_psh(sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 0x50, 0x18, 64240, 0, 0) + payload


def _dns(txid: int, name: str, response: bool) -> bytes:
    flags = 0x8180 if response else 0x0100
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def write_synthetic_capture(path: Path, target_bytes: int, seed: int = SYNTHETIC_SEED) -> dict[str, Any]:
    """Write a deterministic mixed-traffic capture and return the benchmark facts it contains."""
    rng = random.Random(seed)
    sources = Counter[str]()
    packets = dns_queries = frame_bytes = 0
    user_agents: set[str] = set()
    hosts = [f"10.0.{index // 250}.{index % 250 + 1}" for index in range(2000)]
    timestamp = 1_700_000_000.0
    filler = bytes(range(256)) * 6
    with path.open("wb") as handle:
        handle.write(PCAP_HEADER)
        written = len(PCAP_HEADER)
        while written < target_bytes:
            roll = rng.random()
            client = HEAVY_SOURCE if rng.random() < 0.04 else rng.choice(hosts)
            sport = rng.randrange(20000, 60000)
            if roll < 0.08:
                src, dst = client, DNS_SERVER
                ip = _ipv4(
                    src, dst, 17, _udp(sport, 53, _dns(packets & 0xFFFF, f"h{rng.randrange(5000)}.example.test", False))
                )
                dns_queries += 1
            elif roll < 0.16:
                src, dst = DNS_SERVER, client
                ip = _ipv4(
                    src, dst, 17, _udp(53, sport, _dns(packets & 0xFFFF, f"h{rng.randrange(5000)}.example.test", True))
                )
            elif roll < 0.20:
                agent = rng.choice(USER_AGENTS)
                user_agents.add(agent)
                request = f"GET /item/{rng.randrange(100000)} HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: {agent}\r\n\r\n"
                src, dst = client, "10.255.0.80"
                ip = _ipv4(src, dst, 6, _tcp_psh(sport, 80, rng.randrange(1 << 31), request.encode()))
            else:
                src, dst = client, rng.choice(hosts)
                ip = _ipv4(src, dst, 17, _udp(sport, FILLER_PORT, filler[: rng.randrange(32, 1400)]))
            frame = ETHERNET + ip
            timestamp += rng.random() / 1000
            seconds = int(timestamp)
            handle.write(struct.pack("<IIII", seconds, int((timestamp - seconds) * 1_000_000), len(frame), len(frame)))
            handle.write(frame)
            written += 16 + len(frame)
            packets += 1
            frame_bytes += len(frame)
            sources[src] += 1
    primary, primary_count = min(sources.items(), key=lambda item: (-item[1], item[0]))
    return {
        "capture_bytes": written,
        "facts": {
            "packet_count": {"packet_count": packets},
            "primary_source": {"primary_source": primary, "primary_source_packets": primary_count},
            "dns_query_count": {"dns_query_count": dns_queries},
            "literal_user_agent": {"distinct_http_user_agents": len(user_agents)},
            "numeric_frame_bytes": {"frame_bytes": float(frame_bytes)},
        },
    }


def prepare_tier(size_mb: int, work_dir: Path, seed: int = SYNTHETIC_SEED) -> dict[str, Any]:
    """Create (or reuse) one scaling-tier capture and its fact manifest."""
    capture = work_dir / f"synthetic-{size_mb}mb-seed{seed}.pcap"
    manifest_path = capture.with_suffix(".json")
    if capture.exists() and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("capture_bytes") == capture.stat().st_size:
            return manifest
    manifest = write_synthetic_capture(capture, size_mb * 1_000_000, seed)
    manifest.update({"tier": f"{size_mb}MB", "capture": str(capture), "seed": seed})
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _rows(text: str) -> list[list[str]]:
    lines = [line for line in text.splitlines() if line.strip()]
    return [[cell.strip().strip('"') for cell in line.split("\t")] for line in lines[1:]]


def _facts_from_rows(scenario_id: str, rows: list[list[str]]) -> dict[str, Any]:
    if scenario_id == "packet_count":
        return {"packet_count": len(rows)}
    if scenario_id == "primary_source":
        counts = Counter(row[1] for row in rows if len(row) > 1 and row[1])
        source, count = min(counts.items(), key=lambda item: (-item[1], item[0]))
        return {"primary_source": source, "primary_source_packets": count}
    if scenario_id == "dns_query_count":
        return {"dns_query_count": len(rows)}
    if scenario_id == "literal_user_agent":
        return {"distinct_http_user_agents": len({row[1] for row in rows if len(row) > 1 and row[1]})}
    if scenario_id == "numeric_frame_bytes":
        return {"frame_bytes": sum(float(row[1]) for row in rows if len(row) > 1 and row[1])}
    raise ValueError(f"Unknown scenario: {scenario_id}")


def run_cli(scenario_id: str, tshark_path: str, capture: Path | None = None) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_id]
    capture = capture or FIXTURES / scenario["capture"]
    command = [tshark_path, "-n", "-r", str(capture), "-T", "fields"]
    for field in scenario["cli_fields"]:
        command.extend(["-e", field])
    if scenario["filter"]:
        command.extend(["-Y", scenario["filter"]])
    command.extend(["-E", "header=y", "-E", "separator=/t", "-E", "aggregator=,", "-E", "quote=d"])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"tshark exited with {completed.returncode}")
    return _facts_from_rows(scenario_id, _rows(completed.stdout))


async def _prepare_mcp() -> Any:
    from mcp.server import MCPServer

    from wireshark_mcp.tools.stats import register_stats_tools
    from wireshark_mcp.tshark.client import TSharkClient

    server = MCPServer("analysis-path-benchmark")
    register_stats_tools(server, TSharkClient())
    return server


async def run_mcp(server: Any, scenario_id: str, capture: Path | None = None) -> dict[str, Any]:
    from mcp.types import CallToolResult, TextContent

    scenario = SCENARIOS[scenario_id]
    arguments = {"pcap_file": str(capture or FIXTURES / scenario["capture"]), **scenario["mcp"]}
    result = await server.call_tool("wireshark_aggregate", arguments)
    if (
        not isinstance(result, CallToolResult)
        or len(result.content) != 1
        or not isinstance(result.content[0], TextContent)
    ):
        raise RuntimeError("MCP aggregate returned an unexpected content shape")
    payload = json.loads(result.content[0].text)
    if not payload.get("success"):
        raise RuntimeError(json.dumps(payload.get("error"), ensure_ascii=False))
    data = payload["data"]
    if payload.get("coverage", {}).get("status") not in (None, "complete"):
        raise RuntimeError(f"MCP aggregate coverage was {payload['coverage'].get('status')}")
    if scenario_id == "packet_count":
        return {"packet_count": data["matched_packets"]}
    if scenario_id == "primary_source":
        group = data["groups"][0]
        return {"primary_source": group["key"]["ip.src"], "primary_source_packets": group["count"]}
    if scenario_id == "dns_query_count":
        return {"dns_query_count": data["matched_packets"]}
    if scenario_id == "literal_user_agent":
        return {"distinct_http_user_agents": data["groups"][0]["distinct"]["http.user_agent"]}
    if scenario_id == "numeric_frame_bytes":
        return {"frame_bytes": data["groups"][0]["numeric"]["frame.len"]["sum"]}
    raise ValueError(f"Unknown scenario: {scenario_id}")


def _peak_rss_bytes() -> dict[str, int] | None:
    if resource is None:
        return None
    unit = 1 if sys.platform == "darwin" else 1024
    own = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * unit)
    children = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * unit)
    return {"worker": own, "tshark": children, "combined_estimate": own + children}


async def _worker(
    variant: str,
    scenario_id: str,
    iterations: int,
    warmup: int,
    tshark_path: str,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    capture = Path(manifest["capture"]) if manifest else None
    setup_started = time.perf_counter_ns()
    server = await _prepare_mcp() if variant == "mcp" else None
    setup_ms = (time.perf_counter_ns() - setup_started) / 1_000_000

    async def execute() -> dict[str, Any]:
        if variant == "mcp":
            return await run_mcp(server, scenario_id, capture)
        return run_cli(scenario_id, tshark_path, capture)

    for _ in range(warmup):
        await execute()
    elapsed: list[float] = []
    facts: dict[str, Any] = {}
    errors: list[str] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        try:
            facts = await execute()
        except Exception as exc:  # keep all iterations reportable
            errors.append(str(exc))
        elapsed.append((time.perf_counter_ns() - started) / 1_000_000)
    expected = manifest["facts"][scenario_id] if manifest else SCENARIOS[scenario_id]["expected"]
    return {
        "scenario_id": scenario_id,
        "variant": variant,
        "tier": manifest["tier"] if manifest else "fixture",
        "iterations": iterations,
        "warmup_iterations": warmup,
        "setup_ms": setup_ms,
        "passed": not errors and facts == expected,
        "expected": expected,
        "facts": facts,
        "errors": errors,
        "elapsed_ms": elapsed,
        "peak_rss_bytes": _peak_rss_bytes(),
        "process_calls": iterations + warmup,
    }


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
    return round(ordered[index], 3)


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    variants: dict[str, dict[str, Any]] = {}
    for variant in sorted({record["variant"] for record in records}):
        selected = [record for record in records if record["variant"] == variant]
        timings = [value for record in selected for value in record.get("elapsed_ms", [])]
        setup = [float(record["setup_ms"]) for record in selected if isinstance(record.get("setup_ms"), (int, float))]
        memory = [
            record["peak_rss_bytes"]["combined_estimate"]
            for record in selected
            if isinstance(record.get("peak_rss_bytes"), dict)
        ]
        variants[variant] = {
            "scenarios": len(selected),
            "scenarios_passed": sum(bool(record.get("passed")) for record in selected),
            "error_rate": round(sum(len(record.get("errors", [])) for record in selected) / max(1, len(timings)), 4),
            "mean_setup_ms": round(statistics.fmean(setup), 3) if setup else None,
            "mean_elapsed_ms": round(statistics.fmean(timings), 3) if timings else None,
            "p50_elapsed_ms": _percentile(timings, 0.5),
            "p95_elapsed_ms": _percentile(timings, 0.95),
            "max_combined_peak_rss_bytes": max(memory) if memory else None,
            "process_calls": sum(int(record.get("process_calls", 0)) for record in selected),
            "token_cost": None,
        }
    return variants


def _tshark_version(tshark_path: str) -> str:
    completed = subprocess.run([tshark_path, "--version"], capture_output=True, text=True, check=False)
    return next((line for line in completed.stdout.splitlines() if line.strip()), "unknown")


def _run_worker(
    variant: str, scenario_id: str, iterations: int, warmup: int, tshark_path: str, manifest: Path | None
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "_worker",
        "--variant",
        variant,
        "--scenario",
        scenario_id,
        "--iterations",
        str(iterations),
        "--warmup",
        str(warmup),
        "--tshark",
        tshark_path,
    ]
    if manifest:
        command.extend(["--manifest", str(manifest)])
    completed = subprocess.run(command, capture_output=True, text=True, check=False, cwd=ROOT)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    record: dict[str, Any] = json.loads(completed.stdout)
    return record


def _scan_policy_environment() -> dict[str, str]:
    return {name: value for name, value in sorted(os.environ.items()) if name.startswith("WIRESHARK_MCP_AGGREGATE_")}


def _run_parent(
    iterations: int,
    warmup: int,
    output: Path | None,
    tshark_path: str,
    tiers: list[int] | None = None,
    work_dir: Path | None = None,
    scale_iterations: int = 3,
    scale_warmup: int = 1,
) -> int:
    records: list[dict[str, Any]] = []
    for variant in ("mcp", "tshark-cli"):
        for scenario_id in SCENARIOS:
            records.append(_run_worker(variant, scenario_id, iterations, warmup, tshark_path, None))
    scaling: dict[str, Any] = {}
    scaling_records: list[dict[str, Any]] = []
    if tiers:
        work_dir = work_dir or Path(tempfile.gettempdir()) / "wireshark-mcp-benchmark"
        work_dir.mkdir(parents=True, exist_ok=True)
        for size_mb in tiers:
            manifest = prepare_tier(size_mb, work_dir)
            manifest_path = Path(manifest["capture"]).with_suffix(".json")
            tier_records = [
                _run_worker(variant, scenario_id, scale_iterations, scale_warmup, tshark_path, manifest_path)
                for variant in ("mcp", "tshark-cli")
                for scenario_id in SCENARIOS
            ]
            scaling_records.extend(tier_records)
            scaling[manifest["tier"]] = {
                "capture_bytes": manifest["capture_bytes"],
                "packets": manifest["facts"]["packet_count"]["packet_count"],
                "seed": manifest["seed"],
                "summary": summarize(tier_records),
            }
    report = {
        "schema_version": 2,
        "benchmark": "analysis-path-engine-baseline",
        "scope": "Execution primitives only; this does not measure Agent accuracy, evidence quality, or tokens.",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "tshark": _tshark_version(tshark_path),
            "scan_policy_env": _scan_policy_environment(),
        },
        "summary": summarize(records),
        "scaling": scaling,
        "records": records + scaling_records,
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if output:
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if all(record["passed"] for record in report["records"]) else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    run = subparsers.add_parser("run", help="run both execution paths in isolated workers")
    run.add_argument("--iterations", type=int, default=5)
    run.add_argument("--warmup", type=int, default=1)
    run.add_argument("--output", type=Path)
    run.add_argument("--tshark", default=shutil.which("tshark") or "tshark")
    run.add_argument(
        "--scale",
        type=int,
        action="append",
        choices=SCALING_TIERS_MB,
        help="also run a deterministic synthetic capture of this size in MB (repeatable)",
    )
    run.add_argument("--work-dir", type=Path, help="where synthetic captures are generated and reused")
    run.add_argument("--scale-iterations", type=int, default=3)
    run.add_argument("--scale-warmup", type=int, default=1)
    worker = subparsers.add_parser("_worker")
    worker.add_argument("--variant", choices=["mcp", "tshark-cli"], required=True)
    worker.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    worker.add_argument("--iterations", type=int, required=True)
    worker.add_argument("--warmup", type=int, required=True)
    worker.add_argument("--tshark", required=True)
    worker.add_argument("--manifest", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "_worker":
        manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest else None
        record = asyncio.run(_worker(args.variant, args.scenario, args.iterations, args.warmup, args.tshark, manifest))
        sys.stdout.write(json.dumps(record))
        return 0
    if args.command == "run":
        if args.iterations < 1:
            raise SystemExit("--iterations must be positive")
        if args.warmup < 0 or args.scale_warmup < 0:
            raise SystemExit("--warmup must be non-negative")
        if args.scale_iterations < 1:
            raise SystemExit("--scale-iterations must be positive")
        return _run_parent(
            args.iterations,
            args.warmup,
            args.output,
            args.tshark,
            sorted(set(args.scale or [])),
            args.work_dir,
            args.scale_iterations,
            args.scale_warmup,
        )
    _parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
