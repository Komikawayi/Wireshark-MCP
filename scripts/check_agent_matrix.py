#!/usr/bin/env python3
"""Prepare blind tasks or check a complete, repeated Agent comparison matrix."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evals/agent-traffic-analysis/scenarios.json"
VARIANTS = ("without-skill", "with-skill", "tshark-cli")
SHARED_SETTINGS = (
    "model",
    "reasoning_effort",
    "engine_version",
    "plugin_fingerprint",
    "platform",
    "source_revision",
    "budget",
)


def evaluator():
    spec = importlib.util.spec_from_file_location("matrix_evaluator", ROOT / "scripts/evaluate_agent_traffic.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def blind_tasks(manifest: dict, repeats: int = 3) -> list[dict]:
    if isinstance(repeats, bool) or repeats < 1:
        raise ValueError("repeats must be positive")
    scenarios = manifest["scenarios"]
    if not scenarios or len({item["id"] for item in scenarios}) != len(scenarios):
        raise ValueError("scenario IDs must be nonempty and unique")
    tasks = []
    for scenario in scenarios:
        for variant in VARIANTS:
            for trial in range(1, repeats + 1):
                # Do not forward expected facts, conclusions, grading rules or injection recipes.
                task = {
                    "scenario_id": scenario["id"],
                    "variant": variant,
                    "trial": trial,
                    "prompt": scenario["prompt"],
                    "input_id": scenario["capture"],
                }
                if variant != "without-skill":
                    name = "tshark-cli-analysis" if variant == "tshark-cli" else "wireshark-traffic-analysis"
                    task["skill"] = f"skills/{name}/SKILL.md"
                task["input_status"] = (
                    "requires_fixture_adapter" if scenario["capture"].startswith("synthetic://") else "file"
                )
                tasks.append(task)
    return tasks


def check_matrix(manifest: dict, variants: dict[str, list[dict]], traces: dict[str, dict], *, repeats: int = 3) -> dict:
    expected = {(t["scenario_id"], t["variant"], t["trial"]) for t in blind_tasks(manifest, repeats)}
    seen = set()
    contexts = set()
    trace_digests = set()
    shared = None
    profiles = {}
    errors = []
    evaluations = {}
    engine = evaluator()
    scenarios = {item["id"]: item for item in manifest["scenarios"]}
    for variant, runs in variants.items():
        if variant not in VARIANTS:
            errors.append(f"unknown variant: {variant}")
        for index, run in enumerate(runs):
            label = f"{variant}[{index}]"
            trial = run.get("trial")
            scenario_id = run.get("scenario_id")
            if not isinstance(scenario_id, str) or type(trial) is not int:
                errors.append(f"{label}: scenario_id/trial invalid")
                continue
            cell = (scenario_id, variant, trial)
            if cell not in expected:
                errors.append(f"{label}: unexpected cell {cell}")
            if cell in seen:
                errors.append(f"{label}: duplicate cell {cell}")
            seen.add(cell)
            if run.get("variant") != variant:
                errors.append(f"{label}: variant differs from input group")
            trace_id = run.get("trace_id")
            trace = traces.get(variant, {}).get(trace_id, {}) if isinstance(trace_id, str) else {}
            verified = trace.get("_verified_file_sha256")
            if trace.get("load_error") or not verified or verified != run.get("trace_sha256"):
                errors.append(f"{label}: verified trace missing or mismatched")
                continue
            if scenario_id in scenarios:
                trace_errors = []
                engine._check_trace(scenarios[scenario_id], run, trace, trace_errors)
                errors.extend(f"{label}: {error}" for error in trace_errors)
            if verified in trace_digests:
                errors.append(f"{label}: trace reused across trials")
            trace_digests.add(verified)
            context = trace.get("context_id")
            if not isinstance(context, str) or not context or context in contexts:
                errors.append(f"{label}: fresh unique collector context_id required")
            if isinstance(context, str):
                contexts.add(context)
            settings = trace.get("experiment")
            if not isinstance(settings, dict) or any(settings.get(key) in (None, "", {}) for key in SHARED_SETTINGS):
                errors.append(f"{label}: experiment settings missing")
            else:
                current = {key: settings[key] for key in SHARED_SETTINGS}
                if shared is None:
                    shared = current
                elif shared != current:
                    errors.append(f"{label}: shared experiment settings differ")
                profile = settings.get("tool_profile")
                if not isinstance(profile, str) or not profile:
                    errors.append(f"{label}: tool_profile missing")
                elif variant in profiles and profiles[variant] != profile:
                    errors.append(f"{label}: tool_profile changed within variant")
                else:
                    profiles[variant] = profile
            execution = run.get("execution")
            if not isinstance(execution, dict) or execution.get("status") != "completed":
                errors.append(f"{label}: investigation did not complete")
        evaluations[variant] = engine.evaluate(manifest, runs, traces.get(variant, {}))
    # A baseline can be wrong and still be valid comparison data. Never require
    # every baseline answer to pass before measuring a skill's effect.
    missing = sorted(expected - seen)
    if (
        all(name in profiles for name in ("without-skill", "with-skill"))
        and profiles["without-skill"] != profiles["with-skill"]
    ):
        errors.append("MCP baseline and with-skill tool profiles differ")
    return {
        "schema_version": 1,
        "expected_runs": len(expected),
        "received_runs": sum(len(runs) for runs in variants.values()),
        "collection_complete": not missing and not errors,
        "missing_cells": [dict(zip(("scenario_id", "variant", "trial"), cell, strict=True)) for cell in missing],
        "collection_errors": errors,
        "shared_settings": shared,
        "tool_profiles": profiles,
        "evaluations": evaluations,
        "limits": "Unique context IDs and hashes check collector consistency, not authenticity or semantic causality.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--prepare", type=Path, help="create a NEW directory of blind work items; does not execute agents"
    )
    parser.add_argument("--variant", action="append", default=[], help="NAME=RUNS.json")
    parser.add_argument("--trace-dir", type=Path, help="collector-owned traces/<variant>/")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    if args.prepare:
        if args.variant or args.trace_dir or args.output:
            parser.error("--prepare does not accept result/check arguments")
        tasks = blind_tasks(manifest, args.repeats)
        args.prepare.mkdir(parents=True, exist_ok=False)
        for task in tasks:
            name = f"{task['scenario_id']}--{task['variant']}--{task['trial']}.json"
            (args.prepare / name).write_text(json.dumps(task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        plan = {
            "status": "prepared_not_executed",
            "task_count": len(tasks),
            "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            "fixture_adapter_required": sorted({t["input_id"] for t in tasks if t["input_status"] != "file"}),
        }
        (args.prepare / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Prepared {len(tasks)} blind tasks; no Agent run executed: {args.prepare.resolve()}")
        return 0
    if not args.variant or not args.trace_dir or not args.output:
        parser.error("checking requires --variant, --trace-dir and --output")
    engine = evaluator()
    variants = {}
    traces = {}
    for item in args.variant:
        name, sep, path = item.partition("=")
        if not sep or name not in VARIANTS or name in variants:
            parser.error("each variant must use a unique supported NAME=RUNS.json")
        variants[name] = engine._load_runs(Path(path))
        traces[name] = engine.load_traces(args.trace_dir / name, variants[name])
    report = check_matrix(manifest, variants, traces, repeats=args.repeats)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"Agent matrix: {report['received_runs']}/{report['expected_runs']} runs; collection_complete={report['collection_complete']}"
    )
    return int(not report["collection_complete"])


if __name__ == "__main__":
    raise SystemExit(main())
