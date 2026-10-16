"""Check real evaluation invariants, not prose wording or fabricated benchmark scores."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_agent_matrix", ROOT / "scripts/check_agent_matrix.py")
assert SPEC and SPEC.loader
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


def example():
    # Synthetic records here exercise the gate only; they are not Agent results.
    manifest = {
        "scenarios": [
            {
                "id": "one",
                "capture": "synthetic://gate-test",
                "prompt": "Count frames.",
                "expected_conclusion": "confirmed",
                "expected_facts": {"count": 1},
                "allowed_coverage": ["complete"],
                "evidence": {"min_anchors": 1, "accepted_types": ["query"]},
            }
        ]
    }
    variants = {name: [] for name in MATRIX.VARIANTS}
    traces = {name: {} for name in MATRIX.VARIANTS}
    for task in MATRIX.blind_tasks(manifest):
        variant, trial = task["variant"], task["trial"]
        trace_id = f"{variant}-{trial}.json"
        digest = f"{len([r for runs in variants.values() for r in runs]):064x}"
        run = {
            "scenario_id": "one",
            "variant": variant,
            "trial": trial,
            "trace_id": trace_id,
            "trace_sha256": digest,
            "execution": {"status": "completed"},
            "conclusion": "confirmed",
            "facts": {"count": 1},
            "coverage": {"status": "complete"},
            "evidence": [{"type": "query", "call_id": "q", "query": "real query"}],
        }
        trace = {
            "_verified_file_sha256": digest,
            "context_id": trace_id,
            "input_id": "synthetic://gate-test",
            "experiment": {
                **dict.fromkeys(MATRIX.SHARED_SETTINGS, "fixed"),
                "tool_profile": "cli" if variant == "tshark-cli" else "mcp",
            },
            "calls": [
                {
                    "id": "q",
                    "query": "real query",
                    "status": "completed",
                    "coverage": "complete",
                    "observations": {"facts": {"count": 1}},
                }
            ],
        }
        variants[variant].append(run)
        traces[variant][trace_id] = trace
    return manifest, variants, traces


def test_prepared_tasks_do_not_disclose_grading_or_injection_recipes():
    import json

    manifest = json.loads(MATRIX.MANIFEST.read_text(encoding="utf-8"))
    tasks = MATRIX.blind_tasks(manifest)
    assert len(tasks) == 180
    assert len({(t["scenario_id"], t["variant"], t["trial"]) for t in tasks}) == 180
    for task in tasks:
        assert (
            not {
                "expected_conclusion",
                "expected_facts",
                "allowed_coverage",
                "evidence",
                "injection",
                "forbidden_claims",
            }
            & task.keys()
        )
        assert ("skill" in task) == (task["variant"] != "without-skill")
        if task["input_id"].startswith("synthetic://"):
            assert task["input_status"] == "requires_fixture_adapter"


def test_one_trial_per_scenario_is_not_a_complete_matrix():
    manifest, variants, traces = example()
    variants = {name: runs[:1] for name, runs in variants.items()}
    report = MATRIX.check_matrix(manifest, variants, traces)
    assert not report["collection_complete"]
    assert len(report["missing_cells"]) == 6


def test_complete_fresh_context_matrix_is_accepted():
    report = MATRIX.check_matrix(*example())
    assert report["collection_complete"]
    assert report["expected_runs"] == report["received_runs"] == 9
    assert all(item["summary"]["runs_passed"] == 3 for item in report["evaluations"].values())


def test_reusing_a_context_or_trace_does_not_fake_independence():
    manifest, variants, traces = example()
    a = iter(traces["with-skill"].values())
    first, second = next(a), next(a)
    second["context_id"] = first["context_id"]
    report = MATRIX.check_matrix(manifest, variants, traces)
    assert not report["collection_complete"]
    assert any("context_id" in error for error in report["collection_errors"])
    second["context_id"] = "other-context"
    second["_verified_file_sha256"] = first["_verified_file_sha256"]
    variants["with-skill"][1]["trace_sha256"] = first["_verified_file_sha256"]
    assert not MATRIX.check_matrix(manifest, variants, traces)["collection_complete"]


def test_mixed_experiments_and_duplicate_cells_are_rejected():
    manifest, variants, traces = example()
    variants["with-skill"][1]["trial"] = 1
    traces["tshark-cli"]["tshark-cli-1.json"]["experiment"]["model"] = "different-model"
    report = MATRIX.check_matrix(manifest, variants, traces)
    assert not report["collection_complete"]
    assert any("duplicate cell" in error for error in report["collection_errors"])
    assert any("settings differ" in error for error in report["collection_errors"])


def test_valid_but_wrong_baseline_stays_in_comparison_data():
    manifest, variants, traces = example()
    variants["without-skill"][0]["facts"]["count"] = 2
    report = MATRIX.check_matrix(manifest, variants, traces)
    assert report["collection_complete"]
    assert report["evaluations"]["without-skill"]["summary"]["runs_passed"] == 2


def test_verified_but_empty_or_wrong_input_trace_is_not_complete_collection():
    manifest, variants, traces = example()
    traces["with-skill"]["with-skill-1.json"]["calls"] = []
    traces["tshark-cli"]["tshark-cli-2.json"]["input_id"] = "synthetic://different"
    report = MATRIX.check_matrix(manifest, variants, traces)
    assert not report["collection_complete"]
    assert any("no calls" in error for error in report["collection_errors"])
    assert any("input does not match" in error for error in report["collection_errors"])


def test_skill_effect_is_not_confounded_with_changed_mcp_tool_profile():
    manifest, variants, traces = example()
    for trace in traces["with-skill"].values():
        trace["experiment"]["tool_profile"] = "different-mcp-profile"
    report = MATRIX.check_matrix(manifest, variants, traces)
    assert not report["collection_complete"]
    assert "MCP baseline and with-skill tool profiles differ" in report["collection_errors"]


def test_distribution_reports_variation_and_missing_metrics():
    spec = importlib.util.spec_from_file_location("comparison", ROOT / "scripts/compare_agent_traffic.py")
    assert spec and spec.loader
    compare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compare)
    report = compare.summarize_variant(
        {
            "summary": {"missing_scenarios": [], "unknown_scenarios": []},
            "results": [
                {"passed": True, "metrics": {"tool_calls": 1}},
                {"passed": True, "metrics": {"tool_calls": 3}},
                {"passed": True, "metrics": {}},
                {"passed": False, "metrics": {"tool_calls": 999}},
            ],
        },
        [],
    )
    stats = report["efficiency_distributions"]["tool_calls"]
    assert stats == {"samples": 2, "missing": 1, "min": 1.0, "median": 2.0, "max": 3.0, "sample_stdev": 1.41}
    assert report["efficiency_distributions"]["elapsed_ms"]["median"] is None
