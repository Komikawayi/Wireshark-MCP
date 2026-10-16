from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_DIR = ROOT / "skills" / "wireshark-traffic-analysis"
GITHUB_DIR = ROOT / ".github" / "skills" / "wireshark-traffic-analysis"
CLAUDE_DIR = ROOT / ".claude" / "skills" / "wireshark-traffic-analysis"
CODEX_DIR = ROOT / ".agents" / "skills" / "wireshark-traffic-analysis"
MANIFEST_PATH = ROOT / "skills" / "manifest.json"


def _relative_file_map(base: Path) -> dict[str, str]:
    return {
        str(path.relative_to(base)): path.read_text(encoding="utf-8")
        for path in sorted(base.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def test_skill_mirrors_match_canonical() -> None:
    canonical_files = _relative_file_map(CANONICAL_DIR)

    assert canonical_files
    if GITHUB_DIR.exists():
        assert canonical_files == _relative_file_map(GITHUB_DIR)
    if CLAUDE_DIR.exists():
        assert canonical_files == _relative_file_map(CLAUDE_DIR)
    if CODEX_DIR.exists():
        assert canonical_files == _relative_file_map(CODEX_DIR)


def test_skill_manifest_lists_supported_locations() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 1
    skills = manifest["skills"]
    assert isinstance(skills, list)
    assert skills

    skill = next(item for item in skills if item["name"] == "wireshark-traffic-analysis")
    assert skill["canonical_path"] == "skills/wireshark-traffic-analysis"
    assert ".github/skills/wireshark-traffic-analysis" in skill["project_locations"]
    assert ".claude/skills/wireshark-traffic-analysis" in skill["project_locations"]
    assert skill["copilot"]["instructions_file"] == ".github/copilot-instructions.md"
    assert ".agents/skills/wireshark-traffic-analysis" in skill["project_locations"]
    assert {item["name"] for item in skills} == {"wireshark-traffic-analysis", "tshark-cli-analysis"}


def test_sync_skills_cli_check_returns_zero_when_in_sync() -> None:
    import subprocess
    import sys

    res = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_skills.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "installed skill discovery location(s) verified" in res.stdout


def test_sync_skills_check_detects_discrepancy(tmp_path: Path, monkeypatch) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("sync_skills", ROOT / "scripts" / "sync_skills.py")
    assert spec and spec.loader
    ss = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ss)

    fake_empty = tmp_path / "empty_dir"
    fake_empty.mkdir()
    monkeypatch.setattr(ss, "GITHUB_SKILLS_DIR", fake_empty)
    skill_dirs = ss.list_skill_dirs()
    assert ss.run_check(skill_dirs) == 1


def test_sync_skills_does_not_claim_absent_mirrors_are_installed(tmp_path: Path, monkeypatch) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("sync_skills", ROOT / "scripts" / "sync_skills.py")
    assert spec and spec.loader
    ss = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ss)

    monkeypatch.setattr(ss, "GITHUB_SKILLS_DIR", tmp_path / "missing-github-skills")
    monkeypatch.setattr(ss, "CLAUDE_SKILLS_DIR", tmp_path / "missing-claude-skills")
    monkeypatch.setattr(ss, "CODEX_SKILLS_DIR", tmp_path / "missing-codex-skills")
    skill_dirs = ss.list_skill_dirs()
    assert ss.run_check(skill_dirs) == 1
    assert ss.run_check(skill_dirs, source_only=True) == 0


def test_sync_detects_same_size_same_mtime_content_change(tmp_path: Path) -> None:
    import importlib.util
    import os

    spec = importlib.util.spec_from_file_location("sync_skills", ROOT / "scripts" / "sync_skills.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "SKILL.md").write_text("AAAA")
    (target / "SKILL.md").write_text("BBBB")
    stat = (source / "SKILL.md").stat()
    os.utime(target / "SKILL.md", ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert not module.check_tree_matches(source, target)
