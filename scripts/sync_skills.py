#!/usr/bin/env python3
"""Sync canonical project skills into app-specific discovery locations."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
GITHUB_SKILLS_DIR = ROOT / ".github" / "skills"
CLAUDE_SKILLS_DIR = ROOT / ".claude" / "skills"
CODEX_SKILLS_DIR = ROOT / ".agents" / "skills"
MANIFEST_PATH = SKILLS_DIR / "manifest.json"


def list_skill_dirs() -> list[Path]:
    return sorted(path for path in SKILLS_DIR.iterdir() if path.is_dir() and (path / "SKILL.md").exists())


def sync_tree(source: Path, destination: Path) -> None:
    if destination.is_symlink() and destination.resolve() == source.resolve():
        return
    if destination.is_symlink() or destination.is_file():
        destination.unlink()
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def check_tree_matches(source: Path, destination: Path) -> bool:
    if not destination.exists():
        print(f"Destination does not exist: {destination}", file=sys.stderr)
        return False

    def contents(root: Path) -> dict[str, bytes]:
        return {
            str(p.relative_to(root)): p.read_bytes()
            for p in root.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        }

    same = contents(source) == contents(destination)
    if not same:
        print(f"Differences found between {source} and {destination}", file=sys.stderr)
    return same


def discovery_locations() -> tuple[Path, ...]:
    return CODEX_SKILLS_DIR, GITHUB_SKILLS_DIR, CLAUDE_SKILLS_DIR


def build_manifest(skill_dirs: list[Path]) -> dict[str, object]:
    skills: list[dict[str, object]] = []
    for skill_dir in skill_dirs:
        skill_name = skill_dir.name
        skills.append(
            {
                "name": skill_name,
                "canonical_path": f"skills/{skill_name}",
                "project_locations": [
                    f".agents/skills/{skill_name}",
                    f".github/skills/{skill_name}",
                    f".claude/skills/{skill_name}",
                ],
                "root_instruction_files": [
                    "CLAUDE.md",
                ],
                "copilot": {
                    "instructions_file": ".github/copilot-instructions.md",
                },
                "packaged_path": f"wireshark_mcp/skills/{skill_name}",
            }
        )
    return {
        "schema_version": 1,
        "generated_by": "scripts/sync_skills.py",
        "skills": skills,
    }


def run_check(skill_dirs: list[Path], *, source_only: bool = False, require_installed: bool = False) -> int:
    if not MANIFEST_PATH.exists():
        print(f"Manifest missing: {MANIFEST_PATH}", file=sys.stderr)
        return 1
    expected_manifest = build_manifest(skill_dirs)
    try:
        current_manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Failed to read/parse manifest: {exc}", file=sys.stderr)
        return 1
    if current_manifest != expected_manifest:
        print("Manifest does not match generated manifest.", file=sys.stderr)
        return 1

    if source_only:
        print("Canonical skills and manifest are valid; client installation was not checked.")
        return 0
    installed = 0
    missing = []
    for directory in discovery_locations():
        if not directory.exists():
            missing.append(str(directory))
            continue
        for skill_dir in skill_dirs:
            if not check_tree_matches(skill_dir, directory / skill_dir.name):
                return 1
        installed += 1
    if missing:
        print("Skill discovery locations not installed: " + ", ".join(missing))
    if not installed or (require_installed and missing):
        print("Run python scripts/sync_skills.py to install discovery mirrors.", file=sys.stderr)
        return 1
    print(f"Canonical manifest valid; {installed} installed skill discovery location(s) verified.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync or check skill distribution.")
    parser.add_argument("--check", action="store_true", help="Check skill sync without modifying files.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--source-only", action="store_true", help="validate source manifest only; does not claim installation"
    )
    mode.add_argument("--require-installed", action="store_true", help="require every client discovery location")
    args = parser.parse_args()

    skill_dirs = list_skill_dirs()

    if args.check:
        sys.exit(run_check(skill_dirs, source_only=args.source_only, require_installed=args.require_installed))

    for directory in discovery_locations():
        directory.mkdir(parents=True, exist_ok=True)
        for skill_dir in skill_dirs:
            sync_tree(skill_dir, directory / skill_dir.name)

    MANIFEST_PATH.write_text(
        json.dumps(build_manifest(skill_dirs), indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
