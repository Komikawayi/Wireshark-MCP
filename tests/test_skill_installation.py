from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module():
    spec = importlib.util.spec_from_file_location("skill_installation", ROOT / "scripts/check_skill_installation.py")
    assert spec and spec.loader
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_clean_checkout_installs_both_skills_and_repairs_windows_link_files(tmp_path: Path):
    # A Windows checkout without symlinks has plain files containing link targets.
    repo = tmp_path / "clean checkout with spaces"
    shutil.copytree(ROOT / "skills", repo / "skills", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (repo / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts/sync_skills.py", repo / "scripts/sync_skills.py")
    for name in ("tshark-cli-analysis", "wireshark-traffic-analysis"):
        path = repo / ".agents/skills" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("../../skills/" + name, encoding="utf-8")
    cmd = [sys.executable, str(repo / "scripts/sync_skills.py")]
    before = subprocess.run([*cmd, "--check", "--require-installed"], capture_output=True, timeout=20)
    assert before.returncode == 1
    subprocess.run(cmd, check=True, capture_output=True, timeout=20)
    subprocess.run([*cmd, "--check", "--require-installed"], check=True, capture_output=True, timeout=20)
    for client in (".agents", ".github", ".claude"):
        for source in (repo / "skills").rglob("*"):
            if source.is_file() and source.name != "manifest.json":
                assert (
                    source.read_bytes() == (repo / client / "skills" / source.relative_to(repo / "skills")).read_bytes()
                )


def test_installed_resources_work_without_engine_and_do_not_claim_execution(tmp_path: Path, monkeypatch):
    import wireshark_mcp

    package = tmp_path / "installed package"
    shutil.copytree(ROOT / "skills", package / "skills", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    monkeypatch.setattr(wireshark_mcp, "__file__", str(package / "__init__.py"))
    checker = module()
    monkeypatch.setattr(checker.shutil, "which", lambda name: None)
    report = checker.probe()
    assert report["status"] == "passed"
    assert report["engine_smoke"] == "not_run:missing_tshark"
    assert report["client_ui_selection"] == "not_tested"
    assert report["global_registration"] == "not_modified"
    assert len(report["checks"]) == 6
    with pytest.raises(ValueError, match="TShark is required"):
        checker.probe(require_engine=True)


def test_packaged_broken_reference_is_detected(tmp_path: Path, monkeypatch):
    import wireshark_mcp

    package = tmp_path / "pkg"
    shutil.copytree(ROOT / "skills", package / "skills", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    monkeypatch.setattr(wireshark_mcp, "__file__", str(package / "__init__.py"))
    path = package / "skills/tshark-cli-analysis/references/option-index.md"
    path.unlink()
    with pytest.raises(ValueError, match="broken packaged reference"):
        module().probe()


@pytest.mark.parametrize("default_encoding", ["cp1252", "ascii"])
def test_installed_resources_use_utf8_under_legacy_locale(tmp_path: Path, monkeypatch, default_encoding):
    import wireshark_mcp

    package = tmp_path / "installed package"
    shutil.copytree(ROOT / "skills", package / "skills", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (package / "skills/tshark-cli-analysis/references/locale.md").write_text(
        "# 流量分析：UTF-8 — evidence\n", encoding="utf-8"
    )
    monkeypatch.setattr(wireshark_mcp, "__file__", str(package / "__init__.py"))
    checker = module()
    monkeypatch.setattr(checker.shutil, "which", lambda name: None)
    read_text = Path.read_text

    def legacy_read_text(path, *args, **kwargs):
        if not args:
            kwargs.setdefault("encoding", default_encoding)
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", legacy_read_text)
    assert checker.probe()["status"] == "passed"


def test_short_capability_router_keeps_full_option_index_reachable():
    import re

    refs = ROOT / "skills/tshark-cli-analysis/references"
    catalog = json.loads((refs / "capability-catalog.json").read_text(encoding="utf-8"))
    router = (refs / "capability-map.md").read_text(encoding="utf-8")
    index = (refs / "option-index.md").read_text(encoding="utf-8")
    options = set(re.findall(r"^\| `([^`]+)` \|", index, re.MULTILINE))
    assert options == set(catalog["options"])
    assert "option-index.md" in router
    assert not re.search(r"^\| `-", router, re.MULTILINE)
    # Budget the routing surface, not the exact words/headings of the prose.
    assert len(router.encode()) < 3000
