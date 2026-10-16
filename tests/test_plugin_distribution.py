from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from zipfile import ZipFile

import pytest

ROOT = Path(__file__).resolve().parents[1]


def checker():
    spec = importlib.util.spec_from_file_location("check_plugin_package", ROOT / "scripts/check_plugin_package.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_both_clients_expose_same_source_version_and_skills():
    result = checker().check(ROOT)
    from wireshark_mcp import __version__

    assert result["version"] == __version__
    assert result["skills"] == ["tshark-cli-analysis", "wireshark-traffic-analysis"]
    assert "WIRESHARK_MCP_ALLOWED_DIRS" in result["codex_launcher"]["env_vars"]


def test_clean_plugin_archive_contains_runtime_and_no_developer_environment(tmp_path):
    module = checker()
    archive = tmp_path / "plugin.zip"
    assert module.build(ROOT, archive) > 50
    extracted = tmp_path / "unpacked plugin"
    with ZipFile(archive) as bundle:
        names = bundle.namelist()
        assert not any(".venv/" in name or "__pycache__" in name or name.startswith(".git/") for name in names)
        assert "uv.lock" in names and "src/wireshark_mcp/server.py" in names
        assert "CLAUDE.md" not in names  # Repository guidance is not plugin runtime context.
        bundle.extractall(extracted)
    assert module.check(extracted)["skills"] == module.check(ROOT)["skills"]
    with pytest.raises(FileExistsError):
        module.build(ROOT, archive)


def test_plugin_component_cannot_escape_or_reference_missing_resources(tmp_path):
    module = checker()
    with pytest.raises(ValueError):
        module.local_path(tmp_path, "../outside")
    with pytest.raises(ValueError):
        module.local_path(tmp_path, "./missing")


@pytest.mark.parametrize("kind", ["codex", "claude"])
def test_manifest_version_skew_fails(kind, tmp_path):
    module = checker()
    archive = tmp_path / "plugin.zip"
    module.build(ROOT, archive)
    root = tmp_path / "extracted"
    with ZipFile(archive) as bundle:
        bundle.extractall(root)
    manifest = root / f".{kind}-plugin/plugin.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["version"] = "0.0.0"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="version"):
        module.check(root)


def test_declared_skill_resource_loss_fails(tmp_path):
    module = checker()
    archive = tmp_path / "plugin.zip"
    module.build(ROOT, archive)
    root = tmp_path / "extracted"
    with ZipFile(archive) as bundle:
        bundle.extractall(root)
    shutil.rmtree(root / "skills/tshark-cli-analysis")
    with pytest.raises(ValueError, match="canonical skill"):
        module.check(root)
