"""Installation behavior against isolated client/project fixtures, never user configs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import tomlkit

from wireshark_mcp import server
from wireshark_mcp.installer._clients import get_client_configs
from wireshark_mcp.installer._config_edit import render_update
from wireshark_mcp.installer._lifecycle import configure_clients


@pytest.fixture(autouse=True)
def stable_runtime(monkeypatch):
    monkeypatch.setattr("wireshark_mcp.installer._config_gen._get_python_executable", lambda: "/runtime/python")
    monkeypatch.setattr("wireshark_mcp.installer._config_gen._collect_runtime_env", lambda: {"PATH": "/tools"})
    monkeypatch.setattr("wireshark_mcp.installer._orchestrator.sys.stdin.isatty", lambda: False)


def cli(project: Path, action: str, *extra: str):
    server.main(
        [action, "--client", "cursor", "--scope", "project", "--project-dir", str(project), "--format", "json", *extra]
    )


@pytest.mark.parametrize("action", ["install", "update", "uninstall"])
def test_noninteractive_cli_needs_explicit_targets(action, monkeypatch, capsys):
    monkeypatch.setattr(
        "wireshark_mcp.installer._orchestrator.configure_clients",
        lambda *args, **kwargs: pytest.fail("unselected client write was attempted"),
    )
    with pytest.raises(SystemExit) as exc:
        server.main([action, "--format", "json"])
    assert exc.value.code == 2
    assert "--client" in json.loads(capsys.readouterr().out)["error"]


def test_project_preview_creates_no_directory_or_backup(tmp_path, capsys):
    cli(tmp_path, "install", "--dry-run")
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "preview"
    assert report["summary"] == {"changed": 0, "planned": 1, "errors": 0, "skipped": 0}
    assert list(tmp_path.iterdir()) == []


def test_project_install_repeat_and_uninstall_preserve_other_settings(tmp_path, capsys):
    directory = tmp_path / ".cursor"
    directory.mkdir()
    path = directory / "mcp.json"
    before = b'{"otherSetting": true, "mcpServers": {"other": {"command": "other"}}}\n'
    path.write_bytes(before)
    cli(tmp_path, "install")
    first = json.loads(capsys.readouterr().out)
    assert first["summary"]["changed"] == 1
    assert Path(first["clients"][0]["backup_path"]).read_bytes() == before
    after = path.read_bytes()
    stat = path.stat().st_mtime_ns
    cli(tmp_path, "install")
    repeat = json.loads(capsys.readouterr().out)
    assert repeat["summary"]["changed"] == 0
    assert repeat["clients"][0]["status"] == "unchanged"
    assert path.read_bytes() == after and path.stat().st_mtime_ns == stat
    assert len(list(directory.glob("*.bak"))) == 1
    cli(tmp_path, "uninstall")
    removal = json.loads(capsys.readouterr().out)
    assert removal["summary"]["changed"] == 1
    assert json.loads(path.read_text()) == json.loads(before)
    assert Path(removal["clients"][0]["backup_path"]).read_bytes() == after


@pytest.mark.parametrize("action", ["update", "uninstall"])
def test_update_and_uninstall_do_not_create_uninstalled_targets(tmp_path, capsys, action):
    cli(tmp_path, action)
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["changed"] == 0
    assert report["clients"][0]["status"] == "not_installed"
    assert list(tmp_path.iterdir()) == []


def test_project_vscode_uses_top_level_servers_and_deduplicates_insiders(tmp_path):
    configs = get_client_configs(["vs-code", "vs-code-insiders"], scope="project", project_dir=str(tmp_path))
    report = configure_clients(configs, action="install", scope="project", dry_run=False, project_dir=str(tmp_path))
    data = json.loads((tmp_path / ".vscode/mcp.json").read_text())
    assert "wireshark-mcp" in data["servers"] and "mcp" not in data
    assert report["summary"]["changed"] == 1
    assert report["clients"][1]["status"] == "shared_target"


@pytest.mark.parametrize("client,relative", [("claude-code", ".mcp.json"), ("codex", ".codex/config.toml")])
def test_project_client_locations(tmp_path, client, relative):
    configs = get_client_configs([client], scope="project", project_dir=str(tmp_path))
    report = configure_clients(configs, action="install", scope="project", dry_run=False, project_dir=str(tmp_path))
    assert report["summary"]["changed"] == 1
    assert (tmp_path / relative).is_file()


@pytest.mark.parametrize("clients", [["all", "unknown"], [""]])
def test_all_does_not_hide_invalid_client_names(clients):
    with pytest.raises(ValueError, match="Unknown client"):
        get_client_configs(clients)


def test_unsupported_project_client_never_falls_back_to_global(tmp_path):
    with pytest.raises(ValueError):
        get_client_configs(["windsurf"], scope="project", project_dir=str(tmp_path))
    with pytest.raises(ValueError, match="requires --scope project"):
        get_client_configs(["codex"], project_dir=str(tmp_path))


@pytest.mark.parametrize(
    "content", ['{"mcpServers": []}', '{"mcpServers": true}', '{"mcpServers": 0}', "[1, 2]", "{bad json"]
)
def test_invalid_json_shape_remains_byte_identical(tmp_path, content):
    path = tmp_path / "config.json"
    path.write_text(content)
    report = configure_clients({"Cursor": (str(tmp_path), path.name)}, action="install", scope="global", dry_run=False)
    assert report["status"] == "failed" and report["summary"]["errors"] == 1
    assert path.read_text() == content
    assert not list(tmp_path.glob("*.bak"))


def test_malformed_toml_returns_nonzero_without_writes(tmp_path, capsys):
    folder = tmp_path / ".codex"
    folder.mkdir()
    path = folder / "config.toml"
    path.write_text("not valid toml\n")
    with pytest.raises(SystemExit) as exc:
        server.main(
            ["install", "--client", "codex", "--scope", "project", "--project-dir", str(tmp_path), "--format", "json"]
        )
    assert exc.value.code == 1
    assert json.loads(capsys.readouterr().out)["summary"]["errors"] == 1
    assert path.read_text() == "not valid toml\n"
    assert not list(folder.glob("*.bak"))


def test_toml_quoted_tables_multiline_strings_comments_and_custom_settings():
    original = '''# preserve this comment
model = "unchanged"
text = """
[mcp_servers.wireshark-mcp]
This is text, not a table.
"""
[mcp_servers.other] # preserve this table
command = "other"
[mcp_servers."wireshark-mcp"] # legitimate quoted key
command = "old"
startup_timeout_sec = 90
[mcp_servers."wireshark-mcp".env]
WIRESHARK_MCP_ALLOWED_DIRS = "/captures"
'''
    installed = render_update(original, "Codex", action="install", toml=True)
    assert "# preserve this comment" in installed and "# preserve this table" in installed
    data = tomlkit.parse(installed).unwrap()
    target = data["mcp_servers"]["wireshark-mcp"]
    assert target["startup_timeout_sec"] == 90
    assert target["env"]["WIRESHARK_MCP_ALLOWED_DIRS"] == "/captures"
    assert data["mcp_servers"]["other"]["command"] == "other"
    assert render_update(installed, "Codex", action="install", toml=True) == installed
    removed = render_update(installed, "Codex", action="uninstall", toml=True)
    restored = tomlkit.parse(removed).unwrap()
    assert "wireshark-mcp" not in restored["mcp_servers"]
    assert restored["text"] == tomlkit.parse(original)["text"]
    assert restored["model"] == "unchanged"


def test_apply_failure_preserves_config_and_records_backup(tmp_path, monkeypatch):
    path = tmp_path / "mcp.json"
    original = b'{"theme":"unchanged"}'
    path.write_bytes(original)

    def fail(*args, **kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr("wireshark_mcp.installer._lifecycle._write_text_config", fail)
    report = configure_clients({"Cursor": (str(tmp_path), path.name)}, action="install", scope="global", dry_run=False)
    assert report["summary"]["errors"] == 1
    assert path.read_bytes() == original
    assert Path(report["clients"][0]["backup_path"]).read_bytes() == original


def test_project_symlink_cannot_redirect_configuration_outside_project(tmp_path):
    project, outside = tmp_path / "project", tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    try:
        (project / ".cursor").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not supported on this host")
    configs = get_client_configs(["cursor"], scope="project", project_dir=str(project))
    report = configure_clients(configs, action="install", scope="project", dry_run=False, project_dir=str(project))
    assert report["summary"]["errors"] == 1 and not list(outside.iterdir())


def test_running_venv_interpreter_wins_over_stale_env_and_base_stdlib(tmp_path, monkeypatch):
    from wireshark_mcp.installer._detection import _get_python_executable

    executable = tmp_path / "venv python"
    executable.write_text("fixture executable")
    monkeypatch.setattr("wireshark_mcp.installer._detection.sys.executable", str(executable))
    monkeypatch.setattr("wireshark_mcp.installer._detection.sys.prefix", "/actual/venv")
    monkeypatch.setattr("wireshark_mcp.installer._detection.sys.base_prefix", "/base")
    monkeypatch.setattr("wireshark_mcp.installer._detection.sys.path", ["/base/lib/python313.zip"])
    monkeypatch.setenv("VIRTUAL_ENV", "/different/venv")
    assert _get_python_executable() == str(executable)


def test_documented_management_options_are_real_cli_options():
    parser = server._build_parser()
    for action in ("install", "update", "uninstall"):
        args = parser.parse_args(
            [
                action,
                "--client",
                "cursor",
                "--scope",
                "project",
                "--project-dir",
                "/project",
                "--dry-run",
                "--format",
                "json",
            ]
        )
        assert args.scope == "project" and args.dry_run and args.output_format == "json"
