"""Config file read/write operations and CLI output helpers."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from typing import Any, cast

from ._clients import get_client_configs
from ._config_edit import has_entry, render_update, server_map
from ._config_gen import SERVER_NAME


def _read_json_config(path: str, *, strict: bool = False) -> dict[str, Any]:
    """Read a JSON config file, optionally refusing malformed or non-object content."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8-sig") as f:
        data = f.read().strip()
        if not data:
            return {}
        try:
            parsed: Any = json.loads(data)
            if isinstance(parsed, dict):
                return cast("dict[str, Any]", parsed)
            if strict:
                raise ValueError(f"Refusing to modify non-object JSON configuration: {path}")
            return {}
        except json.JSONDecodeError as exc:
            if strict:
                raise ValueError(f"Refusing to modify malformed JSON configuration: {path}") from exc
            return {}


def _write_json_config(path: str, config: dict[str, Any]) -> None:
    """Atomically write a JSON config file."""
    config_dir = os.path.dirname(path)
    mode = stat.S_IMODE(os.stat(path).st_mode) if os.path.exists(path) else 0o600
    fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=".json", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    except Exception:
        os.unlink(temp_path)
        raise


def _write_text_config(path: str, text: str, suffix: str) -> None:
    """Atomically write a text config file."""
    config_dir = os.path.dirname(path)
    mode = stat.S_IMODE(os.stat(path).st_mode) if os.path.exists(path) else 0o600
    fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=suffix, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    except Exception:
        os.unlink(temp_path)
        raise


def _get_mcp_servers_dict(config: dict[str, Any], client_name: str) -> dict[str, Any]:
    """Navigate into the correct nesting level for the mcpServers dict."""
    return server_map(config, client_name)


def _has_server_entry_in_json_config(config: dict[str, Any], client_name: str) -> bool:
    """Check whether a JSON config already contains this MCP server."""
    try:
        return SERVER_NAME in server_map(config.copy(), client_name)
    except ValueError:
        return False


def _has_server_entry(config_path: str, client_name: str) -> bool:
    """Check whether a client config contains this MCP server."""
    if not os.path.exists(config_path):
        return False

    try:
        with open(config_path, encoding="utf-8-sig") as stream:
            return has_entry(stream.read(), client_name, toml=config_path.endswith(".toml"))
    except (OSError, ValueError):
        return False


def _status_marker(status: str) -> str:
    """Return a short ASCII status label for CLI output."""
    return {
        "configured": "[OK]",
        "installed": "[OK]",
        "uninstalled": "[OK]",
        "config file found": "[INFO]",
        "client detected": "[INFO]",
        "already configured": "[SKIP]",
        "not installed": "[SKIP]",
        "not detected": "[MISS]",
    }.get(status, "[INFO]")


def _print_title(title: str) -> None:
    """Print a simple section header."""
    print(title)
    print("=" * len(title))


def _print_rows(rows: list[dict[str, str]]) -> None:
    """Print aligned status rows with optional paths."""
    if not rows:
        return

    width = max(len(row["name"]) for row in rows)
    for row in rows:
        marker = row.get("marker") or _status_marker(row.get("status", ""))
        detail = row.get("detail", "")
        print(f"  {marker:<6} {row['name']:<{width}} {detail}")
        path = row.get("path")
        if path:
            print(f"         {path}")


def _summarize_status_rows(rows: list[dict[str, str]], statuses: tuple[str, ...]) -> dict[str, int]:
    """Summarize row counts for the requested statuses."""
    return {
        status: sum(row["status"] == status for row in rows)
        for status in statuses
        if any(row["status"] == status for row in rows)
    }


def _collect_client_rows(selected_clients: list[str] | None = None) -> list[dict[str, str]]:
    """Collect client detection/configuration status rows."""
    rows: list[dict[str, str]] = []
    for name, (config_dir, config_file) in get_client_configs(selected_clients).items():
        config_path = os.path.join(config_dir, config_file)
        if os.path.exists(config_path):
            status = "configured" if _has_server_entry(config_path, name) else "config file found"
        elif os.path.exists(config_dir):
            status = "client detected"
        else:
            status = "not detected"
        rows.append({"name": name, "status": status, "detail": status, "path": config_path})
    return rows


def _build_client_targets_payload(selected_clients: list[str] | None = None) -> dict[str, Any]:
    """Build a machine-readable payload for client detection status."""
    rows = _collect_client_rows(selected_clients)
    summary_order = ("configured", "config file found", "client detected", "not detected")
    return {
        "clients": rows,
        "summary": _summarize_status_rows(rows, summary_order),
    }


def print_client_targets(*, selected_clients: list[str] | None = None, output_format: str = "text") -> None:
    """Print supported client targets and detection status."""
    payload = _build_client_targets_payload(selected_clients)
    rows = cast("list[dict[str, str]]", payload["clients"])
    if output_format == "json":
        print(json.dumps(payload, indent=2))
        return

    _print_title("Wireshark MCP clients")
    _print_rows(rows)

    summary = [f"{count} {status}" for status, count in cast("dict[str, int]", payload["summary"]).items()]
    if summary:
        print()
        print("Summary: " + ", ".join(summary))


def _install_codex_config(config_path: str, *, uninstall: bool) -> bool:
    """Preserve TOML structure/comments and edit only the named server."""
    content = ""
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8-sig") as stream:
            content = stream.read()
    updated = render_update(content, "Codex", action="uninstall" if uninstall else "install", toml=True)
    if updated == content:
        return False
    _write_text_config(config_path, updated, ".toml")
    return True
