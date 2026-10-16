"""Plan and apply client configuration changes with per-file recovery copies."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from ._config_edit import has_entry, render_update
from ._writer import _write_text_config


def configure_clients(
    configs: dict[str, tuple[str, str]],
    *,
    action: str,
    scope: str,
    dry_run: bool,
    project_dir: str | None = None,
) -> dict[str, Any]:
    if action not in {"install", "update", "uninstall"}:
        raise ValueError(f"Unknown action: {action}")
    rows: list[dict[str, Any]] = []
    paths: dict[Path, str] = {}
    root = Path(project_dir or os.getcwd()).resolve() if scope == "project" else None
    for name, (directory, filename) in configs.items():
        path = Path(directory) / filename
        row: dict[str, Any] = {"name": name, "path": str(path), "status": "error", "backup_path": None}
        rows.append(row)
        try:
            resolved = path.resolve()
            if root is not None and not resolved.is_relative_to(root):
                raise ValueError("Project configuration resolves outside the selected project")
            if resolved in paths:
                row.update(status="shared_target", detail=f"same configuration as {paths[resolved]}")
                continue
            paths[resolved] = name
            if path.is_symlink():
                raise ValueError("Configuration is a symlink; manage its target explicitly")
            if not path.parent.is_dir() and scope == "global":
                row.update(status="not_detected", detail="config dir not found")
                continue
            before = path.read_bytes() if path.exists() else None
            content = before.decode("utf-8-sig") if before is not None else ""
            present = has_entry(content, name, scope=scope, toml=path.suffix == ".toml")
            if action in {"update", "uninstall"} and not present:
                row.update(status="not_installed", detail="not installed")
                continue
            updated = render_update(content, name, action=action, scope=scope, toml=path.suffix == ".toml")
            if updated == content:
                row.update(status="unchanged", detail="already configured")
                continue
            if dry_run:
                row.update(status="planned", detail=f"would {action}", backup_required=before is not None)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            current = path.read_bytes() if path.exists() else None
            if current != before or path.is_symlink():
                raise ValueError("Configuration changed since preflight; rerun the command")
            if before is not None:
                fd, backup = tempfile.mkstemp(prefix=path.name + ".wireshark-mcp-", suffix=".bak", dir=path.parent)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(before)
                row["backup_path"] = backup
            _write_text_config(str(path), updated, path.suffix)
            row.update(
                status={"install": "installed", "update": "updated", "uninstall": "uninstalled"}[action],
                detail="restart client to reload configuration",
            )
        except (OSError, ValueError) as exc:
            row.update(status="error", detail=str(exc))
    errors = sum(row["status"] == "error" for row in rows)
    changed = sum(row["status"] in {"installed", "updated", "uninstalled"} for row in rows)
    planned = sum(row["status"] == "planned" for row in rows)
    return {
        "action": action,
        "scope": scope,
        "dry_run": dry_run,
        "status": "failed" if errors else "preview" if dry_run else "completed",
        "clients": rows,
        "summary": {
            "changed": changed,
            "planned": planned,
            "errors": errors,
            "skipped": len(rows) - changed - planned - errors,
        },
    }
