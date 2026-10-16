"""Installation CLI selection, application and result reporting."""

from __future__ import annotations

import json
import sys
from typing import Any

from ._clients import get_client_configs
from ._config_gen import print_mcp_config
from ._detection import _detect_wireshark_tool_paths
from ._doctor import print_install_doctor
from ._lifecycle import configure_clients
from ._tui import _interactive_select_clients
from ._writer import _print_rows, _print_title, print_client_targets


def _install_report(
    *,
    uninstall: bool,
    update: bool,
    selected_clients: list[str] | None,
    scope: str,
    project_dir: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    if uninstall and update:
        raise ValueError("Choose update or uninstall, not both")
    if selected_clients:
        configs = get_client_configs(selected_clients, scope=scope, project_dir=project_dir)
    else:
        all_configs = get_client_configs(scope=scope, project_dir=project_dir)
        chosen = None if dry_run else _interactive_select_clients(all_configs)
        configs = all_configs if chosen is None else {name: all_configs[name] for name in chosen}
    report = configure_clients(
        configs,
        action="uninstall" if uninstall else "update" if update else "install",
        scope=scope,
        project_dir=project_dir,
        dry_run=dry_run,
    )
    report["warnings"] = []
    if not uninstall and not _detect_wireshark_tool_paths()["WIRESHARK_MCP_TSHARK_PATH"]:
        report["warnings"].append("tshark not found; run wireshark-mcp doctor after installing Wireshark CLI tools")
    if scope == "project" and any(row["name"] == "Codex" for row in report["clients"]):
        report["notes"] = [
            "Codex loads project configuration only for trusted projects; trust settings were not modified"
        ]
    return report


def _print_install_report(report: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return
    _print_title(f"Wireshark MCP {report['action']} ({report['scope']})" + (" — preview" if report["dry_run"] else ""))
    for warning in report.get("warnings", []):
        print(f"[WARN] {warning}")
    rows = []
    for row in report["clients"]:
        status = row["status"]
        marker = (
            "[ERROR]"
            if status == "error"
            else "[PLAN]"
            if status == "planned"
            else "[OK]"
            if status in {"installed", "updated", "uninstalled"}
            else "[SKIP]"
        )
        detail = status + ": " + row.get("detail", "")
        if row.get("backup_path"):
            detail += f"; backup: {row['backup_path']}"
        rows.append({"name": row["name"], "marker": marker, "detail": detail, "path": row["path"]})
    _print_rows(rows)
    summary = report["summary"]
    print(
        f"\nSummary: {summary['changed']} changed, {summary['planned']} planned, {summary['errors']} errors, {summary['skipped']} skipped."
    )
    for note in report.get("notes", []):
        print(note)


def install_mcp_servers(
    *,
    uninstall: bool = False,
    update: bool = False,
    selected_clients: list[str] | None = None,
    scope: str = "global",
    project_dir: str | None = None,
    dry_run: bool = False,
    output_format: str = "text",
) -> int:
    """Configure selected clients; return changed count for existing Python callers.

    CLI selection/exit status is handled by run_install. Existing Python callers
    retain default target selection; automated CLI writes require explicit targets.
    """
    report = _install_report(
        uninstall=uninstall,
        update=update,
        selected_clients=selected_clients,
        scope=scope,
        project_dir=project_dir,
        dry_run=dry_run,
    )
    _print_install_report(report, output_format)
    return int(report["summary"]["changed"])


def run_install(
    action: str | None = None,
    *,
    install: bool = False,
    update: bool = False,
    uninstall: bool = False,
    config: bool = False,
    doctor: bool = False,
    list_clients: bool = False,
    selected_clients: list[str] | None = None,
    config_format: str = "json",
    output_format: str = "text",
    scope: str = "global",
    project_dir: str | None = None,
    dry_run: bool = False,
) -> None:
    """Dispatch client management with explicit automation targets and honest exits."""
    flags = {
        "install": install,
        "update": update,
        "uninstall": uninstall,
        "config": config,
        "doctor": doctor,
        "clients": list_clients,
    }
    if action is not None:
        action = "clients" if action == "list_clients" else action
        if action not in flags:
            raise ValueError(f"Unknown action: {action}")
        flags[action] = True
    enabled = [name for name, value in flags.items() if value]
    if len(enabled) != 1:
        print("Choose only one action at a time: install, update, uninstall, config, doctor, or clients.")
        raise SystemExit(1)
    action = enabled[0]
    if action in {"install", "update", "uninstall"}:
        try:
            if not selected_clients and not dry_run and (not sys.stdin.isatty() or output_format == "json"):
                raise ValueError(
                    "Select explicit --client NAME (repeatable), or --client all; use --dry-run to preview"
                )
            report = _install_report(
                uninstall=action == "uninstall",
                update=action == "update",
                selected_clients=selected_clients,
                scope=scope,
                project_dir=project_dir,
                dry_run=dry_run,
            )
        except (OSError, ValueError) as exc:
            if output_format == "json":
                print(
                    json.dumps(
                        {"action": action, "scope": scope, "dry_run": dry_run, "status": "failed", "error": str(exc)}
                    )
                )
            else:
                print(str(exc))
            raise SystemExit(2) from exc
        _print_install_report(report, output_format)
        if report["summary"]["errors"]:
            raise SystemExit(1)
    elif action == "config":
        print_mcp_config(output_format=config_format)
    elif action == "doctor":
        print_install_doctor(selected_clients=selected_clients, output_format=output_format)
    else:
        print_client_targets(selected_clients=selected_clients, output_format=output_format)
