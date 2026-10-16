"""Pure, scope-aware configuration edits; callers decide when to persist them."""

from __future__ import annotations

import json
from typing import Any

import tomlkit
from tomlkit.exceptions import ParseError

from ._clients import _OPENCODE_STYLE_CLIENTS, _SPECIAL_JSON_STRUCTURES
from ._config_gen import SERVER_NAME, _generate_opencode_config, generate_mcp_config


def server_path(client: str, *, scope: str = "global", toml: bool = False) -> tuple[str, ...]:
    if toml:
        return ("mcp_servers",)
    if scope == "project" and client in {"VS Code", "VS Code Insiders"}:
        return ("servers",)
    if client in _OPENCODE_STYLE_CLIENTS:
        return ("mcp",)
    return _SPECIAL_JSON_STRUCTURES.get(client, ("mcpServers",))


def server_map(config: dict[str, Any], client: str, *, scope: str = "global", toml: bool = False) -> dict[str, Any]:
    current = config
    for key in server_path(client, scope=scope, toml=toml):
        if key not in current:
            current[key] = {}
        if not isinstance(current[key], dict):
            raise ValueError(f"Expected an object/table at {key}; existing configuration left unchanged")
        current = current[key]
    return current


def parse_toml(content: str) -> tomlkit.TOMLDocument:
    try:
        return tomlkit.parse(content)
    except ParseError as exc:
        raise ValueError("malformed TOML configuration; existing configuration left unchanged") from exc


def has_entry(content: str, client: str, *, scope: str = "global", toml: bool = False) -> bool:
    if toml:
        data = parse_toml(content).unwrap()
    else:
        try:
            data = json.loads(content) if content.strip() else {}
        except ValueError as exc:
            raise ValueError("malformed JSON configuration; existing configuration left unchanged") from exc
        if not isinstance(data, dict):
            raise ValueError("Expected an object at the configuration root")
    return SERVER_NAME in server_map(data, client, scope=scope, toml=toml)


def _launch_entry(existing: Any, client: str) -> dict[str, Any]:
    if existing is not None and not isinstance(existing, dict):
        raise ValueError(f"Expected an object/table for {SERVER_NAME}")
    old = existing or {}
    generated = _generate_opencode_config() if client in _OPENCODE_STYLE_CLIENTS else generate_mcp_config()
    env_key = "environment" if client in _OPENCODE_STYLE_CLIENTS else "env"
    old_env = old.get(env_key, {})
    if not isinstance(old_env, dict):
        raise ValueError(f"Expected an object/table for {SERVER_NAME}.{env_key}")
    # Keep user options (timeouts, enablement, allowed directories, custom env),
    # while replacing the launch/transport fields owned by this local installer.
    entry = {
        key: value
        for key, value in old.items()
        if key not in {"command", "args", "env", "environment", "url", "serverUrl", "headers", "type"}
    }
    entry.update(generated)
    entry[env_key] = {**old_env, **generated.get(env_key, {})}
    return entry


def render_update(content: str, client: str, *, action: str, scope: str = "global", toml: bool = False) -> str:
    document = parse_toml(content) if toml else None
    if document is not None:
        data = document.unwrap()
    else:
        try:
            data = json.loads(content) if content.strip() else {}
        except ValueError as exc:
            raise ValueError("malformed JSON configuration; existing configuration left unchanged") from exc
        if not isinstance(data, dict):
            raise ValueError("Expected an object at the configuration root")
    servers = server_map(data, client, scope=scope, toml=toml)
    present = SERVER_NAME in servers
    if action in {"update", "uninstall"} and not present:
        return content
    if action == "uninstall":
        del servers[SERVER_NAME]
    else:
        entry = _launch_entry(servers.get(SERVER_NAME), client)
        if servers.get(SERVER_NAME) == entry:
            return content
        servers[SERVER_NAME] = entry
    if document is not None:
        tables = document.setdefault("mcp_servers", tomlkit.table())
        if action == "uninstall":
            del tables[SERVER_NAME]
        else:
            tables[SERVER_NAME] = servers[SERVER_NAME]
        result = tomlkit.dumps(document)
        parse_toml(result)
        return result
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
