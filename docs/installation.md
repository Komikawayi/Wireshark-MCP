# Install, update and uninstall

Package installation and client registration are separate steps. A written configuration is not proof of a connected server; restart/refresh the client and check dependencies with `wireshark-mcp doctor`.

```sh
pip install wireshark-mcp
wireshark-mcp install                    # interactive selection
wireshark-mcp install --client cursor    # explicit target, global by default
```

## Project scope

```sh
wireshark-mcp install --client codex --scope project --dry-run
wireshark-mcp install --client codex --scope project
wireshark-mcp install --client cursor --scope project --project-dir /absolute/project
```

The project directory must exist; the default is the current working directory. Only an actual install creates client subdirectories. Previewing or updating/removing an absent entry creates none.

| Client | Project path | Server key |
|---|---|---|
| Claude Code | `.mcp.json` | `mcpServers` |
| Cursor | `.cursor/mcp.json` | `mcpServers` |
| Codex | `.codex/config.toml` | `mcp_servers` |
| VS Code / Insiders | `.vscode/mcp.json` | top-level `servers`, not global settings.json's `mcp.servers` |

Unsupported scope/client combinations fail rather than falling back to global configuration. VS Code and Insiders share one project file and write it only once. Out-of-project resolved paths and symlinked configuration files are left unchanged with an error.

Codex loads project settings only for trusted projects; the installer does not modify trust settings. See [official configuration documentation](https://learn.chatgpt.com/docs/config-file/config-basic). Generated stdio launch settings contain machine-specific Python/tool paths and should not be committed as portable cross-machine templates without review.

## Automation and preview

```sh
wireshark-mcp install --client cursor --client codex --dry-run --format json
wireshark-mcp install --client cursor --client codex --format json
wireshark-mcp install --client all --dry-run --format json
```

Without a TTY, or with JSON output, writes require explicit `--client` targets. `--client all` is an explicit bulk choice. Omission exits 2 rather than modifying every detected client. An untargeted `--dry-run` may preview all candidates without creating configuration files, directories or backups.

JSON contains `action`, `scope`, `dry_run`, per-client `status/path/backup_path`, and `summary.changed/planned/errors/skipped`. Planned changes are not configured clients; `not_detected`/`not_installed` are not connection success. Global actions continue to skip absent client configuration directories.

## Update and remove

```sh
pip install --upgrade wireshark-mcp
wireshark-mcp update --client codex --scope project
wireshark-mcp uninstall --client codex --scope project --dry-run
wireshark-mcp uninstall --client codex --scope project
```

`update` refreshes existing entries only, not absent targets or the Python package. Reinstalling an identical configuration does not rewrite it, refresh mtime or create another backup. Launch fields are refreshed while other servers/settings, custom timeouts and non-conflicting environment variables remain. Uninstall removes this server entry only, not the Python package or Wireshark.

JSON shapes are validated; parsed TOML editing supports quoted table names and preserves unrelated comments, tables and multiline strings. Invalid syntax or object/table shapes produce per-client errors without changing the original bytes.

## Backups and results

Before changing an existing configuration, the installer creates an exclusive same-directory `*.wireshark-mcp-*.bak` containing the original bytes. Results identify that backup path. Backups can contain credentials from the original config: retain them accordingly. They are not automatically deleted.

To restore, first check for later edits that must be retained, then copy the corresponding backup over the result's `path`. This restores the entire file, not just this server entry. New configurations have no previous-file backup; uninstall leaves the config file and its other content in place.

Each file uses temporary-file atomic replacement. A multi-client operation is not an all-or-nothing transaction; inspect each result/backup after partial failure and retry failed targets.

- Exit 0: processing/preview completed, possibly entirely unchanged/skipped; connectivity is not certified.
- Exit 1: at least one config read, validation or write failed; other clients may have succeeded.
- Exit 2: invalid parameters, selection or scope, before bulk configuration starts.

## Reference and plugin distribution

Client selection and scoped installation draw on the pinned [ida-pro-mcp installer](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/installer.py). The parallel [plugin distribution route](plugin-installation.md) now bundles this project and both skills; use one registration route per client. Local verification is separate from remote publication.
