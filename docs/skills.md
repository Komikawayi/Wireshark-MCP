# Packet-analysis skills

Two independent skills share evidence standards, not a mandatory double workflow:

- `wireshark-traffic-analysis`: MCP tools, question-driven diagnosis, answerability checks, protocol branches and multi-file handoff.
- `tshark-cli-analysis`: the full native TShark capability surface, versioned option/report/tap catalog, selective reference modules, inventory helper and bounded offline runner.

Canonical files live under `skills/`. Repository Codex discovery uses checked-in relative links under `.agents/skills/`. If Git on Windows materializes links as ordinary files, run the sync command to replace them with real directories. Claude/Copilot mirrors are generated, not another source of truth:

```sh
python scripts/sync_skills.py
python scripts/sync_skills.py --check --require-installed
```

The command only writes this repository's three discovery directories and manifest. It does not modify user-level skills or client MCP configuration. `--check --source-only` validates canonical metadata without claiming client installation; normal `--check` reports missing discovery locations rather than pretending they exist. Restart/refresh the client if its skill list is stale and verify `$wireshark-traffic-analysis` or `$tshark-cli-analysis` is visible.

The Python wheel includes both canonical skills and helpers. Inclusion in site-packages is **not client registration**; use the repository discovery command or install a selected skill folder through your client's supported skill mechanism. There is no claimed public plugin-marketplace publication in this change.

CLI coverage is versioned, not a frozen promise about every future plugin. Normally use the entrypoint task table; consult `references/capability-map.md` for unfamiliar capabilities and the separate `references/option-index.md` for exact option lookups. Recheck with `scripts/tshark_inventory.py --check` on engine/plugin upgrades. Unknown names are reviewable gaps. See [Agent evaluation](agent-evaluation.md) for behavioral gates and their limitations.

## First-install validation

Install the built wheel into a new virtual environment, then select that environment's Python:

```sh
python scripts/check_skill_installation.py --python /absolute/path/to/venv/bin/python --require-engine --output installed-skills.json
```

On Windows use `Scripts/python.exe`. The checker uses `-I` from a temporary working directory to load installed resources, validate both skill trees/references and three disposable discovery layouts, exercise a missing-engine error, and run first offline queries through the native helper and an actually registered MCP tool. Temporary discovery copies are not global installation. This does not refresh a client's UI or demonstrate automatic model skill selection.

Without TShark, omitting `--require-engine` permits resource-only success but explicitly reports `engine_smoke=not_run:missing_tshark`. Keep the flag for full first-use validation. Install Wireshark CLI tools and inspect `wireshark-mcp doctor --format json`; MCP accepts `WIRESHARK_MCP_TSHARK_PATH`, while the native runner accepts an explicit `--tshark` path. The deliberately nonexistent engine path tests recovery, not the machine's actual installation status.

CI runs full installed-engine queries in Linux/Windows integration jobs, and resource/discovery checks in all three package jobs with explicit engine-skip reporting. Configured remote jobs are not evidence that those platforms have already passed.
