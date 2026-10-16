# Release Checklist

Use this checklist before publishing a release from the active `3.x` line.

## Version Sync

Update these files together:

- `pyproject.toml`
- `src/wireshark_mcp/__init__.py`
- `server.json`
- `.well-known/mcp/server.json`
- `changelog/<version>.md` and the root `CHANGELOG.md` index
- `SECURITY.md` if the supported major line changes

Also confirm that compatibility notes still match reality:

- legacy CLI flags are still documented correctly
- deprecated tools retained for compatibility are still explicitly marked as deprecated

## Validation Commands

Run the full local validation set:

```sh
uv run python -m ruff check src/ tests/
uv run python -m mypy --package wireshark_mcp --ignore-missing-imports --no-namespace-packages
uv run python -m pytest
uv export --frozen --no-dev --no-emit-project --format requirements-txt | uvx pip-audit -r /dev/stdin --disable-pip
uvx bandit -q -r src
uvx zizmor --pedantic --min-severity low .
uv build
uv run wireshark-mcp --help
uv run wireshark-mcp doctor
uv run wireshark-mcp doctor --format json
uv run wireshark-mcp clients
uv run wireshark-mcp clients --format json
uv run wireshark-mcp config
```

Build only after the final source change. Compare packaged Python files with `src/wireshark_mcp`, then install that exact wheel into a fresh environment. The installed wheel must pass `--version`, `python -m wireshark_mcp --version`, JSON doctor output, and the `2026-07-28` stateless `server/discover` → `tools/list` → `tools/call` sequence without an MCP session ID.

If Codex support matters for the release, also run:

```sh
uv run wireshark-mcp config --format codex-toml
```

## Documentation Checks

Before release, confirm:

- `README.md` and `README_zh.md` describe the current install path
- `docs/README.md` and `docs/README_zh.md` contain no broken local links
- every documented CLI option appears in `wireshark-mcp <command> --help`
- every documented `wireshark_*` name exists in the selected public tool profile
- `docs/aggregation.md` and `docs/aggregation_zh.md` match the current limits and result fields
- platform validation docs still match the CLI behavior
- the numbered changelog explains user-visible changes from `changelog/unreleased.md`
- `ROADMAP.md` and `ROADMAP_zh.md` reflect any completed or rescheduled work

## Skill Gates

Validate source, discoverability, packaged resources and behavior separately:

```sh
python scripts/sync_skills.py
python scripts/sync_skills.py --check --require-installed
python skills/tshark-cli-analysis/scripts/tshark_inventory.py --output new-inventory.json --check
python scripts/check_skill_package.py dist/wireshark_mcp-<version>-py3-none-any.whl
python scripts/check_skill_installation.py --python /absolute/path/to/clean/venv/python --require-engine --output installed-skills.json
```

Review every newly discovered option/report/tap against the installed/official
manual before updating the capability catalog. The wheel must contain both skill
entrypoints, every referenced guide, UI metadata and executable helper source;
bytecode caches are not distributed. Run actual offline format/statistic/export
smokes and budget recovery tests. Live/remote capture, hardware-specific and
key-dependent features need appropriate separate environments, not fabricated
sign-off from an offline fixture. Independent Agent traces are required before
publishing behavior/cost improvements. Require a complete repeated matrix with
`scripts/check_agent_matrix.py` before interpreting a full comparison; prepared
blind tasks are not executed results. See [Agent evaluation](agent-evaluation.md).

## Cross-Platform Sign-Off

Use [platform-validation.md](platform-validation.md) to confirm at least one manual validation pass on:

- macOS
- Linux
- Windows

## Publish

1. Push the release commit.
2. Tag the release.
3. Let GitHub Actions build and publish the package.
4. Confirm the published package version matches both registry metadata files.

## Post-Publish Checks

After publication, confirm:

- PyPI shows the expected version
- the packaged wheel contains the bundled skill files
- `wireshark-mcp --version` matches the tagged release
- `server.json` and `.well-known/mcp/server.json` match the release version
- a clean installation can call `wireshark_open_file`, `wireshark_aggregate`, and one packet-level verification tool

## Client plugin distribution

Keep both plugin manifest versions aligned with the Python package. Validate
`scripts/check_plugin_package.py`, build a clean source ZIP, and cold-start both
launchers with `scripts/smoke_plugin_runtime.py`. Test native client
marketplace/install/list/remove in isolated configuration directories. Check
that fresh uv environments contain no dev dependencies, stdio is clean, and
skills/resources resolve without a developer checkout or venv.

Commit/publish the repo manifests before advertising the GitHub marketplace
commands as available. Repository marketplaces, release ZIPs and universal public
directory approval are distinct deliverables. Never infer GUI-session success
from manifest parsing alone.
