"""Guard test: every tool name cited in prose must resolve to a registered tool.

Prompts, resources, and the shipped skill files tell the model which tools to call.
A name in that text that the server does not register is a dead end the model cannot
detect: it reads as an instruction, the call fails, and nothing in the codebase links
the prose back to the tool that was renamed or folded away.

This is the ratchet for that class of drift. It fired for real when 21 per-protocol
tools were consolidated into `wireshark_analyze_protocol` — the names survived in five
prompts and two skill documents after the tools were gone.
"""

import re
from pathlib import Path

import pytest

from wireshark_mcp.server import _build_server

REPO_ROOT = Path(__file__).parent.parent

# `wireshark_mcp` is the package and logger name, not a tool.
NON_TOOL_NAMES = {"wireshark_mcp"}

# Prose sources that name tools for the model to call.
PROSE_SOURCES = [
    "src/wireshark_mcp/prompts.py",
    "src/wireshark_mcp/resources.py",
    "src/wireshark_mcp/tools/agents.py",
    ".github/prompts/wireshark-traffic-analysis.prompt.md",
    *[str(path.relative_to(REPO_ROOT)) for path in sorted((REPO_ROOT / "skills").rglob("*.md"))],
]

TOOL_NAME_RE = re.compile(r"\bwireshark_[a-z0-9_]+")


def _registered_tool_names() -> set[str]:
    import asyncio

    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    return {t.name for t in asyncio.run(mcp.list_tools())}


def _cited_names(path: Path) -> set[str]:
    return set(TOOL_NAME_RE.findall(path.read_text(encoding="utf-8"))) - NON_TOOL_NAMES


@pytest.mark.parametrize("source", PROSE_SOURCES)
def test_every_cited_tool_is_registered(source: str) -> None:
    path = REPO_ROOT / source
    assert path.exists(), f"{source} is listed as a prose source but does not exist"

    registered = _registered_tool_names()
    dangling = sorted(_cited_names(path) - registered)
    assert not dangling, f"{source} names tools the server does not register: {dangling}"


def test_prose_sources_actually_cite_tools() -> None:
    """A typo in a path above would make the check vacuous, so prove it reads something."""
    total = sum(len(_cited_names(REPO_ROOT / s)) for s in PROSE_SOURCES)
    assert total > 20, f"only {total} tool citations found across prose sources; check the paths"


def test_protocol_argument_citations_are_valid() -> None:
    """`protocol="..."` on wireshark_analyze_protocol must name a value the tool accepts."""
    from wireshark_mcp.tools.analyze import supported_protocols

    # Scoped to this tool: other tools (stats_service_response_time, export_objects)
    # take an unrelated `protocol` argument whose values are tshark facility names.
    call_re = re.compile(r'wireshark_analyze_protocol\([^)]*protocol="([a-z0-9_]+)"')

    known = set(supported_protocols())
    bad: list[str] = []
    found = 0
    for source in PROSE_SOURCES:
        text = (REPO_ROOT / source).read_text(encoding="utf-8")
        for value in call_re.findall(text):
            found += 1
            if value not in known:
                bad.append(f"{source}: {value}")
    assert not bad, f"prose cites unsupported protocol values: {sorted(bad)}"
    assert found, "no wireshark_analyze_protocol calls found in prose; check the regex"
