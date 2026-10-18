"""Exercise skill contracts, executable examples and actual engine capability coverage."""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from wireshark_mcp.server import _build_server

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "skills/tshark-cli-analysis"
MCP = ROOT / "skills/wireshark-traffic-analysis"


def _module(name: str, file: Path):
    spec = importlib.util.spec_from_file_location(name, file)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INVENTORY = _module("tshark_inventory", CLI / "scripts/tshark_inventory.py")
RUNNER = _module("run_tshark", CLI / "scripts/run_tshark.py")
BATCH = _module("batch_tshark", CLI / "scripts/batch_tshark.py")
AUTOMATION = CLI / "references/automation-and-pipelines.md"


def test_all_skill_reference_links_resolve() -> None:
    for skill in (CLI, MCP):
        for document in skill.rglob("*.md"):
            for target in re.findall(r"\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
                if "://" not in target:
                    assert (document.parent / target.split("#")[0]).exists(), (document, target)


def test_catalog_entries_route_to_existing_guides() -> None:
    catalog = json.loads((CLI / "references/capability-catalog.json").read_text(encoding="utf-8"))
    for kind in ("options", "reports", "statistics"):
        assert catalog[kind]
        for name, guide in catalog[kind].items():
            assert (CLI / "references" / guide).is_file(), (name, guide)
    # Manual-only controls are not discoverable from --help on this build.
    assert {"-A", "--print-timers"} <= catalog["options"].keys()
    assert len(catalog["reports"]) >= 18
    assert len(catalog["statistics"]) >= 190


def test_inventory_parser_and_future_gap_detection() -> None:
    assert INVENTORY.parse_options("  -r <file>, --read-file <file>  input\nExample -w out\n") == ["--read-file", "-r"]
    assert INVENTORY.parse_reports("  -G fields[,[<prefix>]]  fields\n") == ["fields"]
    assert INVENTORY.parse_statistics("tshark: diagnostic\n     follow,tcp\n     io,stat\n") == [
        "follow,tcp",
        "io,stat",
    ]
    gaps = INVENTORY.coverage(
        {"options": ["--future"], "reports": ["future"], "statistics": ["future,tree"]},
        {"options": {}, "reports": {}, "statistics": {}},
    )
    assert all(gaps.values())


def test_mcp_example_calls_match_actual_schemas() -> None:
    app = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    schemas = {tool.name: tool.input_schema for tool in asyncio.run(app.list_tools())}
    lines = (MCP / "references/query-patterns.md").read_text(encoding="utf-8").splitlines()
    count = 0
    for line in lines:
        if not line.startswith("wireshark_"):
            continue
        call = ast.parse(line, mode="eval").body
        assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        schema = schemas[call.func.id]
        kwargs = {kw.arg: ast.literal_eval(kw.value) for kw in call.keywords}
        assert set(schema.get("required", [])) <= kwargs.keys(), line
        assert kwargs.keys() <= schema["properties"].keys(), line
        for key, value in kwargs.items():
            prop = schema["properties"][key]
            if "enum" in prop:
                assert value in prop["enum"]
            if prop.get("type") == "string":
                assert isinstance(value, str)
        count += 1
    assert count >= 6


def test_bounded_runner_reaps_and_caps_outputs() -> None:
    out, err = io.BytesIO(), io.BytesIO()
    r = RUNNER.run_bounded(
        [sys.executable, "-c", "import sys;sys.stdout.write('x'*200000)"], out, err, timeout=5, budget=1024
    )
    assert r["status"] == "output_limit"
    assert len(out.getvalue()) + len(err.getvalue()) <= 1024
    assert isinstance(r["returncode"], int)
    r = RUNNER.run_bounded(
        [sys.executable, "-c", "import time;time.sleep(5)"], io.BytesIO(), io.BytesIO(), timeout=0.05, budget=1024
    )
    assert r["status"] == "timeout"
    assert isinstance(r["returncode"], int)


@pytest.mark.parametrize(
    "args", [["-wout.pcap"], ["--export-objects=http,out"], ["-i", "en0"], ["-Xlua_script:packet.lua"]]
)
def test_runner_separates_unbudgeted_side_effects(args: list[str]) -> None:
    with pytest.raises(ValueError):
        RUNNER.validate_args(args)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires installed tshark")
def test_installed_tshark_capabilities_have_documented_routes() -> None:
    inventory = INVENTORY.collect(shutil.which("tshark"))
    catalog = json.loads((CLI / "references/capability-catalog.json").read_text(encoding="utf-8"))
    # A different release may add names. Make them explicit in a failing gate.
    gaps = INVENTORY.coverage(inventory, catalog)
    assert not any(gaps.values()), gaps


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires installed tshark")
def test_real_cli_count_json_and_bounded_record(tmp_path: Path) -> None:
    spec = _module("fixtures", ROOT / "tests/fixtures/generate_pcaps.py")
    capture = spec.build_all_fixtures(tmp_path)["dns_tunnel"]
    command = [shutil.which("tshark"), "-n", "-r", str(capture)]
    result = subprocess.run(
        [*command, "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        check=True,
        timeout=15,
    )
    assert len(result.stdout.splitlines()) == 27
    data = subprocess.run(
        [*command, "-c", "1", "-T", "json", "--no-duplicate-keys"], capture_output=True, check=True, timeout=15
    )
    assert len(json.loads(data.stdout)) == 1
    destination = tmp_path / "run"
    assert (
        RUNNER.main(
            [
                "--input",
                str(capture),
                "--output-dir",
                str(destination),
                "--",
                "-Y",
                "dns.flags.response == 0",
                "-T",
                "fields",
                "-e",
                "frame.number",
            ]
        )
        == 0
    )
    record = json.loads((destination / "execution.json").read_text(encoding="utf-8"))
    assert record["coverage"]["status"] == "complete"
    assert not record["input_changed"]
    assert len((destination / "stdout.bin").read_bytes().splitlines()) == 27
    assert len(record["input"]["sha256"]) == 64


@pytest.mark.parametrize("args", [["--help"], ["-G", "fields"], ["--hexdump", "help"]])
def test_runner_does_not_label_discovery_as_capture_scan(args: list[str]) -> None:
    with pytest.raises(ValueError):
        RUNNER.validate_args(args)


def test_wheel_validator_rejects_a_missing_skill_resource(tmp_path: Path, monkeypatch) -> None:
    from zipfile import ZipFile

    checker = _module("check_skill_package", ROOT / "scripts/check_skill_package.py")
    source = tmp_path / "skills/example"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text("a skill", encoding="utf-8")
    (source / "helper.py").write_text("print('helper')", encoding="utf-8")
    manifest = tmp_path / "skills/manifest.json"
    manifest.write_text(json.dumps({"skills": [{"name": "example"}]}), encoding="utf-8")
    monkeypatch.setattr(checker, "ROOT", tmp_path)
    wheel = tmp_path / "test.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("wireshark_mcp/skills/manifest.json", manifest.read_bytes())
        archive.writestr("wireshark_mcp/skills/example/SKILL.md", "a skill")
    with pytest.raises(ValueError, match="helper.py"):
        checker.check(wheel)


def test_every_catalog_option_has_execution_guidance() -> None:
    catalog = json.loads((CLI / "references/capability-catalog.json").read_text(encoding="utf-8"))
    for option, guide in catalog["options"].items():
        assert option in (CLI / "references" / guide).read_text(encoding="utf-8"), (option, guide)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires installed tshark")
def test_real_documented_statistics_filters_formats_and_derived_file(tmp_path: Path) -> None:
    fixture = _module("fixtures_more", ROOT / "tests/fixtures/generate_pcaps.py").build_all_fixtures(tmp_path)
    source = fixture["dns_tunnel"]
    command = [shutil.which("tshark"), "-n", "-r", str(source)]

    def execute(*args: str):
        return subprocess.run([*command, *args], capture_output=True, check=True, timeout=15)

    for mode in ("fields", "json", "jsonraw", "ek", "pdml", "psml", "ps", "tabs", "text"):
        args = ["-c", "1", "-T", mode]
        if mode == "fields":
            args += ["-e", "frame.number"]
        assert execute(*args).stdout
    for statistic in ("io,phs", "endpoints,ip", "conv,udp", "expert", "follow,udp,ascii,0"):
        assert execute("-q", "-z", statistic).stdout
    # -Y only changes ordinary packet output, not an independently filtered tap.
    unscoped = execute("-Y", "frame.number == 1", "-q", "-z", "io,stat,0").stdout.decode()
    scoped = execute("-q", "-z", "io,stat,0,frame.number == 1").stdout.decode()
    assert re.search(r"\|\s+27\s+\|", unscoped)
    assert re.search(r"\|\s+1\s+\|", scoped)
    derived = tmp_path / "one-frame.pcapng"
    original = source.read_bytes()
    execute("-Y", "frame.number == 1", "-w", str(derived), "-F", "pcapng")
    reopened = subprocess.run(
        [shutil.which("tshark"), "-n", "-r", str(derived), "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        check=True,
        timeout=15,
    )
    assert reopened.stdout.splitlines() == [b"1"]
    assert source.read_bytes() == original


def test_unfamiliar_plugin_names_are_not_silently_dropped() -> None:
    assert INVENTORY.parse_statistics("     VendorX,latency.v2\n") == ["VendorX,latency.v2"]
    assert INVENTORY.parse_reports("  -G VendorReport2  extra data\n") == ["VendorReport2"]


def _shell_blocks(document: Path) -> list[str]:
    return re.findall(r"```sh\n(.*?)```", document.read_text(encoding="utf-8"), flags=re.S)


def _bash_available() -> bool:
    # On Windows runners `bash` can resolve to the WSL launcher with no distribution installed.
    bash = shutil.which("bash")
    if bash is None:
        return False
    try:
        probe = subprocess.run([bash, "-c", "true"], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


@pytest.mark.skipif(not _bash_available(), reason="requires a working bash")
def test_automation_guide_shell_examples_parse_and_disable_name_resolution() -> None:
    blocks = _shell_blocks(AUTOMATION)
    assert len(blocks) >= 8
    for block in blocks:
        checked = subprocess.run(["bash", "-n"], input=block, capture_output=True, text=True, timeout=10)
        assert checked.returncode == 0, (block, checked.stderr)
        for line in block.splitlines():
            if re.match(r"\s*tshark ", line):
                assert " -n " in line, line
    assert "set -o pipefail" in blocks[0] and "PIPESTATUS" in blocks[0]


def _fake_tshark(tmp_path: Path) -> str:
    # Emits one row per call and fails for inputs whose name contains "bad".
    script = tmp_path / "fake-tshark"
    script.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "path = sys.argv[sys.argv.index('-r') + 1]\n"
        "if 'bad' in path:\n"
        "    sys.stderr.write('tshark: unreadable\\n'); sys.exit(2)\n"
        "print('1')\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return str(script)


@pytest.mark.skipif(sys.platform == "win32", reason="fake engine uses a shebang script")
def test_batch_helper_records_each_input_and_summarizes_coverage(tmp_path: Path) -> None:
    for directory in ("a", "b"):
        (tmp_path / "in" / directory).mkdir(parents=True)
        (tmp_path / "in" / directory / "same.pcap").write_bytes(b"capture-" + directory.encode())
    (tmp_path / "in" / "bad.pcap").write_bytes(b"broken")
    (tmp_path / "in" / "notes.txt").write_text("not selected", encoding="utf-8")
    destination = tmp_path / "batch"
    code = BATCH.main(
        [
            "--input-dir",
            str(tmp_path / "in"),
            "--recursive",
            "--output-dir",
            str(destination),
            "--tshark",
            _fake_tshark(tmp_path),
            "--jobs",
            "2",
            "--",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]
    )
    assert code == 1
    batch = json.loads((destination / "batch.json").read_text(encoding="utf-8"))
    assert batch["counts"] == {"inputs": 3, "complete": 2, "partial": 0, "error": 1}
    runs = {Path(run["input"]).relative_to((tmp_path / "in").resolve()).as_posix(): run for run in batch["runs"]}
    assert set(runs) == {"a/same.pcap", "b/same.pcap", "bad.pcap"}
    assert runs["bad.pcap"]["status"] == "error" and runs["bad.pcap"]["returncode"] == 2
    assert len({run["run_dir"] for run in runs.values()}) == 3
    for name in ("a/same.pcap", "b/same.pcap"):
        assert Path(runs[name]["stdout"]).read_bytes() == b"1\n"
        record = json.loads(Path(runs[name]["record"]).read_text(encoding="utf-8"))
        assert record["coverage"]["status"] == "complete" and len(record["input"]["sha256"]) == 64
    rows = (destination / "summary.tsv").read_text(encoding="utf-8").splitlines()
    assert rows[0].split("\t") == ["index", "coverage", "status", "returncode", "sha256", "input"]
    assert len(rows) == 4


@pytest.mark.parametrize("args", [["-w", "out.pcap"], ["-i", "en0"], ["--export-objects=http,out"]])
def test_batch_helper_rejects_side_effects_before_creating_output(tmp_path: Path, args: list[str]) -> None:
    capture = tmp_path / "one.pcap"
    capture.write_bytes(b"x")
    with pytest.raises(SystemExit) as exit_info:
        BATCH.main(["--input", str(capture), "--output-dir", str(tmp_path / "out"), "--", *args])
    assert exit_info.value.code == 2
    assert not (tmp_path / "out").exists()


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires installed tshark")
def test_real_batch_and_pipefail_pipeline(tmp_path: Path) -> None:
    fixtures = _module("fixtures_batch", ROOT / "tests/fixtures/generate_pcaps.py").build_all_fixtures(tmp_path / "in")
    capture = fixtures["dns_tunnel"]
    destination = tmp_path / "batch"
    assert (
        BATCH.main(
            [
                "--input",
                str(capture),
                "--input",
                str(capture),
                "--output-dir",
                str(destination),
                "--tshark",
                shutil.which("tshark"),
                "--",
                "-Y",
                "dns.flags.response == 0",
                "-T",
                "fields",
                "-e",
                "frame.number",
            ]
        )
        == 0
    )
    batch = json.loads((destination / "batch.json").read_text(encoding="utf-8"))
    assert batch["counts"]["inputs"] == 1 and batch["counts"]["complete"] == 1
    assert len(Path(batch["runs"][0]["stdout"]).read_bytes().splitlines()) == 27
    if shutil.which("bash") is None:
        return
    # The guide's first pipeline: per-name counts must add up to the full query count.
    pipeline = (
        "set -o pipefail; tshark -n -r \"$1\" -Y 'dns.flags.response == 0' -T fields -e dns.qry.name "
        "| LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn"
    )
    result = subprocess.run(
        ["bash", "-c", pipeline, "pipeline", str(capture)], capture_output=True, text=True, check=True, timeout=15
    )
    assert sum(int(line.split()[0]) for line in result.stdout.splitlines()) == 27
