"""A generic subprocess failure is not evidence of a truncated capture."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from wireshark_mcp.tshark.client import TSharkClient


def _process(code: int, diagnostic: str) -> SimpleNamespace:
    stdout, stderr = asyncio.StreamReader(), asyncio.StreamReader()
    stdout.feed_data(b'frame.number\n"1"\n')
    stdout.feed_eof()
    stderr.feed_data(diagnostic.encode())
    stderr.feed_eof()
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr, wait=AsyncMock(), kill=Mock())


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "binary,code,diagnostic,success",
    [
        ("tshark", 14, "capture cut short", True),
        ("tshark", 2, "The file appears to have been cut short in the middle of a packet", True),
        ("tshark.exe", 2, "capture cut short", True),
        ("tshark", 2, "The file appears to be damaged or corrupt", False),
        ("tshark", 1, "invalid field", False),
        ("editcap", 2, "write failed", False),
        ("capinfos", 14, "read failed", False),
    ],
)
async def test_only_tshark_short_reads_are_downgraded(monkeypatch, streaming, binary, code, diagnostic, success):
    monkeypatch.setattr("asyncio.create_subprocess_exec", AsyncMock(return_value=_process(code, diagnostic)))
    client = TSharkClient()
    if streaming:
        result = await client._stream_field_rows([binary], lambda _row: None, max_rows=20)
    else:
        result = json.loads(await client._run_command([binary]))
    assert result["success"] is success
    if success:
        assert result["stderr"] == diagnostic
    else:
        assert result["error"]["type"] == "ExecutionError"


@pytest.mark.asyncio
async def test_partial_capture_output_is_not_cached_without_warning(monkeypatch, tmp_path):
    async def execute(*_args, **_kwargs):
        return _process(14, "capture cut short")

    execute_mock = AsyncMock(side_effect=execute)
    monkeypatch.setattr("asyncio.create_subprocess_exec", execute_mock)
    pcap = tmp_path / "partial.pcap"
    pcap.write_bytes(b"fixture")
    client = TSharkClient()
    first = json.loads(await client._run_command(["tshark", "-r", str(pcap)]))
    second = json.loads(await client._run_command(["tshark", "-r", str(pcap)]))
    assert first["stderr"] == second["stderr"] == "capture cut short"
    assert execute_mock.await_count == 2
