"""Regression cases for BLE negotiation and capture-local connection isolation."""

from unittest.mock import AsyncMock

import pytest

from wireshark_mcp.tools.bluetooth import _infer_pairing_method, make_ble_protocol_handlers
from wireshark_mcp.tools.envelope import parse_tool_result, success_response


def _pair(io: int, *, mitm: bool = True, sc: bool = False, oob: bool = False) -> dict[str, str]:
    return {"io_capability": f"0x{io:02x}", "mitm": str(mitm), "sc": str(sc), "oob": f"0x{int(oob):02x}"}


@pytest.mark.parametrize("initiator_mitm,responder_mitm", [(True, False), (False, True)])
def test_pairing_one_sided_mitm_still_uses_authenticated_method(initiator_mitm: bool, responder_mitm: bool) -> None:
    result = _infer_pairing_method(_pair(2, mitm=initiator_mitm), _pair(0, mitm=responder_mitm))
    assert result[0] == "Passkey Entry"


@pytest.mark.parametrize("initiator_sc,responder_sc", [(True, False), (False, True)])
def test_pairing_one_sided_sc_falls_back_to_legacy(initiator_sc: bool, responder_sc: bool) -> None:
    result = _infer_pairing_method(_pair(1, sc=initiator_sc), _pair(1, sc=responder_sc))
    assert result[0] == "Just Works"


@pytest.mark.parametrize("sc", [False, True])
@pytest.mark.parametrize("io_req", range(5))
@pytest.mark.parametrize("io_rsp", range(5))
def test_pairing_io_capability_matrix(sc: bool, io_req: int, io_rsp: int) -> None:
    # Core Vol 3 Part H, Table 2.8. Both devices request MITM here.
    legacy = [
        ["J", "J", "P", "J", "P"],
        ["J", "J", "P", "J", "P"],
        ["P", "P", "P", "J", "P"],
        ["J", "J", "J", "J", "J"],
        ["P", "P", "P", "J", "P"],
    ]
    expected = legacy[io_req][io_rsp]
    if sc and io_req in (1, 4) and io_rsp in (1, 4):
        expected = "N"
    names = {"J": "Just Works", "P": "Passkey Entry", "N": "Numeric Comparison"}
    assert _infer_pairing_method(_pair(io_req, sc=sc), _pair(io_rsp, sc=sc))[0] == names[expected]


@pytest.mark.parametrize("sc", [False, True])
@pytest.mark.parametrize("oob_req,oob_rsp", [(True, False), (False, True), (True, True)])
def test_pairing_oob_depends_on_negotiated_sc(sc: bool, oob_req: bool, oob_rsp: bool) -> None:
    method, _ = _infer_pairing_method(_pair(3, sc=sc, oob=oob_req), _pair(3, sc=sc, oob=oob_rsp))
    assert method == ("OOB" if sc or (oob_req and oob_rsp) else "Just Works")


def _connection(
    frame: int,
    time: float,
    *,
    disconnect: bool = False,
    update: bool = False,
    handle: str = "0x000c",
    interface: str = "0",
    status: str = "0x00",
) -> str:
    fields = [""] * 21
    fields[:5] = [str(frame), str(time), "0x05" if disconnect else "0x3e", "0x03" if update else "0x01", handle]
    fields[5], fields[7], fields[9], fields[10] = "11:22:33:44:55:66", "24", "72", status
    fields[11], fields[20] = "0x13" if disconnect else "", interface
    return "\t".join(fields)


async def _analyze(name: str, rows: list[str]) -> dict:
    client = AsyncMock()
    client.extract_fields.return_value = success_response("\n".join(rows))
    return parse_tool_result(await make_ble_protocol_handlers(client)[name]("fixture.pcap"))


@pytest.mark.asyncio
async def test_connections_reused_handle_keeps_closed_and_open_sessions_separate() -> None:
    parsed = await _analyze(
        "ble_connections",
        [
            _connection(1, 0),
            _connection(2, 1, update=True),
            _connection(3, 2, disconnect=True),
            _connection(4, 3),
        ],
    )
    first, second = parsed["data"]["connections"]
    assert first["session_duration_s"] == 2
    assert len(first["parameter_updates"]) == 1
    assert second["connect"]["frame"] == 4
    assert second["disconnect"] is None
    assert second["session_duration_s"] is None
    assert second["parameter_updates"] == []


@pytest.mark.asyncio
async def test_connections_reused_handle_keeps_two_durations() -> None:
    parsed = await _analyze(
        "ble_connections",
        [
            _connection(1, 0),
            _connection(2, 2, disconnect=True),
            _connection(3, 3),
            _connection(4, 8, disconnect=True),
        ],
    )
    assert [s["session_duration_s"] for s in parsed["data"]["connections"]] == [2, 5]
    assert parsed["coverage"]["sessions"] == 2


@pytest.mark.asyncio
async def test_connections_same_handle_on_two_interfaces() -> None:
    parsed = await _analyze(
        "ble_connections",
        [
            _connection(1, 0, interface="0"),
            _connection(2, 1, interface="1"),
            _connection(3, 4, interface="0", disconnect=True),
        ],
    )
    first, second = parsed["data"]["connections"]
    assert first["interface_id"] == "0"
    assert second["interface_id"] == "1"
    assert first["session_duration_s"] == 4
    assert second["disconnect"] is None


@pytest.mark.asyncio
async def test_failed_connection_attempt_does_not_replace_active_session() -> None:
    parsed = await _analyze(
        "ble_connections",
        [
            _connection(1, 0),
            _connection(2, 1, status="0x3e"),
            _connection(3, 4, disconnect=True),
        ],
    )
    first, failure = parsed["data"]["connections"]
    assert first["connect"]["frame"] == 1
    assert first["session_duration_s"] == 4
    assert failure["connect"]["status"] == "0x3e"
    assert failure["disconnect"] is None


def _gatt(
    frame: int,
    opcode: str,
    *,
    handle: str = "0x0002",
    uuid: str = "",
    end: str = "",
    connection: str = "0x000c",
    connected: str = "1",
    interface: str = "0",
    aa: str = "",
    src: str = "",
    dst: str = "",
    direction: str = "",
    value: str = "",
) -> str:
    fields = [str(frame), str(frame / 10), opcode, handle, value, "", "0x0004", end, uuid, "", "", ""]
    return "\t".join([*fields, interface, connection, connected, aa, src, dst, direction])


@pytest.mark.asyncio
async def test_gatt_labels_and_services_are_isolated_by_connection() -> None:
    parsed = await _analyze(
        "ble_gatt_timeline",
        [
            _gatt(1, "0x11", uuid="0x1800", end="0xffff"),
            _gatt(2, "0x05", uuid="0x2a00"),
            _gatt(3, "0x11", uuid="0x180f", end="0xffff", connection="0x000d"),
            _gatt(4, "0x05", uuid="0x2a19", connection="0x000d"),
            _gatt(5, "0x1b"),
            _gatt(6, "0x1b", connection="0x000d"),
        ],
    )
    first, second = parsed["data"]["timeline"][-2:]
    assert first["attribute"] == "Device Name (0x2a00)"
    assert first["service"] == "Generic Access (0x1800)"
    assert second["attribute"] == "Battery Level (0x2a19)"
    assert second["service"] == "Battery (0x180f)"
    assert first["connection"] != second["connection"]
    assert parsed["data"]["handle_map"] == {}  # no misleading global handle namespace
    assert len(parsed["data"]["handle_maps"]) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("difference", ["connected", "interface", "aa"])
async def test_gatt_isolates_reconnect_interfaces_and_air_links(difference: str) -> None:
    other = {"connected": "9"} if difference == "connected" else {"interface": "1"}
    base = {}
    if difference == "aa":
        base = {"connection": "", "connected": "", "aa": "0x12345678"}
        other = {"connection": "", "connected": "", "aa": "0x87654321"}
    parsed = await _analyze(
        "ble_gatt_timeline",
        [
            _gatt(1, "0x05", uuid="0x2a00", **base),
            _gatt(2, "0x05", uuid="0x2a19", **other),
            _gatt(3, "0x1b", **base),
            _gatt(4, "0x1b", **other),
        ],
    )
    assert [e["attribute"] for e in parsed["data"]["timeline"][-2:]] == [
        "Device Name (0x2a00)",
        "Battery Level (0x2a19)",
    ]


@pytest.mark.asyncio
async def test_gatt_pending_read_by_type_is_not_shared_between_connections() -> None:
    parsed = await _analyze(
        "ble_gatt_timeline",
        [
            _gatt(1, "0x08", uuid="0x2a00"),
            _gatt(2, "0x08", uuid="0x2a19", connection="0x000d"),
            _gatt(3, "0x09"),
            _gatt(4, "0x09", connection="0x000d"),
            _gatt(5, "0x1b"),
            _gatt(6, "0x1b", connection="0x000d"),
        ],
    )
    assert [e["attribute"] for e in parsed["data"]["timeline"][-2:]] == [
        "Device Name (0x2a00)",
        "Battery Level (0x2a19)",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [False, True])
async def test_gatt_opposite_servers_on_one_connection(addresses: bool) -> None:
    local, remote = "00:11:22:33:44:55", "66:77:88:99:aa:bb"
    sent = {"src": local, "dst": remote} if addresses else {"direction": "0"}
    received = {"src": remote, "dst": local} if addresses else {"direction": "1"}
    parsed = await _analyze(
        "ble_gatt_timeline",
        [
            _gatt(1, "0x08", uuid="0x2a00", **sent),
            _gatt(2, "0x08", uuid="0x2a19", **received),
            _gatt(3, "0x09", **received),
            _gatt(4, "0x09", **sent),
            _gatt(5, "0x1b", **received),
            _gatt(6, "0x1b", **sent),
        ],
    )
    first, second = parsed["data"]["timeline"][-2:]
    assert first["attribute"] == "Device Name (0x2a00)"
    assert second["attribute"] == "Battery Level (0x2a19)"
    assert first["server"] != second["server"]


@pytest.mark.asyncio
async def test_gatt_att_error_clears_pending_type() -> None:
    parsed = await _analyze(
        "ble_gatt_timeline",
        [
            _gatt(1, "0x08", uuid="0x2a00"),
            _gatt(2, "0x01"),
            _gatt(3, "0x09"),
            _gatt(4, "0x1b"),
        ],
    )
    assert parsed["data"]["timeline"][-1]["attribute"] is None
