"""End-to-end regression tests running against real tshark with deterministic pcap fixtures."""

import shutil
from pathlib import Path

import pytest
from conftest import call_tool_text
from mcp.server import MCPServer

from wireshark_mcp.tools.bluetooth import make_ble_protocol_handlers
from wireshark_mcp.tools.envelope import parse_tool_result
from wireshark_mcp.tools.security import make_security_tools
from wireshark_mcp.tools.stats import register_stats_tools
from wireshark_mcp.tools.threat import make_threat_tools
from wireshark_mcp.tshark.client import TSharkClient

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "pcaps"


@pytest.fixture(scope="module")
def pcap_fixtures() -> dict[str, str]:
    from fixtures.generate_pcaps import build_all_fixtures

    paths = build_all_fixtures(FIXTURES_DIR)
    return {k: str(v) for k, v in paths.items()}


@pytest.mark.asyncio
async def test_real_pcap_credential_extraction(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    tools = dict(make_security_tools(client))
    pcap = pcap_fixtures["credentials"]

    raw = await tools["wireshark_extract_credentials"](pcap)
    parsed = parse_tool_result(raw)

    assert parsed["success"] is True
    data = parsed["data"]
    assert len(data["findings"]) == 1

    finding = data["findings"][0]
    assert finding["severity"] == "high"
    assert finding["confidence"] == "confirmed"

    evidence = finding["evidence"]
    protocols = {e.get("protocol") for e in evidence}
    assert "HTTP" in protocols
    assert "FTP" in protocols

    # Ensure passwords under 20 chars (admin:secret and 123456) were NOT dropped
    http_ev = next(e for e in evidence if e.get("protocol") == "HTTP")
    assert "admin:" in http_ev["value"]
    assert "secret" not in http_ev["value"]  # masked!

    ftp_ev = next(e for e in evidence if e.get("protocol") == "FTP")
    assert ftp_ev["value"] == "1*****"  # 123456 masked!


@pytest.mark.asyncio
async def test_real_pcap_dns_tunnel_candidate(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    tools = dict(make_threat_tools(client))
    pcap = pcap_fixtures["dns_tunnel"]

    raw = await tools["wireshark_detect_dns_tunnel"](pcap)
    parsed = parse_tool_result(raw)

    assert parsed["success"] is True
    data = parsed["data"]
    assert len(data["findings"]) == 1

    finding = data["findings"][0]
    assert finding["severity"] == "high"
    assert finding["confidence"] == "candidate"
    assert "Candidate DNS tunneling" in finding["observation"]
    assert finding["constraints"]["scanned"] == 27  # 2 normal + 25 exfil
    assert finding["constraints"]["limit"] == 5000


@pytest.mark.asyncio
async def test_real_pcap_port_scan_detection(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    tools = dict(make_threat_tools(client))
    pcap = pcap_fixtures["syn_scan"]

    # Threshold 15: should flag scanner with 25 ports
    raw_hit = await tools["wireshark_detect_port_scan"](pcap, threshold=15)
    parsed_hit = parse_tool_result(raw_hit)
    assert parsed_hit["success"] is True
    finding_hit = parsed_hit["data"]["findings"][0]
    assert finding_hit["severity"] == "high"
    assert "192.168.1.50" in finding_hit["evidence"][0]["value"]

    # Threshold 30: should report clean (only 25 scanned)
    raw_clean = await tools["wireshark_detect_port_scan"](pcap, threshold=30)
    parsed_clean = parse_tool_result(raw_clean)
    assert parsed_clean["success"] is True
    finding_clean = parsed_clean["data"]["findings"][0]
    assert finding_clean["severity"] == "info"
    assert finding_clean["confidence"] == "confirmed"


@pytest.mark.asyncio
async def test_real_pcap_aggregation_and_multivalue(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    mcp = MCPServer("test")
    register_stats_tools(mcp, client)
    pcap = pcap_fixtures["multivalue"]

    raw = await call_tool_text(
        mcp,
        "wireshark_aggregate",
        {
            "pcap_file": pcap,
            "group_by": "ip.src,tcp.dstport",
            "distinct": "http.user_agent",
        },
    )
    parsed = parse_tool_result(raw)
    assert parsed["success"] is True
    data = parsed["data"]
    assert data["matched_packets"] == 1
    assert data["groups_total"] == 1
    group = data["groups"][0]
    assert group["key"]["ip.src"] == "10.1.1.5"
    assert group["key"]["tcp.dstport"] == "80"


@pytest.mark.asyncio
async def test_real_pcap_numeric_aggregation(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    mcp = MCPServer("test")
    register_stats_tools(mcp, client)

    raw = await call_tool_text(
        mcp,
        "wireshark_aggregate",
        {
            "pcap_file": pcap_fixtures["credentials"],
            "group_by": "ip.src",
            "sum_fields": "frame.len",
            "avg_fields": "frame.len",
            "sort_by": "numeric_desc",
            "sort_numeric": "frame.len",
        },
    )
    parsed = parse_tool_result(raw)

    assert parsed["success"] is True
    group = parsed["data"]["groups"][0]
    assert group["key"] == {"ip.src": "192.168.1.10"}
    assert group["numeric"]["frame.len"] == {
        "valid_values": 3,
        "missing_values": 0,
        "invalid_values": 0,
        "sum": 304.0,
        "avg": pytest.approx(304 / 3),
    }


@pytest.mark.asyncio
async def test_real_pcap_empty_capture_handling(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    tools_sec = dict(make_security_tools(client))
    tools_thr = dict(make_threat_tools(client))
    pcap = pcap_fixtures["empty"]

    raw_sec = await tools_sec["wireshark_extract_credentials"](pcap)
    parsed_sec = parse_tool_result(raw_sec)
    assert parsed_sec["success"] is True
    assert parsed_sec["data"]["findings"] == []

    raw_dns = await tools_thr["wireshark_detect_dns_tunnel"](pcap)
    parsed_dns = parse_tool_result(raw_dns)
    assert parsed_dns["success"] is True
    assert parsed_dns["data"]["findings"] == []


@pytest.mark.asyncio
async def test_real_pcap_ble_device_inventory(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    handlers = make_ble_protocol_handlers(client)
    pcap = pcap_fixtures["ble_adv"]

    parsed = parse_tool_result(await handlers["ble_devices"](pcap, limit=50))

    assert parsed["success"] is True
    data = parsed["data"]
    assert parsed["coverage"]["devices"] == 3

    by_addr = {d["address"]: d for d in data["devices"]}
    assert by_addr["a2:d8:30:1e:9f:66"]["frame_count"] == 3
    assert by_addr["a2:d8:30:1e:9f:66"]["address_type"] == "random"
    assert by_addr["a2:d8:30:1e:9f:66"]["pdu_types"] == {"ADV_IND": 2, "SCAN_RSP": 1}
    assert by_addr["a2:d8:30:1e:9f:66"]["names"] == ["TwinLight"]
    assert by_addr["66:55:44:33:22:11"]["address_type"] == "public"
    assert by_addr["66:55:44:33:22:11"]["company_ids"] == ["0x0059"]
    assert by_addr["aa:bb:cc:dd:ee:ff"]["frame_count"] == 2

    assert len(data["shared_name_groups"]) == 1
    group = data["shared_name_groups"][0]
    assert group["device_name"] == "TwinLight"
    assert set(group["addresses"]) == {"a2:d8:30:1e:9f:66", "aa:bb:cc:dd:ee:ff"}


@pytest.mark.asyncio
async def test_real_pcap_ble_scan_activity(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    handlers = make_ble_protocol_handlers(client)
    pcap = pcap_fixtures["ble_adv"]

    parsed = parse_tool_result(await handlers["ble_scan_activity"](pcap, limit=50))

    assert parsed["success"] is True
    scanners = parsed["data"]["scanners"]
    assert len(scanners) == 1
    assert scanners[0]["address"] == "ee:00:11:22:33:44"
    assert scanners[0]["scan_requests"] == 3
    assert scanners[0]["distinct_targets"] == 2
    assert scanners[0]["top_targets"][0]["address"] == "a2:d8:30:1e:9f:66"

    finding = parsed["data"]["findings"][0]
    assert finding["severity"] == "info"
    assert "btle.scanning_address == ee:00:11:22:33:44" in finding["evidence"][0]["filter"]


@pytest.mark.asyncio
async def test_real_pcap_gatt_timeline(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    handlers = make_ble_protocol_handlers(client)
    pcap = pcap_fixtures["ble_gatt"]

    parsed = parse_tool_result(await handlers["ble_gatt_timeline"](pcap, limit=50))

    assert parsed["success"] is True
    data = parsed["data"]
    timeline = data["timeline"]
    assert len(timeline) == 15

    by_frame = {e["frame"]: e for e in timeline}
    # Exchange MTU Request carries neither handle nor value.
    assert by_frame[2]["operation"] == "Exchange MTU Request"
    assert by_frame[2]["handle"] is None
    # Read By Group Type Response: multi-value handles + service table.
    assert by_frame[5]["operation"] == "Read By Group Type Response"
    assert by_frame[5]["handle"] == "0x0001,0x0006"
    assert by_frame[5]["value"] == "0018,0118"
    assert [svc["label"] for svc in data["services"]] == [
        "Generic Access (0x1800)",
        "Generic Attribute (0x1801)",
    ]
    # Read By Type Response: handle linked via btatt.handle, value hex.
    assert by_frame[9]["operation"] == "Read By Type Response"
    assert by_frame[9]["handle"] == "0x000b"
    assert by_frame[9]["value"] == "424c452d464958"
    # Characteristic Declaration (0x2803) resolves the Battery Level value handle.
    assert data["handle_map"]["0x000e"] == "Battery Level (0x2a19)"
    assert data["handle_map"]["0x000b"] == "Client Characteristic Configuration (0x2902)"
    # Write Request / Response and Notification.
    assert by_frame[14]["operation"] == "Write Request"
    assert by_frame[14]["handle"] == "0x000c"
    assert by_frame[14]["value"] == "010203"
    assert by_frame[15]["handle"] is None
    assert by_frame[16]["operation"] == "Handle Value Notification"
    assert by_frame[16]["handle"] == "0x000e"
    assert by_frame[16]["attribute"] == "Battery Level (0x2a19)"
    assert by_frame[16]["service"] == "Generic Attribute (0x1801)"

    summary = data["operation_summary"]
    assert summary["Read By Group Type Request"] == 1
    assert summary["Exchange MTU Request"] == 1


@pytest.mark.asyncio
async def test_real_pcap_ble_connections(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    handlers = make_ble_protocol_handlers(client)
    pcap = pcap_fixtures["ble_gatt"]

    parsed = parse_tool_result(await handlers["ble_connections"](pcap, limit=50))

    assert parsed["success"] is True
    connections = parsed["data"]["connections"]
    assert len(connections) == 1
    session = connections[0]
    assert session["handle"] == "0x000c"
    assert session["connect"]["peer_address"] == "80:a9:97:23:9b:44"
    assert session["connect"]["interval_ms"] == 30.0
    assert session["connect"]["supervision_timeout_ms"] == 720
    assert len(session["parameter_updates"]) == 1
    assert session["parameter_updates"][0]["interval_ms"] == 52.5
    assert session["disconnect"]["reason"] == "Remote User Terminated Connection (0x13)"
    assert session["session_duration_s"] == pytest.approx(0.17)
    assert parsed["data"]["reason_summary"] == {"Remote User Terminated Connection (0x13)": 1}
    # An HCI H4 capture carries no over-the-air CONNECT_IND frames.
    assert parsed["data"]["over_air_connects"] == []
    assert "Remote User Terminated Connection" in parsed["data"]["summary"]


@pytest.mark.asyncio
async def test_real_pcap_ble_tools_on_empty_capture(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    handlers = make_ble_protocol_handlers(client)
    pcap = pcap_fixtures["empty"]

    parsed_devices = parse_tool_result(await handlers["ble_devices"](pcap))
    assert parsed_devices["success"] is True
    assert parsed_devices["data"]["devices"] == []

    parsed_scanners = parse_tool_result(await handlers["ble_scan_activity"](pcap))
    assert parsed_scanners["success"] is True
    assert parsed_scanners["data"]["scanners"] == []

    parsed_gatt = parse_tool_result(await handlers["ble_gatt_timeline"](pcap))
    assert parsed_gatt["success"] is True
    assert parsed_gatt["data"]["timeline"] == []


@pytest.mark.asyncio
async def test_real_pcap_truncated_capture_returns_partial_rows_with_warning(pcap_fixtures: dict[str, str]) -> None:
    """A capture killed mid-packet (tshark exit 14) must yield its dissected
    rows plus the stderr warning instead of an ExecutionError. Real sniffer
    captures get exactly this shape when the capture tool is killed (pkill)."""
    client = TSharkClient()
    pcap = pcap_fixtures["truncated"]

    raw = await client.extract_fields(
        pcap,
        ["frame.number", "dns.qry.name"],
        display_filter="dns",
        limit=10,
    )
    parsed = parse_tool_result(raw)

    assert parsed["success"] is True
    assert "first.example.com" in parsed["data"]
    assert "second.example.com" not in parsed["data"]  # the truncated packet never dissected
    assert "cut short" in parsed["stderr"]

    # The full tool pipeline must work on a truncated capture end to end.
    tools = dict(make_threat_tools(client))
    tool_result = parse_tool_result(await tools["wireshark_detect_dns_tunnel"](pcap))
    assert tool_result["success"] is True
    finding = tool_result["data"]["findings"][0]
    assert finding["severity"] == "info"  # one clean query is no tunneling signal


@pytest.mark.asyncio
async def test_real_pcap_ble_pairing(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    handlers = make_ble_protocol_handlers(client)
    parsed = parse_tool_result(await handlers["ble_pairing"](pcap_fixtures["ble_pairing"], limit=50))

    assert parsed["success"] is True
    data = parsed["data"]
    assert [e["operation"] for e in data["timeline"]] == [
        "Pairing Request",
        "Pairing Response",
        "Pairing Confirm",
        "Pairing Random",
        "Encryption Information",
        "Master Identification",
        "Identity Information",
        "Identity Address Information",
        "Signing Information",
    ]
    assert data["pairing_method"]["method"] == "Just Works"
    assert data["pairing_method"]["note"] == "no MITM protection requested"
    key_material = data["key_material"]
    assert key_material["ltk"] == "2b7d1c4e9f0a3d685e214a7c0fd8b649"
    assert key_material["ediv"] == "0x3412"  # fixture bytes 12 34 rendered little-endian
    assert "irk" in key_material
    finding = data["findings"][0]
    assert finding["severity"] == "low"
    assert finding["confidence"] == "likely"
    assert "Just Works" in data["summary"]
