"""Unit tests for the Bluetooth LE analysis tools (mock client, no real tshark)."""

from unittest.mock import AsyncMock

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.bluetooth import make_bluetooth_tools
from wireshark_mcp.tools.envelope import envelope_response, error_response, parse_tool_result, success_response

DEV_HEADER = (
    "frame.number\tbtle.advertising_address\tbtle.advertising_header.pdu_type\t"
    "btle.advertising_header.randomized_tx\tbtcommon.eir_ad.entry.device_name\tbtcommon.eir_ad.entry.company_id"
)
SCAN_HEADER = "frame.number\tbtle.scanning_address\tbtle.advertising_address\tbtle.advertising_header.randomized_tx"
GATT_HEADER = (
    "frame.number\tframe.time_relative\tbtatt.opcode\tbtatt.handle\tbtatt.value\tbtatt.handles_info\tbtl2cap.cid"
)


class TestBleDevicesContract:
    """Field and filter contract for the advertising inventory tool."""

    @pytest.mark.asyncio
    async def test_requests_advertising_fields(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "frame.number",
                "btle.advertising_address",
                "btle.advertising_header.pdu_type",
                "btle.advertising_header.randomized_tx",
                "btcommon.eir_ad.entry.device_name",
                "btcommon.eir_ad.entry.company_id",
            ],
            display_filter="btle.advertising_address and not btle.scanning_address",
            limit=100,
        )
        for field in (
            "btle.advertising_address",
            "btle.advertising_header.pdu_type",
            "btle.advertising_header.randomized_tx",
            "btcommon.eir_ad.entry.device_name",
            "btcommon.eir_ad.entry.company_id",
        ):
            assert f"-e {field}" in result
        assert "-Y btle.advertising_address and not btle.scanning_address" in result


class TestBleScanActivityContract:
    """Field and filter contract for the scanner detection tool."""

    @pytest.mark.asyncio
    async def test_filters_scan_req(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "frame.number",
                "btle.scanning_address",
                "btle.advertising_address",
                "btle.advertising_header.randomized_tx",
            ],
            display_filter="btle.advertising_header.pdu_type == 0x03",
            limit=100,
        )
        assert "-e btle.scanning_address" in result
        assert "-e btle.advertising_address" in result
        assert "-Y btle.advertising_header.pdu_type == 0x03" in result


class TestGattTimelineContract:
    """Field and filter contract for the ATT/GATT timeline tool."""

    @pytest.mark.asyncio
    async def test_requests_btatt_fields(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "frame.number",
                "frame.time_relative",
                "btatt.opcode",
                "btatt.handle",
                "btatt.value",
                "btatt.handles_info",
                "btl2cap.cid",
            ],
            display_filter="btatt",
            limit=100,
        )
        for field in (
            "btatt.opcode",
            "btatt.handle",
            "btatt.value",
            "btatt.handles_info",
            "frame.time_relative",
            "btl2cap.cid",
        ):
            assert f"-e {field}" in result
        assert "-Y btatt" in result


class TestBleDevicesSemantics:
    """Aggregation semantics for the advertising inventory."""

    @pytest.mark.asyncio
    async def test_aggregation_and_dual_name_detection(self) -> None:
        mock_client = AsyncMock()
        rows = [
            DEV_HEADER,
            "1\ta2:d8:30:1e:9f:66\t0x00\tTrue\tTwinLight\t",
            "2\t66:55:44:33:22:11\t0x00\tFalse\tStaticDev\t0x0059",
            "3\taa:bb:cc:dd:ee:ff\t0x00\tTrue\tTwinLight\t",
            "5\ta2:d8:30:1e:9f:66\t0x04\tTrue\tTwinLight\t",
            "7\ta2:d8:30:1e:9f:66\t0x00\tTrue\tTwinLight\t",
            "8\taa:bb:cc:dd:ee:ff\t0x00\tTrue\tTwinLight\t",
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(rows))

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_ble_devices"]("test.pcap"))

        assert parsed["success"] is True
        data = parsed["data"]
        assert len(data["devices"]) == 3
        by_addr = {d["address"]: d for d in data["devices"]}
        assert by_addr["a2:d8:30:1e:9f:66"]["frame_count"] == 3
        assert by_addr["a2:d8:30:1e:9f:66"]["address_type"] == "random"
        assert by_addr["a2:d8:30:1e:9f:66"]["pdu_types"] == {"ADV_IND": 2, "SCAN_RSP": 1}
        assert by_addr["66:55:44:33:22:11"]["address_type"] == "public"
        assert by_addr["66:55:44:33:22:11"]["company_ids"] == ["0x0059"]

        assert len(data["shared_name_groups"]) == 1
        group = data["shared_name_groups"][0]
        assert group["device_name"] == "TwinLight"
        assert set(group["addresses"]) == {"a2:d8:30:1e:9f:66", "aa:bb:cc:dd:ee:ff"}
        assert "share" in data["summary"]

    @pytest.mark.asyncio
    async def test_multivalue_eir_split(self) -> None:
        mock_client = AsyncMock()
        rows = [
            DEV_HEADER,
            "1\t02:00:00:00:00:01\t0x00\tTrue\tNameA,NameB\t0x004c,0x424e",
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(rows))

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_ble_devices"]("test.pcap"))

        device = parsed["data"]["devices"][0]
        assert device["names"] == ["NameA", "NameB"]
        assert device["company_ids"] == ["0x004c", "0x424e"]

    @pytest.mark.asyncio
    async def test_empty_capture_points_to_hci_side(self) -> None:
        mock_client = AsyncMock()
        mock_client.extract_fields.return_value = success_response("")

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_ble_devices"]("test.pcap"))

        assert parsed["success"] is True
        assert parsed["data"]["devices"] == []
        assert "HCI" in parsed["data"]["summary"]

    @pytest.mark.asyncio
    async def test_truncated_coverage_is_partial(self) -> None:
        mock_client = AsyncMock()
        rows = "\n".join([DEV_HEADER, "1\ta2:d8:30:1e:9f:66\t0x00\tTrue\tTwinLight\t"])
        mock_client.extract_fields.return_value = envelope_response(rows, truncated=True)

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_ble_devices"]("test.pcap"))

        assert parsed["coverage"]["status"] == "partial"
        assert any("lower bounds" in w for w in parsed["warnings"])

    @pytest.mark.asyncio
    async def test_missing_trailing_tab_does_not_drop_row(self) -> None:
        mock_client = AsyncMock()
        # tshark drops the trailing tab when tail fields are empty, so rows may
        # arrive with fewer columns than requested. Such rows must still count.
        rows = "\n".join([DEV_HEADER, "1\ta2:d8:30:1e:9f:66\t0x00\tTrue\tTwinLight"])
        mock_client.extract_fields.return_value = success_response(rows)

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_ble_devices"]("test.pcap"))

        device = parsed["data"]["devices"][0]
        assert device["address"] == "a2:d8:30:1e:9f:66"
        assert device["frame_count"] == 1
        assert device["names"] == ["TwinLight"]
        assert device["company_ids"] == []


class TestBleScanActivitySemantics:
    """Aggregation semantics for scanner detection."""

    @pytest.mark.asyncio
    async def test_scanner_aggregation(self) -> None:
        mock_client = AsyncMock()
        rows = [
            SCAN_HEADER,
            "4\tee:00:11:22:33:44\ta2:d8:30:1e:9f:66\tFalse",
            "6\tee:00:11:22:33:44\t66:55:44:33:22:11\tFalse",
            "9\tee:00:11:22:33:44\ta2:d8:30:1e:9f:66\tFalse",
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(rows))

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_detect_ble_scan_activity"]("test.pcap"))

        assert parsed["success"] is True
        scanners = parsed["data"]["scanners"]
        assert len(scanners) == 1
        assert scanners[0]["scan_requests"] == 3
        assert scanners[0]["distinct_targets"] == 2
        assert scanners[0]["top_targets"][0]["address"] == "a2:d8:30:1e:9f:66"
        assert scanners[0]["top_targets"][0]["requests"] == 2

        finding = parsed["data"]["findings"][0]
        assert finding["severity"] == "info"
        assert finding["confidence"] == "confirmed"
        assert "btle.scanning_address == ee:00:11:22:33:44" in finding["evidence"][0]["filter"]

    @pytest.mark.asyncio
    async def test_no_scan_activity(self) -> None:
        mock_client = AsyncMock()
        mock_client.extract_fields.return_value = success_response("")

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_detect_ble_scan_activity"]("test.pcap"))

        assert parsed["success"] is True
        assert parsed["data"]["findings"] == []
        assert parsed["data"]["scanners"] == []


class TestGattTimelineSemantics:
    """Aggregation semantics for the ATT/GATT timeline."""

    @pytest.mark.asyncio
    async def test_opcode_semantics_and_multivalue_handle(self) -> None:
        mock_client = AsyncMock()
        rows = [
            GATT_HEADER,
            "1\t0.000000\t0x0a\t0x000b\t\t\t0x0004",
            "2\t0.010000\t0x12\t0x000c\t010203\t\t0x0004",
            "3\t0.020000\t0x1b\t0x000d\t2a2b\t\t0x0004",
            "4\t0.030000\t0x11\t0x0002,0x0003\t\t\t0x0004",
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(rows))

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_gatt_timeline"]("test.pcap"))

        assert parsed["success"] is True
        timeline = parsed["data"]["timeline"]
        assert [e["operation"] for e in timeline] == [
            "Read Request",
            "Write Request",
            "Handle Value Notification",
            "Read By Group Type Response",
        ]
        # Multi-value handle is passed through verbatim.
        assert timeline[3]["handle"] == "0x0002,0x0003"
        assert timeline[0]["time"] == 0.0
        assert timeline[1]["value"] == "010203"
        summary_counts = parsed["data"]["operation_summary"]
        assert summary_counts["Read Request"] == 1
        assert summary_counts["Write Request"] == 1

    @pytest.mark.asyncio
    async def test_missing_handle_and_value_is_none_not_error(self) -> None:
        mock_client = AsyncMock()
        rows = [
            GATT_HEADER,
            "12\t0.110000\t0x13\t\t\t\t0x0004",  # Write Response: no handle, no value
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(rows))

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_gatt_timeline"]("test.pcap"))

        event = parsed["data"]["timeline"][0]
        assert event["operation"] == "Write Response"
        assert event["handle"] is None
        assert event["value"] is None

    @pytest.mark.asyncio
    async def test_handles_info_passthrough_not_handle(self) -> None:
        mock_client = AsyncMock()
        rows = [
            GATT_HEADER,
            "4\t0.030000\t0x11\t\t\t0018,0118\t0x0004",  # RBGT response: handle unlinked, handles_info present
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(rows))

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_gatt_timeline"]("test.pcap"))

        event = parsed["data"]["timeline"][0]
        assert event["handle"] is None
        assert event["handles_info"] == "0018,0118"

    @pytest.mark.asyncio
    async def test_error_envelope_propagated(self) -> None:
        mock_client = AsyncMock()
        mock_client.extract_fields.return_value = error_response("tshark failed")

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_gatt_timeline"]("test.pcap"))

        assert parsed["success"] is False
        assert parsed["error"]["message"] == "tshark failed"
