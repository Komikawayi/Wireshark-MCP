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
                "btatt.group_end_handle",
                "btatt.uuid16",
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
            "btatt.group_end_handle",
            "btatt.uuid16",
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


class TestGattLabelResolution:
    """Service-table and handle-label resolution from the discovery exchange."""

    @pytest.mark.asyncio
    async def test_resolves_services_fitting_declaration_and_fi(self) -> None:
        mock_client = AsyncMock()
        rows = [
            GATT_HEADER,
            # RBGT Response: GAP 0x0001-0x0005, GATT 0x0006-0x000f (uuid little-endian hex)
            "5\t0.030000\t0x11\t0x0001,0x0006\t0018,0118\t\t0x0004\t0x0005,0x000f\t",
            # Find Information Response: handle 0x000b is a CCCD
            "7\t0.050000\t0x05\t0x000b\t\t\t0x0004\t\t0x2902",
            # Read By Type Request/Response for Characteristic Declarations (0x2803):
            # entry: handle 0x000d, value = props(0c) | value_handle(0x000e) | uuid(0x2a19)
            "10\t0.080000\t0x08\t\t\t\t0x0004\t\t0x2803",
            "11\t0.090000\t0x09\t0x000d\t0c0e00192a\t\t0x0004\t\t",
            # Read By Type Request/Response by characteristic UUID (0x2a00 Device Name)
            "12\t0.100000\t0x08\t\t\t\t0x0004\t\t0x2a00",
            "13\t0.110000\t0x09\t0x000b\t424c452d464958\t\t0x0004\t\t",
            # Notification on the Battery Level value handle
            "16\t0.140000\t0x1b\t0x000e\t2a2b\t\t0x0004\t\t",
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(rows))

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_gatt_timeline"]("test.pcap"))

        assert parsed["success"] is True
        data = parsed["data"]
        assert [svc["label"] for svc in data["services"]] == ["Generic Access (0x1800)", "Generic Attribute (0x1801)"]
        assert data["handle_map"]["0x000e"] == "Battery Level (0x2a19)"
        assert (
            data["handle_map"]["0x000b"] == "Client Characteristic Configuration (0x2902)"
        )  # FIT wins over the later RBT query

        by_frame = {e["frame"]: e for e in data["timeline"]}
        assert by_frame[16]["attribute"] == "Battery Level (0x2a19)"
        assert by_frame[16]["service"] == "Generic Attribute (0x1801)"
        assert by_frame[7]["attribute"] == "Client Characteristic Configuration (0x2902)"
        # An unlabeled handle still carries its service range.
        assert by_frame[5]["service"] == "Generic Access (0x1800)"
        assert "Resolved 2 service(s)" in data["summary"]

    @pytest.mark.asyncio
    async def test_characteristic_declaration_with_128bit_uuid(self) -> None:
        mock_client = AsyncMock()
        uuid128 = "12345678901234567890123456789012"  # 16 bytes little-endian
        rows = [
            GATT_HEADER,
            "10\t0.080000\t0x08\t\t\t\t0x0004\t\t0x2803",
            f"11\t0.090000\t0x09\t0x000d\t0c0e00{uuid128}\t\t0x0004\t\t",
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(rows))

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_extract_gatt_timeline"]("test.pcap"))

        handle_map = parsed["data"]["handle_map"]
        # The 16-byte UUID is parsed little-endian, so the label carries the byte-reversed hex.
        assert handle_map["0x000e"] == "0x" + bytes.fromhex(uuid128)[::-1].hex()


class TestBleConnectionsContract:
    """Field and filter contract for the connection lifecycle tool."""

    @pytest.mark.asyncio
    async def test_queries_connection_events(self, mock_client: MockTSharkClient) -> None:
        await mock_client.extract_fields(
            "test.pcap",
            [
                "frame.number",
                "frame.time_relative",
                "bthci_evt.le_meta_subevent",
                "bthci_evt.connection_handle",
                "bthci_evt.bd_addr",
                "bthci_evt.le_peer_address_type",
                "bthci_evt.le_con_interval",
                "bthci_evt.le_con_latency",
                "bthci_evt.le_supv_timeout",
                "bthci_evt.status",
            ],
            display_filter="bthci_evt.code == 0x3e",
            limit=100,
        )
        result = await mock_client.extract_fields(
            "test.pcap",
            ["frame.number", "frame.time_relative", "bthci_evt.connection_handle", "bthci_evt.reason"],
            display_filter="bthci_evt.code == 0x05",
            limit=100,
        )
        assert "-e bthci_evt.reason" in result
        assert "-Y bthci_evt.code == 0x05" in result


class TestBleConnectionsSemantics:
    """Aggregation semantics for connection lifecycle analysis."""

    @pytest.mark.asyncio
    async def test_full_session_with_reason_attribution(self) -> None:
        mock_client = AsyncMock()
        connect_rows = [
            "frame.number\tframe.time_relative\tbthci_evt.le_meta_subevent\tbthci_evt.connection_handle\t"
            "bthci_evt.bd_addr\tbthci_evt.le_peer_address_type\tbthci_evt.le_con_interval\t"
            "bthci_evt.le_con_latency\tbthci_evt.le_supv_timeout\tbthci_evt.status",
            "1\t0.000000\t0x01\t0x000c\t80:a9:97:23:9b:44\t0x00\t24\t0\t72\t0x00",
            "17\t0.160000\t0x03\t0x000c\t\t\t42\t0\t600\t",
        ]
        disconnect_rows = [
            "frame.number\tframe.time_relative\tbthci_evt.connection_handle\tbthci_evt.reason",
            "18\t0.170000\t0x000c\t0x13",
        ]
        mock_client.extract_fields.side_effect = [
            success_response("\n".join(connect_rows)),
            success_response("\n".join(disconnect_rows)),
            success_response(""),  # no over-the-air CONNECT_IND in an HCI capture
        ]

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_analyze_ble_connections"]("test.pcap"))

        assert parsed["success"] is True
        connections = parsed["data"]["connections"]
        assert len(connections) == 1
        session = connections[0]
        assert session["handle"] == "0x000c"
        assert session["connect"]["peer_address"] == "80:a9:97:23:9b:44"
        assert session["connect"]["interval_ms"] == 30.0
        assert len(session["parameter_updates"]) == 1
        assert session["parameter_updates"][0]["interval_ms"] == 52.5
        assert session["disconnect"]["reason"] == "Remote User Terminated Connection (0x13)"
        assert session["session_duration_s"] == pytest.approx(0.17)
        assert parsed["data"]["reason_summary"] == {"Remote User Terminated Connection (0x13)": 1}
        assert parsed["data"]["over_air_connects"] == []
        assert "Remote User Terminated Connection" in parsed["data"]["summary"]

    @pytest.mark.asyncio
    async def test_over_the_air_connect_ind(self) -> None:
        mock_client = AsyncMock()
        ota_rows = [
            "frame.number\tframe.time_relative\tbtle.initiator_address\tbtle.advertising_address\t"
            "btle.link_layer_data.access_address\tbtle.link_layer_data.crc_init\tbtle.link_layer_data.interval\t"
            "btle.link_layer_data.latency\tbtle.link_layer_data.timeout\tbtle.link_layer_data.channel_map",
            "70\t10.300000\tf0:f1:f2:f3:f4:f5\t80:a9:97:23:9b:44\t0x556254e2\t0x7bc24d\t24\t0\t72\t0x1fffffffff",
        ]
        mock_client.extract_fields.side_effect = [
            success_response(""),  # no HCI events in an over-the-air capture
            success_response(""),  # no HCI disconnects
            success_response("\n".join(ota_rows)),
        ]

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_analyze_ble_connections"]("test.pcap"))

        assert parsed["success"] is True
        ota = parsed["data"]["over_air_connects"]
        assert len(ota) == 1
        assert ota[0]["initiator_address"] == "f0:f1:f2:f3:f4:f5"
        assert ota[0]["advertiser_address"] == "80:a9:97:23:9b:44"
        assert ota[0]["interval_ms"] == 30.0
        assert ota[0]["timeout_ms"] == 720
        assert parsed["data"]["connections"] == []

    @pytest.mark.asyncio
    async def test_no_connection_activity(self) -> None:
        mock_client = AsyncMock()
        mock_client.extract_fields.side_effect = [
            success_response(""),
            success_response(""),
            success_response(""),
        ]

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_analyze_ble_connections"]("test.pcap"))

        assert parsed["success"] is True
        assert parsed["data"]["connections"] == []
        assert "No BLE connection activity" in parsed["data"]["summary"]

    @pytest.mark.asyncio
    async def test_failed_connection_attempt_is_kept(self) -> None:
        mock_client = AsyncMock()
        # LE Connection Complete with status 0x08 (Connection Timeout): the
        # attempt itself is data; it must not be dropped.
        connect_rows = [
            "frame.number\tframe.time_relative\tbthci_evt.le_meta_subevent\tbthci_evt.connection_handle\t"
            "bthci_evt.bd_addr\tbthci_evt.le_peer_address_type\tbthci_evt.le_con_interval\t"
            "bthci_evt.le_con_latency\tbthci_evt.le_supv_timeout\tbthci_evt.status",
            "3\t0.150000\t0x01\t0x0005\t46:ba:e2:8e:02:f1\t0x01\t\t\t\t0x08",
        ]
        mock_client.extract_fields.side_effect = [
            success_response("\n".join(connect_rows)),
            success_response(""),
            success_response(""),
        ]

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_analyze_ble_connections"]("test.pcap"))

        connections = parsed["data"]["connections"]
        assert len(connections) == 1
        assert connections[0]["connect"]["status"] == "0x08"
        assert connections[0]["disconnect"] is None

    @pytest.mark.asyncio
    async def test_truncated_queries_warn_lower_bounds(self) -> None:
        mock_client = AsyncMock()
        mock_client.extract_fields.side_effect = [
            envelope_response("1\t0.000000\t0x01\t0x000c", truncated=True),
            success_response(""),
            success_response(""),
        ]

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_analyze_ble_connections"]("test.pcap"))

        assert parsed["coverage"]["status"] == "partial"
        assert any("lower bounds" in w for w in parsed["warnings"])


class TestBleConnectionsRealWorldShapes:
    """Subevent variants seen in real controller traces (deep-test findings)."""

    @pytest.mark.asyncio
    async def test_enhanced_connection_complete_v2_subevent(self) -> None:
        mock_client = AsyncMock()
        # Zephyr SDC (Bluetooth 5.3) reports LE Enhanced Connection Complete V2,
        # which tshark renders as subevent 0x29 — not the textbook 0x01.
        connect_rows = [
            "frame.number\tframe.time_relative\tbthci_evt.le_meta_subevent\tbthci_evt.connection_handle\t"
            "bthci_evt.bd_addr\tbthci_evt.le_peer_address_type\tbthci_evt.le_con_interval\t"
            "bthci_evt.le_con_latency\tbthci_evt.le_supv_timeout\tbthci_evt.status",
            "2\t0.137000\t0x29\t0x0020\tfc:de:c5:ae:c4:d6\t0x00\t24\t0\t72\t0x00",
        ]
        mock_client.extract_fields.side_effect = [
            success_response("\n".join(connect_rows)),
            success_response(""),
            success_response(""),
        ]

        tools = dict(make_bluetooth_tools(mock_client))
        parsed = parse_tool_result(await tools["wireshark_analyze_ble_connections"]("test.pcap"))

        connections = parsed["data"]["connections"]
        assert len(connections) == 1
        assert connections[0]["handle"] == "0x0020"
        assert connections[0]["connect"]["peer_address"] == "fc:de:c5:ae:c4:d6"
        assert connections[0]["connect"]["interval_ms"] == 30.0
