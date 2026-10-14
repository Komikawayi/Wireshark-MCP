"""Bluetooth Low Energy analysis tools (advertising inventory, scanners, ATT/GATT timeline)."""

import logging
from collections import Counter
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import envelope_response, normalize_tool_result, parse_tool_result
from .findings import Finding, FindingEvidence
from .formatting import OK, WARN

logger = logging.getLogger("wireshark_mcp")

# btatt.opcode renders as hex ("0x12"); map to spec names (verified against
# tshark 4.6.8 dissections of a real GATT exchange).
OPCODE_NAMES: dict[int, str] = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request",
    0x03: "Exchange MTU Response",
    0x04: "Find Information Request",
    0x05: "Find Information Response",
    0x06: "Find By Type Value Request",
    0x07: "Find By Type Value Response",
    0x08: "Read By Type Request",
    0x09: "Read By Type Response",
    0x0A: "Read Request",
    0x0B: "Read Response",
    0x0C: "Read Blob Request",
    0x0D: "Read Blob Response",
    0x0E: "Read Multiple Request",
    0x0F: "Read Multiple Response",
    0x10: "Read By Group Type Request",
    0x11: "Read By Group Type Response",
    0x12: "Write Request",
    0x13: "Write Response",
    0x14: "Prepare Write Request",
    0x15: "Prepare Write Response",
    0x16: "Execute Write Request",
    0x17: "Execute Write Response",
    0x1B: "Handle Value Notification",
    0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation",
    0x20: "Read Multiple Variable Length Request",
    0x21: "Read Multiple Variable Length Response",
    0x52: "Write Command",
    0xD2: "Signed Write Command",
}

# Legacy advertising PDU types (btle.advertising_header.pdu_type renders as hex).
PDU_NAMES: dict[int, str] = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND",
    0x07: "ADV_EXTRA_IND",
}


def _strip(raw: str) -> str:
    """tshark quote=d wraps every value in double quotes."""
    return raw.strip().strip('"').strip()


def _col(parts: list[str], index: int) -> str:
    """Read a TSV column defensively: tshark drops trailing tabs for empty tail fields."""
    return parts[index] if len(parts) > index else ""


def _split_multivalue(raw: str) -> list[str]:
    """Split an aggregator-joined multi-instance field (names, company IDs, handles)."""
    return [s for s in (_strip(p) for p in raw.split(",")) if s]


def _pdu_name(raw: str) -> str:
    value = _strip(raw)
    try:
        key = int(value, 16)
    except ValueError:
        return value
    return PDU_NAMES.get(key, value)


def _address_type(txadd_values: set[str]) -> str:
    """Map observed TxAdd flag values to an address type label."""
    flags = {v for v in txadd_values if v in {"True", "False"}}
    if not flags:
        return "unknown"
    if len(flags) > 1:
        return "mixed"
    return "random" if flags == {"True"} else "public"


def _parse_opcode(raw: str) -> tuple[str, str]:
    """Return (opcode string, semantic operation name)."""
    opcode = _strip(raw)
    try:
        return opcode, OPCODE_NAMES.get(int(opcode, 16), f"Unknown ({opcode})")
    except ValueError:
        return opcode, f"Unknown ({opcode})"


# HCI error codes as seen in Disconnect Complete events (bthci_evt.reason).
REASON_CODES: dict[int, str] = {
    0x00: "Success",
    0x01: "Unknown HCI Command",
    0x02: "Unknown Connection Identifier",
    0x03: "Hardware Failure",
    0x05: "Authentication Failure",
    0x06: "PIN or Key Missing",
    0x07: "Memory Capacity Exceeded",
    0x08: "Connection Timeout",
    0x09: "Connection Limit Exceeded",
    0x0A: "Synchronous Connection Limit Exceeded",
    0x0B: "ACL Connection Already Exists",
    0x0C: "Command Disallowed",
    0x0D: "Connection Rejected Due To Limited Resources",
    0x0E: "Connection Rejected Due To Security Reasons",
    0x0F: "Connection Rejected Due To Unacceptable BD_ADDR",
    0x10: "Connection Accept Timeout Exceeded",
    0x11: "Unsupported Feature or Parameter Value",
    0x12: "Invalid HCI Command Parameters",
    0x13: "Remote User Terminated Connection",
    0x14: "Remote Device Terminated Connection Due To Low Resources",
    0x15: "Remote Device Terminated Connection Due To Power Off",
    0x16: "Connection Terminated By Local Host",
    0x17: "Repeated Attempts",
    0x18: "Pairing Not Allowed",
    0x1A: "Unsupported Remote Feature",
    0x1E: "Invalid LL Parameters",
    0x1F: "Unspecified Error",
    0x20: "Unsupported LL Parameter Value",
    0x21: "Role Change Not Allowed",
    0x22: "LL Response Timeout",
    0x23: "LL Procedure Collision",
    0x25: "Encryption Mode Not Acceptable",
    0x28: "Instant Passed",
    0x2C: "Parameter Out Of Mandatory Range",
    0x30: "QoS Unacceptable Parameter",
    0x34: "Host Occupied",
    0x35: "Host Busy",
    0x36: "Controller Busy",
    0x3C: "Unacceptable Connection Parameters",
    0x3E: "Connection Failed to be Established",
    0x3F: "MAC Connection Failed",
    0x40: "Coarse Clock Adjustment Rejected",
    0x44: "Remote Device Terminated Due To Subrating Not Supported",
}


def _reason_name(raw: str) -> str:
    """Map a bthci_evt.reason value ('0x13') to its spec name."""
    value = _strip(raw)
    try:
        code = int(value, 16)
    except ValueError:
        return f"Unknown ({value})"
    return f"{REASON_CODES.get(code, 'Unknown error code')} ({value})"


# Common Bluetooth assigned numbers for GATT services and characteristics.
UUID_NAMES: dict[int, str] = {
    # Services
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x1802: "Immediate Alert",
    0x1803: "Link Loss",
    0x1804: "Tx Power",
    0x1805: "Pulse Oximeter",
    0x1808: "Glucose",
    0x1809: "Health Thermometer",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180E: "Phone Alert Status",
    0x180F: "Battery",
    0x1810: "Blood Pressure",
    0x1811: "Alert Notification",
    0x1812: "Human Interface Device",
    0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence",
    0x1815: "Automation IO",
    0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power",
    0x1819: "Location and Navigation",
    0x181A: "Environmental Sensing",
    0x181C: "User Data",
    0x1826: "Fitness Machine",
    # Characteristics
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A19: "Battery Level",
    0x2A23: "System ID",
    0x2A24: "Model Number String",
    0x2A25: "Serial Number String",
    0x2A26: "Firmware Revision String",
    0x2A27: "Hardware Revision String",
    0x2A28: "Software Revision String",
    0x2A29: "Manufacturer Name String",
    0x2A37: "Heart Rate Measurement",
    0x2A50: "Pulse Oximetry Measurement",
    0x2A6E: "Temperature",
    0x2A6F: "Humidity",
    # Attribute types
    0x2800: "Primary Service",
    0x2801: "Secondary Service",
    0x2802: "Include",
    0x2803: "Characteristic Declaration",
    # Descriptors
    0x2900: "Characteristic Extended Properties",
    0x2901: "Characteristic User Description",
    0x2902: "Client Characteristic Configuration",
    0x2905: "Characteristic Aggregate Format",
    0x2906: "Valid Range",
}


def _uuid_label(hex_value: str) -> str:
    """Label a little-endian 16-bit UUID hex string ('0018') with its name."""
    value = _strip(hex_value).replace(",", "")
    try:
        uuid_int = int.from_bytes(bytes.fromhex(value), "little")
    except ValueError:
        return hex_value
    name = UUID_NAMES.get(uuid_int)
    return f"{name} (0x{uuid_int:04x})" if name else f"0x{uuid_int:04x}"


def _uuid_label_from_display(raw: str) -> str:
    """Label a tshark-rendered UUID ('0x290d' or '0x2a00') with its name."""
    value = _strip(raw)
    try:
        uuid_int = int(value, 16)
    except ValueError:
        return value
    name = UUID_NAMES.get(uuid_int)
    return f"{name} (0x{uuid_int:04x})" if name else value


def _split_handles(raw: str) -> list[int]:
    """Parse an aggregator-joined handle column ('0x0001,0x0006') into ints."""
    values: list[int] = []
    for part in _split_multivalue(raw):
        try:
            values.append(int(part, 16))
        except ValueError:
            pass
    return values


def make_bluetooth_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build Bluetooth LE analysis tools."""

    async def wireshark_extract_ble_devices(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] BLE advertising device inventory: devices by address with frame counts, names, company IDs, address type, dual-address same-name detection."""
        result = await client.extract_fields(
            pcap_file,
            [
                "frame.number",
                "btle.advertising_address",
                "btle.advertising_header.pdu_type",
                "btle.advertising_header.randomized_tx",
                "btcommon.eir_ad.entry.device_name",
                "btcommon.eir_ad.entry.company_id",
            ],
            display_filter="btle.advertising_address and not btle.scanning_address",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        truncated = wrapped.get("truncated") is True
        if truncated:
            warnings.append(
                f"Advertising rows hit the limit of {limit}; frame counts are lower bounds. Raise limit for full inventory."
            )

        if not isinstance(data, str) or not data.strip():
            return envelope_response(
                data={
                    "devices": [],
                    "shared_name_groups": [],
                    "summary": (
                        f"{OK} No BLE over-the-air advertising frames found. "
                        "HCI-side captures (btsnoop/H4) expose GATT traffic via wireshark_extract_gatt_timeline instead."
                    ),
                },
                scope={"pcap_file": pcap_file, "filter": "btle.advertising_address and not btle.scanning_address"},
                coverage={"status": "complete", "frames_scanned": 0, "devices": 0, "limit": limit},
            )

        lines = data.strip().splitlines()
        start_idx = 1 if "frame.number" in lines[0] else 0

        # Per-advertiser aggregation: frame_count, PDU mix, names, company IDs, TxAdd.
        devices: dict[str, dict[str, Any]] = {}
        rows = 0
        for line in lines[start_idx:]:
            parts = line.split("\t")
            if len(parts) < 2:  # need at least the address column
                continue
            addr = _strip(parts[1])
            if not addr:
                continue
            rows += 1
            frame_raw = _strip(_col(parts, 0))
            frame = int(frame_raw) if frame_raw.isdigit() else None
            dev = devices.setdefault(
                addr,
                {
                    "frame_count": 0,
                    "pdu_types": Counter(),
                    "names": set(),
                    "company_ids": set(),
                    "txadd": set(),
                    "first_frame": frame,
                    "last_frame": frame,
                },
            )
            dev["frame_count"] += 1
            dev["pdu_types"][_pdu_name(_col(parts, 2))] += 1
            for name in _split_multivalue(_col(parts, 4)):
                dev["names"].add(name)
            for company in _split_multivalue(_col(parts, 5)):
                dev["company_ids"].add(company)
            txadd = _strip(_col(parts, 3))
            if txadd:
                dev["txadd"].add(txadd)
            if frame is not None:
                if dev["first_frame"] is None or frame < dev["first_frame"]:
                    dev["first_frame"] = frame
                if dev["last_frame"] is None or frame > dev["last_frame"]:
                    dev["last_frame"] = frame

        device_rows: list[dict[str, Any]] = []
        for addr, dev in sorted(devices.items(), key=lambda kv: kv[1]["frame_count"], reverse=True):
            device_rows.append(
                {
                    "address": addr,
                    "address_type": _address_type(dev["txadd"]),
                    "frame_count": dev["frame_count"],
                    "pdu_types": dict(sorted(dev["pdu_types"].items(), key=lambda kv: kv[1], reverse=True)),
                    "names": sorted(dev["names"]),
                    "company_ids": sorted(dev["company_ids"]),
                    "first_frame": dev["first_frame"],
                    "last_frame": dev["last_frame"],
                    "filter": f"btle.advertising_address == {addr}",
                }
            )

        # Dual-address same-name detection: one device name advertised by 2+ addresses.
        name_to_addresses: dict[str, set[str]] = {}
        for row in device_rows:
            for name in row["names"]:
                name_to_addresses.setdefault(name, set()).add(row["address"])
        shared_name_groups = [
            {
                "device_name": name,
                "addresses": sorted(addresses),
                "frame_counts": {
                    row["address"]: row["frame_count"] for row in device_rows if row["address"] in addresses
                },
            }
            for name, addresses in sorted(name_to_addresses.items())
            if len(addresses) >= 2
        ]

        summary_lines = [f"BLE advertising devices ({len(device_rows)}) from {rows} frame(s):"]
        for row in device_rows:
            pdu_mix = ", ".join(f"{name} x{count}" for name, count in row["pdu_types"].items())
            names = f", names {row['names']}" if row["names"] else ""
            companies = f", company IDs {row['company_ids']}" if row["company_ids"] else ""
            summary_lines.append(
                f"- {row['address']} [{row['address_type']}]: {row['frame_count']} frame(s) ({pdu_mix}){names}{companies}"
            )
        for group in shared_name_groups:
            summary_lines.append(
                f"{WARN} {len(group['addresses'])} address(es) share the device name '{group['device_name']}' "
                f"(RPA rotation or cloned identity): {', '.join(group['addresses'])}"
            )

        return envelope_response(
            data={
                "devices": device_rows,
                "shared_name_groups": shared_name_groups,
                "summary": "\n".join(summary_lines),
            },
            scope={"pcap_file": pcap_file, "filter": "btle.advertising_address and not btle.scanning_address"},
            coverage={
                "status": "partial" if truncated else "complete",
                "frames_scanned": rows,
                "devices": len(device_rows),
                "limit": limit,
            },
            truncated=truncated or None,
            warnings=warnings or None,
        )

    async def wireshark_detect_ble_scan_activity(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] Detect BLE active scanners: SCAN_REQ initiators with request counts and scanned-target distribution."""
        result = await client.extract_fields(
            pcap_file,
            [
                "frame.number",
                "btle.scanning_address",
                "btle.advertising_address",
                "btle.advertising_header.randomized_tx",
            ],
            display_filter="btle.advertising_header.pdu_type == 0x03",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        truncated = wrapped.get("truncated") is True
        if truncated:
            warnings.append(
                f"SCAN_REQ rows hit the limit of {limit}; request counts are lower bounds. Raise limit for full activity."
            )

        if not isinstance(data, str) or not data.strip():
            return envelope_response(
                data={
                    "findings": [],
                    "scanners": [],
                    "summary": f"{OK} No BLE SCAN_REQ (active scanning) activity found.",
                },
                scope={"pcap_file": pcap_file, "filter": "btle.advertising_header.pdu_type == 0x03"},
                coverage={"status": "complete", "frames_scanned": 0, "scanners": 0, "limit": limit},
            )

        lines = data.strip().splitlines()
        start_idx = 1 if "frame.number" in lines[0] else 0

        scanners: dict[str, dict[str, Any]] = {}
        rows = 0
        for line in lines[start_idx:]:
            parts = line.split("\t")
            if len(parts) < 2:  # need at least the scanner address column
                continue
            scanner = _strip(parts[1])
            target = _strip(_col(parts, 2))
            if not scanner:
                continue
            rows += 1
            frame_raw = _strip(_col(parts, 0))
            frame = int(frame_raw) if frame_raw.isdigit() else None
            entry = scanners.setdefault(
                scanner,
                {
                    "scan_requests": 0,
                    "targets": Counter(),
                    "txadd": set(),
                    "first_frame": frame,
                    "last_frame": frame,
                },
            )
            entry["scan_requests"] += 1
            if target:
                entry["targets"][target] += 1
            txadd = _strip(_col(parts, 3))
            if txadd:
                entry["txadd"].add(txadd)
            if frame is not None:
                if entry["first_frame"] is None or frame < entry["first_frame"]:
                    entry["first_frame"] = frame
                if entry["last_frame"] is None or frame > entry["last_frame"]:
                    entry["last_frame"] = frame

        scanner_rows: list[dict[str, Any]] = []
        for scanner, entry in sorted(scanners.items(), key=lambda kv: kv[1]["scan_requests"], reverse=True):
            top_targets = [{"address": addr, "requests": count} for addr, count in entry["targets"].most_common(10)]
            scanner_rows.append(
                {
                    "address": scanner,
                    "address_type": _address_type(entry["txadd"]),
                    "scan_requests": entry["scan_requests"],
                    "distinct_targets": len(entry["targets"]),
                    "top_targets": top_targets,
                    "first_frame": entry["first_frame"],
                    "last_frame": entry["last_frame"],
                }
            )

        total_requests = sum(entry["scan_requests"] for entry in scanners.values())
        total_targets = len({addr for entry in scanners.values() for addr in entry["targets"]})

        summary_lines = [
            f"Active BLE scanners ({len(scanner_rows)}) issuing {total_requests} SCAN_REQ against {total_targets} target(s):"
        ]
        for row in scanner_rows:
            top = ", ".join(f"{t['address']} x{t['requests']}" for t in row["top_targets"][:3])
            summary_lines.append(
                f"- {row['address']} [{row['address_type']}]: {row['scan_requests']} SCAN_REQ, "
                f"{row['distinct_targets']} target(s) ({top})"
            )

        evidence = [
            FindingEvidence(
                filter=f"btle.advertising_header.pdu_type == 0x03 and btle.scanning_address == {row['address']}",
                field="btle.scanning_address",
                description=f"{row['scan_requests']} SCAN_REQ against {row['distinct_targets']} target(s)",
                value=", ".join(t["address"] for t in row["top_targets"][:3]),
                frame=row["first_frame"],
            )
            for row in scanner_rows[:5]
        ]
        more = len(scanner_rows) - 5
        observation = f"{len(scanner_rows)} active BLE scanner(s) issued {total_requests} SCAN_REQ against {total_targets} target(s)."
        if more > 0:
            observation += f" …and {more} more scanner(s)."
        finding: Finding = {
            "observation": observation,
            "severity": "info",
            "confidence": "confirmed",
            "evidence": evidence,
        }

        return envelope_response(
            data={
                "findings": [finding] if scanner_rows else [],
                "scanners": scanner_rows,
                "summary": "\n".join(summary_lines),
            },
            scope={"pcap_file": pcap_file, "filter": "btle.advertising_header.pdu_type == 0x03"},
            coverage={
                "status": "partial" if truncated else "complete",
                "frames_scanned": rows,
                "scanners": len(scanner_rows),
                "limit": limit,
            },
            truncated=truncated or None,
            warnings=warnings or None,
        )

    async def wireshark_extract_gatt_timeline(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] ATT/GATT timeline: time, semantic opcode, handle(s), value, with services and handle labels resolved from discovery."""
        result = await client.extract_fields(
            pcap_file,
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
                "btatt.uuid128",
            ],
            display_filter="btatt",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        truncated = wrapped.get("truncated") is True
        if truncated:
            warnings.append(f"ATT timeline hit the limit of {limit} events; raise limit for the rest.")

        if not isinstance(data, str) or not data.strip():
            return envelope_response(
                data={
                    "timeline": [],
                    "services": [],
                    "handle_map": {},
                    "operation_summary": {},
                    "summary": (
                        f"{OK} No ATT/GATT (btatt) traffic found in this capture "
                        "(works for over-the-air btle and HCI snoop/H4 sources)."
                    ),
                },
                scope={"pcap_file": pcap_file, "filter": "btatt"},
                coverage={"status": "complete", "events": 0, "limit": limit},
            )

        lines = data.strip().splitlines()
        start_idx = 1 if "frame.number" in lines[0] else 0

        parsed_rows: list[list[str]] = []
        for line in lines[start_idx:]:
            parts = line.split("\t")
            if len(parts) < 3:  # need frame, time, opcode
                continue
            parsed_rows.append(parts)

        # First pass: resolve services and handle -> attribute labels from the
        # discovery exchange itself (Read By Group Type responses give service
        # ranges, Find Information responses give handle/UUID pairs, and Read By
        # Type responses to 0x2803 give characteristic declarations).
        services: list[dict[str, Any]] = []
        service_ranges: list[tuple[int, int, str]] = []
        handle_labels: dict[str, str] = {}
        pending_rbt_type: str | None = None
        for parts in parsed_rows:
            opcode, _operation = _parse_opcode(_col(parts, 2))
            if opcode == "0x11":  # Read By Group Type Response: service table
                starts = _split_handles(_col(parts, 3))
                ends = _split_handles(_col(parts, 7))
                # Request correlation injects the queried type (0x2800/0x2801) as a
                # trailing uuid16 instance; drop it. 128-bit service UUIDs render
                # into btatt.uuid128 instead of uuid16. Uncorrelated responses
                # (synthetic captures) carry entry UUIDs in btatt.value as raw LE hex.
                uuid128_list = _split_multivalue(_col(parts, 9))
                uuid_display = [u for u in _split_multivalue(_col(parts, 8)) if u not in ("0x2800", "0x2801")]
                uuid_value = _split_multivalue(_col(parts, 4))
                if uuid128_list:
                    uuid_pairs = [(u, f"0x{u}") for u in uuid128_list]
                elif uuid_display:
                    uuid_pairs = [(uuid, _uuid_label_from_display(uuid)) for uuid in uuid_display]
                else:
                    uuid_pairs = [(uuid_hex, _uuid_label(uuid_hex)) for uuid_hex in uuid_value]
                # zip truncates to the shortest list, absorbing leftover injections.
                for start, end, (uuid_raw, label) in zip(starts, ends, uuid_pairs):
                    services.append(
                        {
                            "start_handle": f"0x{start:04x}",
                            "end_handle": f"0x{end:04x}",
                            "uuid": uuid_raw,
                            "label": label,
                        }
                    )
                    service_ranges.append((start, end, label))
            elif opcode == "0x05":  # Find Information Response: handle -> UUID
                fit_handles = _split_handles(_col(parts, 3))
                fit_uuids = _split_multivalue(_col(parts, 8))
                # Correlated renderings inject extra uuid16 instances (service /
                # characteristic UUID lookups per handle), so the counts only match
                # for clean single-entry responses. Pair only when they do; the
                # 0x2803 declaration path provides labels otherwise.
                if len(fit_handles) == len(fit_uuids):
                    for fit_handle, fit_uuid in zip(fit_handles, fit_uuids):
                        handle_labels.setdefault(f"0x{fit_handle:04x}", _uuid_label_from_display(fit_uuid))
            elif opcode == "0x08":  # Read By Type Request: remember the queried type
                pending_rbt_type = _strip(_col(parts, 8)) or None
            elif opcode == "0x09" and pending_rbt_type == "0x2803":
                # Read By Type Response to a Characteristic Declaration query:
                # each entry value is properties(1) | value_handle(2) | uuid(2 or 16).
                entry_handles = _split_handles(_col(parts, 3))
                entry_values = _split_multivalue(_col(parts, 4))
                for _decl_handle, entry_value in zip(entry_handles, entry_values):
                    try:
                        raw = bytes.fromhex(entry_value)
                    except ValueError:
                        continue
                    if len(raw) < 5:
                        continue
                    value_handle = int.from_bytes(raw[1:3], "little")
                    if len(raw) >= 19:  # 128-bit UUID
                        uuid_int = int.from_bytes(raw[3:19], "little")
                        handle_labels[f"0x{value_handle:04x}"] = f"0x{uuid_int:032x}"
                    else:
                        uuid_int = int.from_bytes(raw[3:5], "little")
                        name = UUID_NAMES.get(uuid_int)
                        handle_labels[f"0x{value_handle:04x}"] = (
                            f"{name} (0x{uuid_int:04x})" if name else f"0x{uuid_int:04x}"
                        )
                pending_rbt_type = None
            elif opcode == "0x09" and pending_rbt_type is not None:
                # Read By Type Response to a characteristic-UUID query: the entry
                # handle itself is the value handle of the queried characteristic.
                queried_label = _uuid_label_from_display(pending_rbt_type)
                for entry_handle in _split_handles(_col(parts, 3)):
                    handle_labels.setdefault(f"0x{entry_handle:04x}", queried_label)
                pending_rbt_type = None

        # Second pass: build the annotated timeline.
        timeline: list[dict[str, Any]] = []
        operation_counts: Counter[str] = Counter()
        for parts in parsed_rows:
            opcode, operation = _parse_opcode(_col(parts, 2))
            frame_raw = _strip(_col(parts, 0))
            frame = int(frame_raw) if frame_raw.isdigit() else None
            try:
                time_value: float | None = float(_strip(_col(parts, 1)))
            except ValueError:
                time_value = None
            handle = _strip(_col(parts, 3)) or None
            value = _strip(_col(parts, 4)) or None
            handles_info = _strip(_col(parts, 5)) or None
            cid = _strip(_col(parts, 6)) or None
            attribute = handle_labels.get(handle) if handle else None
            service: str | None = None
            handle_ints = _split_handles(handle) if handle else []
            if handle_ints:
                for lo, hi, label in service_ranges:
                    if lo <= handle_ints[0] <= hi:
                        service = label
                        break
            timeline.append(
                {
                    "frame": frame,
                    "time": time_value,
                    "opcode": opcode,
                    "operation": operation,
                    "handle": handle,
                    "value": value,
                    "handles_info": handles_info,
                    "cid": cid,
                    "attribute": attribute,
                    "service": service,
                }
            )
            operation_counts[operation] += 1

        operation_summary = dict(sorted(operation_counts.items(), key=lambda kv: kv[1], reverse=True))
        mix = ", ".join(f"{name} x{count}" for name, count in operation_summary.items())
        summary = f"GATT timeline: {len(timeline)} ATT operation(s). Operation mix: {mix}"
        if services or handle_labels:
            summary += f" Resolved {len(services)} service(s) and {len(handle_labels)} labeled handle(s)."

        return envelope_response(
            data={
                "timeline": timeline,
                "services": services,
                "handle_map": handle_labels,
                "operation_summary": operation_summary,
                "summary": summary,
            },
            scope={"pcap_file": pcap_file, "filter": "btatt"},
            coverage={
                "status": "partial" if truncated else "complete",
                "events": len(timeline),
                "limit": limit,
                "first_frame": timeline[0]["frame"] if timeline else None,
                "last_frame": timeline[-1]["frame"] if timeline else None,
            },
            truncated=truncated or None,
            warnings=warnings or None,
        )

    async def wireshark_analyze_ble_connections(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] BLE connection lifecycle: HCI sessions per handle with link params, duration, disconnect reasons; over-the-air CONNECT_IND."""
        hci_filter = "bthci_evt.code == 0x3e"
        hci_result = await client.extract_fields(
            pcap_file,
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
            display_filter=hci_filter,
            limit=limit,
        )
        hci_wrapped = parse_tool_result(hci_result)
        if not hci_wrapped["success"]:
            return normalize_tool_result(hci_wrapped)

        disc_filter = "bthci_evt.code == 0x05"
        disc_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "frame.time_relative", "bthci_evt.connection_handle", "bthci_evt.reason"],
            display_filter=disc_filter,
            limit=limit,
        )
        disc_wrapped = parse_tool_result(disc_result)
        if not disc_wrapped["success"]:
            return normalize_tool_result(disc_wrapped)

        ota_filter = "btle.advertising_header.pdu_type == 0x05"
        ota_result = await client.extract_fields(
            pcap_file,
            [
                "frame.number",
                "frame.time_relative",
                "btle.initiator_address",
                "btle.advertising_address",
                "btle.link_layer_data.access_address",
                "btle.link_layer_data.crc_init",
                "btle.link_layer_data.interval",
                "btle.link_layer_data.latency",
                "btle.link_layer_data.timeout",
                "btle.link_layer_data.channel_map",
            ],
            display_filter=ota_filter,
            limit=limit,
        )
        ota_wrapped = parse_tool_result(ota_result)
        if not ota_wrapped["success"]:
            return normalize_tool_result(ota_wrapped)

        hci_data = hci_wrapped.get("data", "")
        disc_data = disc_wrapped.get("data", "")
        ota_data = ota_wrapped.get("data", "")
        warnings: list[str] = []
        truncated = (
            hci_wrapped.get("truncated") is True
            or disc_wrapped.get("truncated") is True
            or ota_wrapped.get("truncated") is True
        )
        if truncated:
            warnings.append(f"One or more connection queries hit the limit of {limit}; counts are lower bounds.")

        # HCI side: group LE meta events by connection handle.
        sessions: dict[str, dict[str, Any]] = {}
        update_events: list[tuple[str, dict[str, Any]]] = []
        hci_rows = 0
        if isinstance(hci_data, str) and hci_data.strip():
            lines = hci_data.strip().splitlines()
            start_idx = 1 if "frame.number" in lines[0] else 0
            for line in lines[start_idx:]:
                parts = line.split("\t")
                if len(parts) < 4:
                    continue
                handle = _strip(_col(parts, 3))
                if not handle:
                    continue
                hci_rows += 1
                subevent = _strip(_col(parts, 2))
                frame_raw = _strip(_col(parts, 0))
                frame = int(frame_raw) if frame_raw.isdigit() else None
                try:
                    time_value = float(_strip(_col(parts, 1)))
                except ValueError:
                    time_value = None
                entry: dict[str, Any] = {
                    "handle": handle,
                    "frame": frame,
                    "time": time_value,
                    "subevent": subevent,
                }
                # 0x01 LE Connection Complete, 0x0a Enhanced V1, 0x29 Enhanced V2
                # (5.3 controllers like Zephyr SDC report the V2 event).
                if subevent in ("0x01", "0x0a", "0x29"):
                    entry.update(
                        {
                            "peer_address": _strip(_col(parts, 4)) or None,
                            "peer_address_type": _strip(_col(parts, 5)) or None,
                            "interval": _strip(_col(parts, 6)) or None,
                            "interval_ms": None,
                            "latency": _strip(_col(parts, 7)) or None,
                            "supervision_timeout": _strip(_col(parts, 8)) or None,
                            "supervision_timeout_ms": None,
                            "status": _strip(_col(parts, 9)) or None,
                        }
                    )
                    interval_raw = entry.get("interval")
                    if interval_raw and interval_raw.isdigit():
                        entry["interval_ms"] = round(int(interval_raw) * 1.25, 2)
                    timeout_raw = entry.get("supervision_timeout")
                    if timeout_raw and timeout_raw.isdigit():
                        entry["supervision_timeout_ms"] = int(timeout_raw) * 10
                    sessions.setdefault(handle, {"connect": None, "updates": []})["connect"] = entry
                elif subevent == "0x03":  # LE Connection Update Complete
                    update: dict[str, Any] = {
                        "frame": frame,
                        "time": time_value,
                        "interval": _strip(_col(parts, 6)) or None,
                        "latency": _strip(_col(parts, 7)) or None,
                        "supervision_timeout": _strip(_col(parts, 8)) or None,
                    }
                    if update["interval"] and str(update["interval"]).isdigit():
                        update["interval_ms"] = round(int(update["interval"]) * 1.25, 2)
                    else:
                        update["interval_ms"] = None
                    update_events.append((handle, update))

        for handle, update in update_events:
            if handle in sessions:
                sessions[handle]["updates"].append(update)

        # HCI disconnects: attach reason + session duration to each handle.
        reason_counts: Counter[str] = Counter()
        disc_rows = 0
        if isinstance(disc_data, str) and disc_data.strip():
            lines = disc_data.strip().splitlines()
            start_idx = 1 if "frame.number" in lines[0] else 0
            for line in lines[start_idx:]:
                parts = line.split("\t")
                if len(parts) < 4:
                    continue
                handle = _strip(_col(parts, 2))
                if not handle:
                    continue
                disc_rows += 1
                reason_name = _reason_name(_col(parts, 3))
                reason_counts[reason_name] += 1
                try:
                    time_value = float(_strip(_col(parts, 1)))
                except ValueError:
                    time_value = None
                session = sessions.setdefault(handle, {"connect": None, "updates": []})
                session["disconnect"] = {"reason": reason_name, "time": time_value}
                connect_time = session["connect"]["time"] if session.get("connect") else None
                if connect_time is not None and time_value is not None:
                    session["session_duration_s"] = round(time_value - connect_time, 6)

        connection_rows: list[dict[str, Any]] = []
        for handle, session in sorted(sessions.items()):
            row: dict[str, Any] = {"handle": handle, "connect": session.get("connect")}
            row["parameter_updates"] = session.get("updates", [])
            row["disconnect"] = session.get("disconnect")
            row["session_duration_s"] = session.get("session_duration_s")
            connection_rows.append(row)

        # Over-the-air side: CONNECT_IND frames carry LL-level session parameters.
        ota_rows: list[dict[str, Any]] = []
        if isinstance(ota_data, str) and ota_data.strip():
            lines = ota_data.strip().splitlines()
            start_idx = 1 if "frame.number" in lines[0] else 0
            for line in lines[start_idx:]:
                parts = line.split("\t")
                if len(parts) < 4:
                    continue
                initiator = _strip(_col(parts, 2))
                advertiser = _strip(_col(parts, 3))
                if not initiator and not advertiser:
                    continue
                frame_raw = _strip(_col(parts, 0))
                frame = int(frame_raw) if frame_raw.isdigit() else None
                try:
                    time_value = float(_strip(_col(parts, 1)))
                except ValueError:
                    time_value = None
                interval_raw = _strip(_col(parts, 6))
                timeout_raw = _strip(_col(parts, 8))
                ota_rows.append(
                    {
                        "frame": frame,
                        "time": time_value,
                        "initiator_address": initiator or None,
                        "advertiser_address": advertiser or None,
                        "access_address": _strip(_col(parts, 4)) or None,
                        "crc_init": _strip(_col(parts, 5)) or None,
                        "interval": interval_raw or None,
                        "interval_ms": round(int(interval_raw) * 1.25, 2) if interval_raw.isdigit() else None,
                        "timeout": timeout_raw or None,
                        "timeout_ms": int(timeout_raw) * 10 if timeout_raw.isdigit() else None,
                        "channel_map": _strip(_col(parts, 9)) or None,
                    }
                )

        if not connection_rows and not ota_rows:
            return envelope_response(
                data={
                    "connections": [],
                    "over_air_connects": [],
                    "reason_summary": {},
                    "summary": (
                        f"{OK} No BLE connection activity found. HCI captures expose LE Connection/Disconnect "
                        "events; over-the-air captures expose CONNECT_IND frames."
                    ),
                },
                scope={"pcap_file": pcap_file, "filters": [hci_filter, disc_filter, ota_filter]},
                coverage={"status": "complete", "hci_rows": 0, "disconnect_rows": 0, "ota_rows": 0, "limit": limit},
            )

        summary_lines: list[str] = []
        if connection_rows:
            summary_lines.append(f"BLE connections (HCI): {len(connection_rows)} session(s):")
            for row in connection_rows:
                connect = row["connect"]
                if connect is not None:
                    duration = row["session_duration_s"]
                    duration_text = f", {duration:.3f}s session" if duration is not None else ", no disconnect event"
                    interval_text = f", interval {connect['interval_ms']}ms" if connect.get("interval_ms") else ""
                    peer_text = connect.get("peer_address") or "?"
                    summary_lines.append(f"- handle {row['handle']} -> {peer_text}{interval_text}{duration_text}")
                disconnect = row["disconnect"]
                if disconnect is not None:
                    summary_lines.append(f"  disconnected: {disconnect['reason']}")
            if reason_counts:
                mix = ", ".join(f"{name} x{count}" for name, count in reason_counts.most_common())
                summary_lines.append(f"Disconnect reasons: {mix}")
        if ota_rows:
            summary_lines.append(f"Over-the-air CONNECT_IND: {len(ota_rows)} connection(s):")
            for row in ota_rows[:10]:
                summary_lines.append(
                    f"- {row['initiator_address']} -> {row['advertiser_address']} "
                    f"(AA {row['access_address']}, interval {row['interval_ms']}ms, CRCInit {row['crc_init']})"
                )
            if len(ota_rows) > 10:
                summary_lines.append(f"  …and {len(ota_rows) - 10} more")

        return envelope_response(
            data={
                "connections": connection_rows,
                "over_air_connects": ota_rows,
                "reason_summary": dict(reason_counts),
                "summary": "\n".join(summary_lines),
            },
            scope={"pcap_file": pcap_file, "filters": [hci_filter, disc_filter, ota_filter]},
            coverage={
                "status": "partial" if truncated else "complete",
                "hci_rows": hci_rows,
                "disconnect_rows": disc_rows,
                "ota_rows": len(ota_rows),
                "limit": limit,
            },
            truncated=truncated or None,
            warnings=warnings or None,
        )

    return [
        ("wireshark_extract_ble_devices", wireshark_extract_ble_devices),
        ("wireshark_detect_ble_scan_activity", wireshark_detect_ble_scan_activity),
        ("wireshark_extract_gatt_timeline", wireshark_extract_gatt_timeline),
        ("wireshark_analyze_ble_connections", wireshark_analyze_ble_connections),
    ]
