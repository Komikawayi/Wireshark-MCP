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
        """[Protocol] ATT/GATT operation timeline: time, semantic opcode, handle(s), value. Works for over-the-air and HCI snoop captures."""
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

        timeline: list[dict[str, Any]] = []
        operation_counts: Counter[str] = Counter()
        for line in lines[start_idx:]:
            parts = line.split("\t")
            if len(parts) < 3:  # need frame, time, opcode
                continue
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
                }
            )
            operation_counts[operation] += 1

        operation_summary = dict(sorted(operation_counts.items(), key=lambda kv: kv[1], reverse=True))
        mix = ", ".join(f"{name} x{count}" for name, count in operation_summary.items())
        summary = f"GATT timeline: {len(timeline)} ATT operation(s). Operation mix: {mix}"

        return envelope_response(
            data={"timeline": timeline, "operation_summary": operation_summary, "summary": summary},
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

    return [
        ("wireshark_extract_ble_devices", wireshark_extract_ble_devices),
        ("wireshark_detect_ble_scan_activity", wireshark_detect_ble_scan_activity),
        ("wireshark_extract_gatt_timeline", wireshark_extract_gatt_timeline),
    ]
