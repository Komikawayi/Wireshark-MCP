"""Deterministic PCAP fixture builder for Wireshark MCP integration tests.

Generates minimal valid pcap files using only Python standard library.
"""

import socket
import struct
from pathlib import Path


def _checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def make_pcap_header(linktype: int = 1) -> bytes:
    # magic, ver_major(2), ver_minor(4), thiszone(0), sigfigs(0), snaplen(65535), linktype (1=Ethernet default)
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def make_pcap_packet(frame: bytes, sec: int = 0, usec: int = 0) -> bytes:
    return struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame


def make_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes) -> bytes:
    ihl_version = 0x45
    tos = 0
    tot_len = 20 + len(payload)
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    header_no_cs = struct.pack(
        "!BBHHHBBH4s4s", ihl_version, tos, tot_len, ident, flags_frag, ttl, proto, 0, src_bytes, dst_bytes
    )
    cs = _checksum(header_no_cs)
    header = struct.pack(
        "!BBHHHBBH4s4s", ihl_version, tos, tot_len, ident, flags_frag, ttl, proto, cs, src_bytes, dst_bytes
    )
    return header + payload


def make_ethernet_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def make_tcp_packet(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int, payload: bytes = b"", seq: int = 1, ack: int = 0
) -> bytes:
    offset_res = 5 << 4
    window = 65535
    tcp_hdr_no_cs = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_res, flags, window, 0, 0)
    # Pseudo header for TCP checksum
    pseudo = struct.pack(
        "!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(tcp_hdr_no_cs) + len(payload)
    )
    cs = _checksum(pseudo + tcp_hdr_no_cs + payload)
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_res, flags, window, cs, 0)
    return make_ipv4_packet(src_ip, dst_ip, 6, tcp_hdr + payload)


def make_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    # UDP checksum 0 is valid in IPv4 (means not computed)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return make_ipv4_packet(src_ip, dst_ip, 17, udp_hdr + payload)


def encode_dns_name(domain: str) -> bytes:
    res = b""
    for part in domain.strip(".").split("."):
        b_part = part.encode("ascii")
        res += struct.pack("B", len(b_part)) + b_part
    res += b"\x00"
    return res


def make_dns_query(qname: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)
    return header + question


# ── Bluetooth Low Energy fixture builders ────────────────────────────────────

# Advertising access address 0x8e89bed6, little-endian on air.
ADV_ACCESS_ADDRESS = bytes.fromhex("d6be898e")

# Nordic sniffer pseudo-header flags (little-endian u16): dewhitened (bit0) |
# signal_power_valid (bit1) | crc_checked (bit10) | crc_valid (bit11).
# Payload and CRC are stored PLAIN in this format; tshark trusts the flags and
# does not re-verify. Matches real captures produced by whad (linktype 256).
BTLE_FLAGS_PLAIN = 0x0C03


def _crc24_ble(pdu: bytes, crc_init: int = 0xAAAAAA) -> int:
    """BLE CRC-24 over a plain (dewhitened) PDU.

    Reflected polynomial of 0x65B is 0xDA6000; advertising CRCInit 0x555555
    bit-reversed is 0xAAAAAA. Verified byte-identical against a real Nordic
    sniffer capture (stored CRC bytes 72 ac ba for frame 1).
    """
    crc = crc_init
    for byte in pdu:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xDA6000 if crc & 1 else crc >> 1
    return crc & 0xFFFFFF


def _btle_rf_frame(pdu: bytes, rf_channel: int = 0) -> bytes:
    """Nordic btle_rf frame: 10-byte RF header + access address + PDU + CRC-24."""
    hdr = struct.pack("<BBBBIH", rf_channel, 0xDE, 0x80, 0, 0, BTLE_FLAGS_PLAIN)
    #               channel, -34dBm, noise, aa_offenses, ref_aa, flags (LE!)
    return hdr + ADV_ACCESS_ADDRESS + pdu + struct.pack("<I", _crc24_ble(pdu))[:3]


def _eir(ad_type: int, data: bytes) -> bytes:
    return bytes([len(data) + 1, ad_type]) + data


def _adv_pdu(pdu_type: int, header_bits: int, payload: bytes) -> bytes:
    # TxAdd lives at bit 6 (0x40) per tshark 4.6.8 dissection behavior, matching
    # a real capture (header byte 0x60 -> TxAdd: Random). A spec-literal 0x80
    # reads as Reserved / randomized_tx=False.
    return struct.pack("<BB", pdu_type | header_bits, len(payload)) + payload


def _adv_address(addr: str) -> bytes:
    """'a2:d8:30:1e:9f:66' -> little-endian on-air byte order (66 9f 1e 30 d8 a2)."""
    return bytes.fromhex(addr.replace(":", ""))[::-1]


def make_att_acl_packet(direction: int, att_pdu: bytes) -> bytes:
    """HCI H4 ACL packet carrying an ATT PDU, for linktype 201 (H4 with phdr).

    direction: 0 = sent to controller, 1 = received from controller (4-byte phdr).
    """
    l2cap = struct.pack("<HH", len(att_pdu), 0x0004) + att_pdu  # length, CID 0x0004 (ATT)
    acl = struct.pack("<HH", 0x2000 | 0x000C, len(l2cap)) + l2cap  # handle 0x000C, PB first-auto-flushable
    return struct.pack("<IB", direction, 0x02) + acl  # 4B direction phdr + H4 type ACL


def build_all_fixtures(output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: dict[str, Path] = {}

    # 1. empty.pcap
    p_empty = output_dir / "empty.pcap"
    p_empty.write_bytes(make_pcap_header())
    generated["empty"] = p_empty

    # 2. plaintext_credentials.pcap
    # Contains HTTP Basic Auth ("admin:secret") and FTP PASS ("PASS 123456")
    p_creds = output_dir / "plaintext_credentials.pcap"
    creds_bytes = bytearray(make_pcap_header())

    # HTTP packet (Basic YWRtaW46c2VjcmV0 = admin:secret)
    http_payload = (
        b"GET /login HTTP/1.1\r\n"
        b"Host: 10.0.0.1\r\n"
        b"Authorization: Basic YWRtaW46c2VjcmV0\r\n"
        b"User-Agent: Mozilla/5.0, TestAgent\r\n\r\n"
    )
    ip_tcp = make_tcp_packet("192.168.1.10", "10.0.0.1", 45678, 80, flags=0x18, payload=http_payload)
    frame = make_ethernet_frame(ip_tcp)
    creds_bytes.extend(make_pcap_packet(frame, sec=1000, usec=0))

    # FTP command: USER testuser\r\n
    ftp_user = b"USER testuser\r\n"
    ip_ftp_u = make_tcp_packet("192.168.1.10", "10.0.0.2", 45679, 21, flags=0x18, payload=ftp_user)
    creds_bytes.extend(make_pcap_packet(make_ethernet_frame(ip_ftp_u), sec=1001, usec=0))

    # FTP command: PASS 123456\r\n
    ftp_pass = b"PASS 123456\r\n"
    ip_ftp_p = make_tcp_packet(
        "192.168.1.10", "10.0.0.2", 45679, 21, flags=0x18, payload=ftp_pass, seq=1 + len(ftp_user), ack=1
    )
    creds_bytes.extend(make_pcap_packet(make_ethernet_frame(ip_ftp_p), sec=1002, usec=0))

    p_creds.write_bytes(creds_bytes)
    generated["credentials"] = p_creds

    # 3. syn_scan_burst.pcap
    # 25 SYN packets to different ports from 192.168.1.50 within 1 second
    p_scan = output_dir / "syn_scan_burst.pcap"
    scan_bytes = bytearray(make_pcap_header())
    for i in range(25):
        port = 8000 + i
        pkt = make_tcp_packet("192.168.1.50", "10.0.0.5", 50000 + i, port, flags=0x02)
        scan_bytes.extend(make_pcap_packet(make_ethernet_frame(pkt), sec=2000, usec=i * 20000))
    p_scan.write_bytes(scan_bytes)
    generated["syn_scan"] = p_scan

    # 4. dns_tunnel_candidate.pcap
    # Legitimate queries + 25 high-subdomain exfil queries (>50 chars, TXT)
    p_dns = output_dir / "dns_tunnel_candidate.pcap"
    dns_bytes = bytearray(make_pcap_header())

    # 2 normal queries
    for domain in ["www.google.com", "cdn.cloudflare.com"]:
        q = make_dns_query(domain, qtype=1)
        pkt = make_udp_packet("192.168.1.20", "8.8.8.8", 53001, 53, q)
        dns_bytes.extend(make_pcap_packet(make_ethernet_frame(pkt), sec=3000, usec=0))

    # 25 candidate exfil queries
    for i in range(25):
        qname = f"exfilpayloadpart{i:03d}somesecretdataandlargesubdomainstring.tunnel.attacker.org"
        q = make_dns_query(qname, qtype=16)  # TXT
        pkt = make_udp_packet("192.168.1.20", "8.8.8.8", 53002, 53, q)
        dns_bytes.extend(make_pcap_packet(make_ethernet_frame(pkt), sec=3001, usec=i * 10000))

    p_dns.write_bytes(dns_bytes)
    generated["dns_tunnel"] = p_dns

    # 5. multivalue_fields.pcap
    # HTTP requests with comma in User-Agent header
    p_multi = output_dir / "multivalue_fields.pcap"
    multi_bytes = bytearray(make_pcap_header())
    http_commas = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0, CustomAgent/1.0, Token/2.0\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n\r\n"
    )
    pkt = make_tcp_packet("10.1.1.5", "93.184.216.34", 41234, 80, flags=0x18, payload=http_commas)
    multi_bytes.extend(make_pcap_packet(make_ethernet_frame(pkt), sec=4000, usec=0))
    p_multi.write_bytes(multi_bytes)
    generated["multivalue"] = p_multi

    # 6. truncated_capture.pcap
    # A 2-packet capture whose last record is cut short mid-packet: the byte
    # stream ends halfway through the second frame. Real sniffer captures get
    # exactly this shape when the capture tool is killed (e.g. pkill). tshark
    # dissects packet 1, reports "cut short in the middle of a packet", and
    # exits 14 — usable output plus a warning, not a fatal read error.
    p_trunc = output_dir / "truncated_capture.pcap"
    trunc_bytes = bytearray(make_pcap_header())
    q1 = make_dns_query("first.example.com", qtype=1, txid=0x1111)
    trunc_bytes.extend(
        make_pcap_packet(
            make_ethernet_frame(make_udp_packet("192.168.1.20", "8.8.8.8", 53100, 53, q1)), sec=7000, usec=0
        )
    )
    q2 = make_dns_query("second.example.com", qtype=1, txid=0x2222)
    frame2 = make_ethernet_frame(make_udp_packet("192.168.1.20", "8.8.8.8", 53101, 53, q2))
    # Write the record header claiming the full length, then only half the bytes.
    trunc_bytes.extend(struct.pack("<IIII", 7000, 10000, len(frame2), len(frame2)))
    trunc_bytes.extend(frame2[: len(frame2) // 2])

    p_trunc.write_bytes(trunc_bytes)
    generated["truncated"] = p_trunc

    # 7. ble_advertising.pcap (linktype 256, Nordic btle_rf)
    # Three advertisers, one active scanner, and one SCAN_RSP. Device A and B share
    # the local name "TwinLight" (dual-address same-name detection path).
    p_ble_adv = output_dir / "ble_advertising.pcap"
    ble_adv_bytes = bytearray(make_pcap_header(linktype=256))

    addr_a = "a2:d8:30:1e:9f:66"  # random address (TxAdd=1)
    addr_b = "aa:bb:cc:dd:ee:ff"  # random address (TxAdd=1), same name as A
    addr_c = "66:55:44:33:22:11"  # public address (TxAdd=0)
    addr_s = "ee:00:11:22:33:44"  # scanner

    def adv_payload(adv_a: str, eirs: bytes) -> bytes:
        return _adv_address(adv_a) + eirs

    flags_eir = _eir(0x01, b"\x06")  # LE General Discoverable + BR/EDR Not Supported

    eir_a = flags_eir + _eir(0x09, b"TwinLight")
    eir_b = _eir(0x09, b"TwinLight")
    eir_c = flags_eir + _eir(0x09, b"StaticDev") + _eir(0xFF, struct.pack("<H", 0x0059) + b"\x55\x11")

    ble_frames: list[bytes] = [
        _btle_rf_frame(_adv_pdu(0x00, 0x40, adv_payload(addr_a, eir_a))),  # A ADV_IND
        _btle_rf_frame(_adv_pdu(0x00, 0x00, adv_payload(addr_c, eir_c))),  # C ADV_IND (public)
        _btle_rf_frame(_adv_pdu(0x00, 0x40, adv_payload(addr_b, eir_b))),  # B ADV_IND (same name)
        _btle_rf_frame(_adv_pdu(0x03, 0x00, _adv_address(addr_s) + _adv_address(addr_a))),  # SCAN_REQ S->A
        _btle_rf_frame(_adv_pdu(0x04, 0x40, adv_payload(addr_a, eir_a))),  # A SCAN_RSP
        _btle_rf_frame(_adv_pdu(0x03, 0x00, _adv_address(addr_s) + _adv_address(addr_c))),  # SCAN_REQ S->C
        _btle_rf_frame(_adv_pdu(0x00, 0x40, adv_payload(addr_a, eir_a))),  # A ADV_IND again
        _btle_rf_frame(_adv_pdu(0x00, 0x40, adv_payload(addr_b, eir_b))),  # B ADV_IND again
        _btle_rf_frame(_adv_pdu(0x03, 0x00, _adv_address(addr_s) + _adv_address(addr_a))),  # SCAN_REQ S->A
    ]
    for i, frame in enumerate(ble_frames):
        ble_adv_bytes.extend(make_pcap_packet(frame, sec=6000, usec=i * 10000))

    p_ble_adv.write_bytes(ble_adv_bytes)
    generated["ble_adv"] = p_ble_adv

    # 8. ble_gatt_h4.pcap (linktype 201, HCI H4 with direction phdr)
    # A full GATT discovery + write + notification exchange over ATT.
    p_ble_gatt = output_dir / "ble_gatt_h4.pcap"
    ble_gatt_bytes = bytearray(make_pcap_header(linktype=201))

    att_script: list[tuple[int, str]] = [
        (0, "02f700"),  # Exchange MTU Request (no handle/value edge case)
        (1, "03f700"),  # Exchange MTU Response
        (0, "100100ffff0028"),  # Read By Group Type Request
        (1, "1106010005000018060009000118"),  # RBGT Response: handles 0x0001,0x0006; handles_info 0018,0118
        (0, "040a000f00"),  # Find Information Request
        (1, "05010b000d29"),  # Find Information Response: format 0x01, handle 0x000b + UUID16 0x290d
        (0, "080100ffff002a"),  # Read By Type Request (Device Name)
        (1, "09090b00424c452d464958"),  # Read By Type Response: handle 0x000b, value "BLE-FIX"
        (0, "0a0b00"),  # Read Request
        (1, "0b424c452d464958"),  # Read Response: value present, handle unlinked
        (0, "120c00010203"),  # Write Request: handle 0x000c, value 010203
        (1, "13"),  # Write Response: no handle, no value
        (1, "1b0d002a2b"),  # Handle Value Notification: handle 0x000d
    ]
    for i, (direction, hex_pdu) in enumerate(att_script):
        frame = make_att_acl_packet(direction, bytes.fromhex(hex_pdu))
        ble_gatt_bytes.extend(make_pcap_packet(frame, sec=5000, usec=i * 10000))

    p_ble_gatt.write_bytes(ble_gatt_bytes)
    generated["ble_gatt"] = p_ble_gatt

    return generated


if __name__ == "__main__":
    fixtures_dir = Path(__file__).parent / "pcaps"
    res = build_all_fixtures(fixtures_dir)
    print(f"Generated {len(res)} fixture pcaps in {fixtures_dir}")
