# Statistics and stream following

## Discovery and scope

`tshark -z help` lists every registered tap/statistic in this build, often on stderr with a nonzero discovery exit. It is not an analysis failure if the expected help list was actually returned. The [coverage catalog](capability-catalog.json) records the checked baseline's complete tap names; the [inventory helper](../scripts/tshark_inventory.py) detects additions, not just a few favorite families. Tap availability and argument grammar depend on version and plugins.

Most `-z` statistics ignore the main `-Y` filter; put the expression in the statistic's own documented filter argument. Do not infer filter support from another tap's syntax. Capture filters and read filters still change the input. Use `-q` to suppress normal packet summaries, except `proto,colinfo`, which modifies those summaries and therefore must not be combined with `-q` or `-V`.

## Statistics families: route any discovered tap

| Family / names | Purpose / argument requirements |
|---|---|
| `io,phs` | Protocol hierarchy; one frame contributes to multiple layers, percentages are not disjoint |
| `io,stat` | Frames/bytes and numeric operations in intervals; see below |
| `endpoints,<type>`, `conv,<type>` | All discovered address families, e.g. eth/ip/ipv6/tcp/udp/wlan/usb/bluetooth; distinguish hosts, ports and conversations |
| `expert` | Optional severity and filter; triage hints, not ground truth |
| `flow,<name>,<mode>` | Flow/sequence views; choose observed protocol and the installed grammar |
| `<protocol>,tree` | Every registered statistics tree, including DNS/HTTP/HTTP2, address/TTL/destination/packet-length, BACnet, mobile and plugin-specific trees; usually accepts a tap-local filter |
| `<protocol>,stat`, `<protocol>,counter` | Protocol-specific counters, e.g. DHCP/SIP/RTSP/SCTP, telecom and plugin protocols; verify parameter grammar |
| `<protocol>,srt`, `<protocol>,rtd` | Service response/round-trip delays, e.g. SMB/SMB2/NFS/LDAP/Kerberos/ICMP/RADIUS/GTP; some need program/version, opcode, UUID/version or category before the filter |
| `rpc,programs`, `rpc,srt`, `dcerpc,srt` | RPC inventory/latency; do not omit mandatory program/version or interface UUID/version |
| `rtp,streams`, `sip,stat` | Media/signaling summaries; packet timing/jitter does not prove decoded audio quality |
| `diameter,avp`, `wsp,stat` | Specialized field/counter formats; AVP command/field selectors differ from generic `tree` |
| `gsm_a`, `ansi_map`, `isup_msg,tree`, `mtp3,msus`, `gsm_map,operation` | Telecom category/operation counters; inspect required selectors |
| `mac-3gpp,stat`, `rlc-3gpp,stat`, SCTP and cellular trees | Radio/link statistics with capture-specific prerequisites |
| `credentials`, `smb,sids`, `hosts` | Sensitive authentication/name/identity summaries; mask values; absence does not establish absence of encrypted activity |
| `proto,colinfo` | Add protocol field values to normal columns, not an end-of-scan summary |
| `follow,<protocol>` | Reassembled data; selectors and output modes below |
| Any remaining plugin or new tap | Find exact name in `-z help`, consult matching installed/official manual or plugin documentation; never assume it has no filter or takes generic arguments |

The catalog assigns every baseline name a reference. Family routing provides complete discoverability without freezing thousands of protocol fields into instructions. An unknown new name fails the strict coverage gate until reviewed.

## Whole-scope and numeric I/O statistics

```sh
tshark -n -r "$capture" -q -z 'io,stat,0,dns.flags.response == 0'
tshark -n -r "$capture" -q -z 'io,stat,1,SUM(frame.len)frame.len'
tshark -n -r "$capture" -q -z 'io,stat,1,COUNT(dns.qry.name)dns.flags.response == 0 and dns.qry.name'
tshark -n -r "$capture" -q -z 'conv,tcp,ip.addr == 192.0.2.10'
```

Interval 0 summarizes the whole input; fractional intervals support fine time windows. `COUNT(field)` counts field occurrences, not packets. `SUM/MIN/MAX/AVG` need suitable numeric/relative-time fields; explicitly include the field in the calculation filter. `LOAD` needs a response-time field and measures in-flight load/queue depth, not bytes/sec. `FRAMES` and `BYTES` have an optional `()filter`; preserve empty comma arguments when selecting multiple columns. Set a dot decimal locale for numeric statistics. Distinguish frame-byte totals, captured bytes and application goodput; bidirectional totals are not directional throughput. Multiple `-z` arguments can share one pass but each still has its own scope and resource cost.

Native taps do not implement arbitrary SQL group-by or universal percentiles. For an unsupported reduction, stream selected fields through a bounded parser; track missing/invalid/multi-occurrence values, cardinality and exactness. Never sum distinct counts over overlapping or even disjoint time windows without unioning identities. Top-K displays are not all groups; a truncated scan can bias both counts and ranking.

## Streams, substreams and output modes

```sh
tshark -n -r "$capture" -q -z 'follow,tcp,ascii,0'
tshark -n -r "$capture" -q -z 'follow,http2,hex,0,1'
```

Replace indices with observed anchors. TCP indices are zero-based. Registered families include TCP, UDP, DCCP, TLS, DTLS, HTTP, HTTP2, QUIC, MP2T, MPEG-PES and build-dependent USB/WebSocket additions. `-z help` can advertise entries such as SIP even where TShark has no implemented follow selector: discovery is not proof of operational support; check the manual and validate a real selector.

Modes include ascii, ebcdic, hex, raw (hexadecimal text, not automatically a binary file), utf-8 and yaml where supported. Text may contain newlines; direction markers and chunk byte lengths are part of the output grammar. Optional ranges select chunks, not frame numbers. Selectors are address:port pairs, a stream index, or parent/substream identifiers. HTTP2 needs parent TCP stream + HTTP2 stream ID; QUIC needs connection + stream identity. A UDP 5-tuple can include multiple QUIC connections and misses migration. TLS/DTLS and encrypted QUIC data require usable secrets for application content.

Record capture ID, stream/substream selector, decoding/key settings, direction and any range. Reassembly needs packets outside a narrow display window; truncating the input before following can change the answer.

Source: [TShark manual, statistics and follow grammar](https://www.wireshark.org/docs/man-pages/tshark.html).
