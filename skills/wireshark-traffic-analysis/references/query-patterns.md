# Minimal MCP query patterns

These are starting shapes, not previously executed evidence. Replace paths and anchors with observed values, inspect current tool schemas, and use only tools present in the selected profile. Arguments below match the repository tools; the running server may be another revision.

## Exact filtered packet count

```text
wireshark_aggregate(pcap_file="/captures/input.pcapng", display_filter="dns.flags.response == 0")
```

Interpret the aggregate's scan coverage and total; do not count returned groups. Count DNS request packets, not individual questions in a multi-question message. A more specific question may need message or transaction semantics instead.

## Source fanout and byte volume

```text
wireshark_aggregate(pcap_file="/captures/input.pcapng", display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0", group_by="ip.src", distinct="ip.dst,tcp.dstport", top_k=10)
wireshark_aggregate(pcap_file="/captures/input.pcapng", display_filter="ip", group_by="ip.src", sum_fields="frame.len", sort_by="numeric_desc", sort_numeric="frame.len", top_k=10)
```

Select `ipv6.src`/`ipv6.dst` for IPv6 instead of silently discarding it. Frame-byte sums are observed frame sizes, not application goodput or proven exfiltration. Confirm the running schema's numeric-sort syntax before reuse.

## Rates and evidence samples

```text
wireshark_aggregate(pcap_file="/captures/input.pcapng", display_filter="dns.flags.response == 0", time_bucket_seconds=1, top_k=20)
wireshark_extract_fields(pcap_file="/captures/input.pcapng", fields="frame.number,frame.time_epoch,ip.src,dns.qry.name", display_filter="dns.flags.response == 0", limit=20)
```

Time buckets are relative to the capture time origin. Top-K is a ranked subset, not a complete chronological timeline; check sorting and output coverage before locating bursts. Request further scoped windows only when needed. Check the running field-list type; this project's extractor takes a comma-separated string.

The current extractor's limit/offset count TSV lines, including the header; `limit=20` is a line budget, not a guarantee of 20 data rows. Do not use `limit=1` for a one-frame filtered extraction: it can retain only the header. Keep the filter and allow the header plus the needed evidence rows.

## Packet verification

```text
wireshark_get_packet_details(pcap_file="/captures/input.pcapng", frame_number=42)
wireshark_follow_stream(pcap_file="/captures/input.pcapng", stream_index=0)
```

42 and 0 are placeholders. First obtain real anchors from a completed query. Details/streams can contain secrets; record masked observations. A statistic alone can establish a factual total; a content or causal claim needs the relevant packet or stream.
