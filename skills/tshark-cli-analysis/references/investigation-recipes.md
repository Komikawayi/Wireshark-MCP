# Question-driven investigation recipes

Examples are POSIX shell patterns with existing `capture` and unused outputs. Use argv arrays on other shells. Check fields against the installed engine and preserve completion status. Do not execute every branch or broaden a narrow question to a full audit.

## Unknown capture or quality-dependent claim

Use optional `capinfos "$capture"` for metadata; fall back to available TShark observations if capinfos is absent. `tshark -n -r "$capture" -q -z io,phs` supplies structural protocol context. For a claim affected by truncation, query `frame.cap_len < frame.len`; retain relevant frame numbers. Determine vantage/interfaces, offload artifacts, return-path visibility, clock precision and loss counters only where needed. An absent drop counter is unknown, not zero.

## DNS failure

Extract `frame.number`, `frame.time_epoch`, source/destination, `dns.id`, `dns.flags.response`, `dns.flags.rcode`, `dns.qry.name` and query type. Pair IDs with endpoints/name/type/time because IDs are reused. No plaintext query can mean cache, DoH/DoT, different resolver or visibility limits. Query-only traffic requires a return-path check; an explicit response code supports that code, not a blanket DNS outage. Once DNS succeeds, investigate connection/application stages instead.

## Connection and slow service

```sh
tshark -n -r "$capture" -Y 'tcp.flags.syn == 1 or tcp.flags.reset == 1' \
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.stream -e tcp.flags
tshark -n -r "$capture" -Y 'tcp.analysis.retransmission or tcp.analysis.zero_window' \
  -T fields -e frame.number -e tcp.stream -e tcp.analysis.ack_rtt
```

Use observed tuples/streams and IPv6 fields when relevant. Separate DNS, TCP setup, TLS, request-to-response and transfer intervals. SYN-only traffic does not prove server nonresponse. RST direction identifies an observed reset, not necessarily the responsible backend. Retransmission and checksum warnings can be capture/offload artifacts; inspect adjacent sequence/ack evidence. Zero window points to the advertising receiver, not automatically a saturated network. A request-to-response delay includes application processing and unseen network segments. Do not label averages as percentiles or infer one-way delay across unsynchronized sensors.

## TLS / QUIC / HTTP2 and HTTP3

First distinguish connection failure, visible alerts, incomplete handshake, and encrypted application traffic. Discover fields and follow grammar for the installed version; record parent connection + substream IDs. HTTP2 requests share a TCP connection; QUIC can migrate and multiplex streams. Decrypt only with task-provided/configured material and verify application fields. Neither SNI nor an observed certificate proves encrypted request content. If a particular HTTP3/QUIC version cannot decode, record that capability gap rather than guessing the payload.

## Periodicity, scan and exfiltration leads

For periodicity, use scoped time buckets for the same client/service, direction and sizes; compare telemetry, polling, backup and sync. Fanout needs distinct targets/ports in an explicit window, plus handshake outcomes and benign scanner alternatives. High entropy or upload asymmetry is a signal, not proof of DNS tunnel/C2/data theft. Inspect matching frames/streams and independently corroborate detector output. A public-suffix-aware domain boundary is needed before grouping base domains; do not always use the last two labels.

## BLE, industrial, VoIP and any other dissector

Discover fields/protocols rather than assuming the desktop GUI's capabilities are all CLI taps. BLE link type, address type, connections and peer-specific ATT handle maps constrain identity; advertisements are not proof of a connection. Industrial write requests/acknowledgements are not direct evidence of physical state changes. RTP stream statistics need signaling/capture context; jitter is not an audio-quality verdict. For an unfamiliar protocol, use the same schema: observed operation + endpoint roles + transaction/stream identity + frame/time + decode assumptions + competing explanation. Load the protocol's official field reference only when needed.

## Verification and stop

`tshark -n -r "$capture" -Y 'frame.number == 42' -V` inspects an observed frame; 42 is a placeholder. Stream output is evidence only after executing the selected observed stream. State `confirmed` observations separately from `likely` explanations and `candidate` leads. Finish at the deepest supported boundary and identify only the next observation that would resolve an actual gap.
