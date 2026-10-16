# Capture quality and answerability

Use this checklist only when the requested conclusion depends on a condition below. Record `observed`, `not_observed`, or `unknown` with evidence; absence of a reported drop counter is not proof of zero loss.

| Condition | Useful observation | Effect on the answer |
|---|---|---|
| Identity and integrity | Path, size, hash when available, packet count, time range; read errors | Keep results attached to one immutable input; an incomplete read cannot establish a total |
| Capture vantage | Host-side, TAP, SPAN, gateway, wireless; interfaces in pcapng | Describe visible segment and direction; do not infer visibility of an unseen return path |
| Truncation | Compare `frame.cap_len` and `frame.len` on relevant frames | Header facts can remain valid while payload, reassembly, or credential conclusions are unavailable |
| Loss and asymmetry | Capture drop counters if supplied, sequence gaps, handshake visibility, direction counts | A missing ACK or SYN-ACK is not by itself a network loss/server failure diagnosis |
| Offload and duplicates | Host-side large segments, checksum warnings, repeated frames across interfaces | Distinguish NIC offload and multi-interface copies from malformed traffic, retransmissions, and volume |
| Time | Epoch timestamps, interface resolution, discontinuities and clock offsets | Do not compare latency across unsynchronized sensors or assume relative times have a shared origin |
| Decode settings | Encapsulation, Decode As, reassembly, active profile and keys | An empty protocol filter can be a decoding failure; preserve settings used for a finding |
| Encryption | Handshake visibility, key availability, successful application dissection | Distinguish observable metadata from decrypted content; adding a key file is not proof decryption worked |

Use `wireshark_get_file_info` when available, then a targeted `wireshark_extract_fields` or packet-detail query for the relevant condition. Missing capinfos should not stop frame-level analysis. Do not read every payload to assess metadata quality.

## Answerability record

```text
Question: Did the server reject this connection?
Visible: client-side outgoing SYNs at frames <observed numbers>.
Unknown: return-path visibility and capture loss.
Supported: no SYN-ACK or RST observed in <executed scope>.
Unresolved: server nonresponse versus unseen/dropped replies.
Next discriminating evidence: synchronized server-side capture or server logs.
```

For an exact packet count, complete reading and a correct filter/denominator are enough; do not demand server logs. For root cause, state the deepest boundary actually supported.
