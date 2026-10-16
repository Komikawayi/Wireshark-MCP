# Diagnostic decisions

Choose the branch matching the symptom. At each step, ask which result would distinguish the explanations; stop once the requested fact is established. Tool names are candidates subject to current schemas and profiles.

## DNS failure

1. Scope the client, name, and time. Extract request/response flags, transaction ID, transport endpoints, query name, response code and frame anchors.
2. No visible query: check vantage point, cache, DoH/DoT or a different resolver; do not diagnose DNS outage from an empty plaintext filter.
3. Query without visible response: inspect retries and both directions; distinguish resolver nonresponse from one-sided visibility or capture loss.
4. Error response: report the observed code and responding server. NXDOMAIN does not prove a malicious domain or network reachability failure.
5. Successful answer followed by connection failure: move to connection diagnosis, not more DNS enumeration.

Use `wireshark_extract_dns_queries` for discovery and filtered `wireshark_extract_fields` / packet details for request-response pairing. Transaction IDs can be reused; pair with endpoints, name/type and time, not ID alone.

## TCP connection failure

1. Identify the observed 5-tuple and SYN frame; separate successive connection attempts and reused tuples.
2. SYN retransmissions only: verify visibility before saying the server did not respond.
3. RST: inspect source and timing. A visible reset establishes a reset at the observed point, not which upstream component caused it.
4. Three-way handshake completed: investigate TLS/application behavior rather than diagnosing connectivity failure.
5. Use `wireshark_analyze_tcp_health` as a lead, then inspect a relevant stream and `wireshark_get_packet_context` for sequence/order. Do not treat host offload checksums as on-wire corruption without corroboration.

## TLS handshake failure

1. Separate TCP failure from the TLS exchange. Inspect ClientHello, ServerHello, alerts and handshake progress where visible.
2. Distinguish an explicit alert from an unexplained close/timeout. Report the direction and observable alert; do not invent certificate details hidden by encryption.
3. Successful handshake with slow application traffic moves to application diagnosis. Missing plaintext payload is expected without usable secrets.
4. Use `wireshark_analyze_protocol(protocol="tls_handshakes")` when available, then verify the cited frames. TLS metadata does not establish an application exploit or weak configuration without the relevant evidence.

## Slow website / service

Split the observed interval into DNS, connection setup, TLS, request-to-first-response, and transfer. Query only missing stages; use `wireshark_aggregate` for scoped numeric/timing summaries and packet fields for boundaries.

- Delayed handshake: check retries and visibility before attributing latency to a particular hop.
- Long request-to-response interval: application processing and unseen network delay remain competing explanations.
- Repeated retransmissions: distinguish loss, reordering and capture artifacts; require stream context.
- Zero window: identify the advertising endpoint and interval; do not call it bandwidth saturation by default.
- Report units, sample count and missing/invalid values. An average alone hides tails; do not label it p95. Use supported response-time facilities only for protocols they accept.

## Periodic traffic / possible beacon

1. Group the same client/service by an explicit time window. Inspect a timeline, request sizes, direction, application purpose and representative frames.
2. Compare polling, telemetry, scheduled sync and backup explanations. DNS names, rarity and periodicity are signals, not intent.
3. A detector shortlist needs independently inspected traffic. Stable periodicity supports a timing observation; C2 or exfiltration needs additional content/context.
4. Expand scope only to test an actual hypothesis, not to meet a suspicious-host quota.

## Stop / handoff

For every branch, finish at `supported observation`, `likely explanation with remaining alternative`, or `unresolved with next discriminating observation`. Never replace missing evidence with a longer report.
