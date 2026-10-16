# Specialized protocol branches

Load one relevant section. Confirm registered protocol values, fields, profile and installed engine capabilities first. These notes do not make every analysis mode available on every server.

## BLE

Use `wireshark_analyze_protocol`: `ble` for raw overview, `ble_devices` for advertisers, `ble_scan_activity` for scanners, `ble_gatt_timeline` for ATT operations, `ble_connections` for connection sessions, or `ble_pairing` for SMP negotiation. Start with `limit=20`; expand for missing evidence, not every recommendation.

In multi-link GATT results, use each event's `connection` and `server` with `handle_maps`; attribute handles are not global across peers or reconnections. Advertising presence is not proof of a connection or paired identity. Encrypted link data and incomplete discovery constrain characteristic attribution. Preserve address type and capture link type.

## TLS, QUIC and HTTP/2

Use the available TLS handshake mode for handshake metadata. QUIC/HTTP2-specific capabilities vary; inspect schemas/resources instead of inventing `protocol` values. For direct execution explicitly selected by the user, the CLI skill covers native stream/substream facilities.

Do not equate TCP sessions with HTTP/2 requests, or UDP 5-tuples with QUIC connection identity. HTTP/2 multiplexes streams; QUIC can migrate between addresses. Pair stream IDs with their parent connection and retain request/response direction. Verify decryption by application-layer fields, not key-file existence. Encrypted handshakes and payloads limit observable claims.

## Industrial and IoT

Use only advertised modes such as `modbus`, `s7comm`, or `mqtt`; verify exact field names. Associate request/response identifiers, endpoint roles, operation, object/register/topic and frame/time. Polling and telemetry can explain periodicity. A write request is not proof a physical process changed; distinguish request, acknowledgement and externally observed state. Packet investigation does not authorize active probing or control commands.

## Adding a branch

Add a branch only with a concrete user question, source-backed field/selector semantics, a minimal query, known false interpretations, and a deterministic or appropriately licensed fixture. Test cited tool names/protocol values and execute the minimal query against the target engine. Record version/platform limits; do not copy a static full protocol registry into the main skill.
