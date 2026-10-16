# Decoding, reassembly, profiles and decryption

## Decode As and protocol controls

```sh
tshark -n -r "$capture" -d tcp.port==8888,http -Y http.request -T fields -e frame.number -e http.host
tshark -G dissector-tables
tshark -G decodes
tshark -G heuristic-decodes
```

`-d <table>==<selector>,<protocol>` needs a valid dissector table, selector and decode-as protocol, not a guessed display field. Supported selectors include specific values and table-dependent ranges (`8888-8890`, `8888:3`). Deliberately invalid discovery (`-d .` or `-d 'ethertype==0x0800,.'`) can list valid choices and return nonzero; never mistake that output for packet analysis. Record each override and compare a representative decode before/after.

`--enable-protocol`, `--disable-protocol`, `--only-protocols`, `--disable-all-protocols` and `--enable-heuristic`/`--disable-heuristic` alter dissection, not acquisition. Protocol dependencies matter: disabling lower layers can remove upper-layer fields. `ALL` and enable/disable precedence are documented semantics, not a security isolation boundary. Preserve active controls in the execution record; an empty result after disabling a dissector does not prove absence of traffic.

## Profiles and preferences

`-C "$profile"` selects a named profile; `--global-profile` changes its lookup to global configuration. `-o name:value` overrides preferences per process without saving them. Inspect `-G folders`, `-G currentprefs`, `-G defaultprefs` and `-G plugins` as needed. An inherited profile/UAT can change results or emit startup errors; inspect stderr even when exit status is zero. Use a dedicated `WIRESHARK_CONFIG_DIR` for reproducible experiments, not by modifying the user's live preferences.

Common relevant preferences include TCP desegmentation and protocol-specific desegmentation/decryption settings, but exact names/types come from the installed registry. Verify future-dependent fields with `-2` on seekable input. A decode change can renumber streams or change visibility: invalidate dependent cached findings. `-M` session resets alter continuity and are not a transparent memory optimization.

## TLS and QUIC

```sh
tshark -n -r "$capture" -o "tls.keylog_file:$keylog" -Y http -T fields -e frame.number -e http.request.method
```

Use a legitimately available key log with matching sessions. Verify successful application dissection on observed frames, not merely process exit or file existence. TLS 1.3/PFS sessions are not generally decrypted with a server RSA private key. QUIC handshake/application levels, packet completeness, supported version and secrets affect decryption; a connection ID or SNI does not reveal encrypted HTTP3 content. Consult the installed TLS/QUIC preferences before constructing a protocol-specific query. `--export-tls-session-keys` exports known secrets; it is not key recovery.

## WLAN and Kerberos

WLAN decoding/decryption depends on link type, decryption preferences/UAT keys, cipher support and the required handshake or configured session keys. First establish whether the capture contains raw 802.11 or already decapsulated Ethernet. Keep keys out of argv/logs where possible; prefer a dedicated protected profile for complex UAT configuration. Do not claim WPA3 or all ciphers work merely because a preference exists.

`-K "$keytab"` loads Kerberos keys and may be repeated; correct principals/encryption types and protocol preferences still matter. A successful keytab load is not successful ticket/message decryption. Other protocol decryption (e.g. IPsec, SSH-related dissectors or proprietary sessions) is engine/plugin-specific: discover its preferences, document required key material, verify actual plaintext fields, and leave unavailable content unresolved.

## Name and identity resolution

`-n` avoids automatic resolution; `-N` selectively enables captured-DNS, external DNS, MAC/vendor, SNI, service, VLAN and geolocation resolution as supported (`d,n,N,m,s,t,v,g`). Ordering with `-n` matters. External lookups are network activity and can alter timing or disclose names; use only when the task needs them. `-H`/`-W n` preserve hosts mappings in supported files. Preserve numeric identities alongside resolved names; resolution is enrichment, not proof that an endpoint owned a hostname at capture time.

Sources: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [TLS decryption](https://wiki.wireshark.org/TLS), [802.11 decryption](https://wiki.wireshark.org/HowToDecrypt802.11).
