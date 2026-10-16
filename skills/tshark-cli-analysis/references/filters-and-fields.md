# Filters, fields and scan semantics

## Filter stages

| Control | Stage | Consequence |
|---|---|---|
| `-f 'BPF'` | Acquisition | Excluded packets never enter the capture |
| `-2 -R 'expression'` | Read filter in two-pass processing | Can remove dependencies; cannot use future-dependent response-in-frame fields |
| `-Y 'expression'` | Per-packet display/write selection | Not a universal statistics-tap filter |
| `-z 'tap,...,filter'` | Tap-local selection | Most statistics have their own filter slot |

Do not add `-R` merely for speed; it can alter reassembly/matching. `-2` populates future-dependent fields on seekable input. `-M N` resets internal session state every N packets, cannot combine with `-2`, and breaks cross-reset continuity.

## Display-filter construction

For an already named field, prefer `tshark -G fields,http.user_agent` where the installed build supports prefix discovery. On the reviewed 4.6.9 build, this emits abbreviation/name pairs, not the full `F`/`P` registry schema; do not apply full-registry column offsets or infer a missing type. Match the exact abbreviation, since a prefix can match more than one field. If types or other full metadata are needed, save `tshark -G fields` once outside model context, search the saved registry and reuse it only while version/plugins remain unchanged. Older builds may require this full-registry route even for field existence.

Use `-G ftypes`, `-G values`, `-G protocols` only for the relevant uncertainty. Comparisons, existence, `and/or/not`, sets (`in { ... }`), `contains`, `matches`, slices and functions have type-specific semantics. Quote the entire expression; double-quote string literals inside it. Do not interpolate untrusted packet text as filter syntax.

```sh
tshark -n -r "$capture" -Y 'dns.flags.response == 0' -T fields -e frame.number
tshark -n -r "$capture" -Y 'ip.addr == 192.0.2.10 and tcp.port == 443'
tshark -n -r "$capture" -Y 'frame.time_epoch >= 1700000000 and frame.time_epoch < 1700000060'
```

Conjunctions can match fields from different nested layers/PDU occurrences. Multi-value comparisons are not scalar SQL predicates; `!=` need not mean `not (== ...)` for repeating or absent fields. Consult installed semantics for `any`/`all`, layer selectors, raw-byte `@field`, slices and functions. IPv4/IPv6 use distinct fields. Half-open time windows avoid overlap; timestamp precision and clock error still apply.

## Reproducible extraction

```sh
tshark -n -r "$capture" -Y 'dns.flags.response == 0' \
  -T fields -E header=y -E separator=/t -E quote=d -E occurrence=a \
  -e frame.number -e frame.time_epoch -e ip.src -e ipv6.src \
  -e dns.qry.name -e dns.qry.type > "$new_tsv" 2> "$new_stderr"
```

Use a TSV parser aware of quoting, doubled quotes and control escaping. `-E` supports `bom`, `header`, `separator`, `quote`, `occurrence`, `aggregator` and version-dependent `escape`. `-e` selects fields, protocol summaries or `_ws.col.*` columns; applicable output modes and raw `@field` vary by version. A protocol label is not all child fields.

`occurrence=a` joins occurrences into a cell; literal commas can be indistinguishable from the default aggregator. Do not split arbitrary strings into values. `occurrence=f/l` discards occurrences and cannot justify all-values cardinality. For multiplicity-sensitive questions inspect a bounded structured tree, use a field-aware parser or report ambiguity. Count emitted frame records after a complete successful scan, not headers, occurrences or application transactions.

## Completeness

`-c` includes packets rejected by `-Y`. `head`, early pipe closure, timeout and output caps are previews. Check TShark's exit status and stderr; a pipeline's final exit can hide failure. Unknown fields are failures, not empty results. Distinguish complete scan coverage from bounded Top-K display coverage.

Sources: [Display filters](https://www.wireshark.org/docs/man-pages/wireshark-filter.html), [TShark](https://www.wireshark.org/docs/man-pages/tshark.html).

`--read-filter` aliases `-R`; `--display-filter` aliases `-Y`. These names do not make either a BPF capture filter or a universal tap filter.
