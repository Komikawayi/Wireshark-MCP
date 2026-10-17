# Bounded execution, evidence and resumption

## Execution record

For a long-running offline extraction, use the optional standard-library runner:

```sh
python "$skill_dir/scripts/run_tshark.py" --input "$capture" \
  --output-dir "$new_run_dir" --timeout 30 --max-output-bytes 1048576 \
  -- -n -Y 'dns.flags.response == 0' -T fields -e frame.number
```

The helper creates a new output directory and exclusive files, records input SHA-256 and exact argv, drains stdout/stderr incrementally with a combined byte cap, and terminates/reaps TShark on timeout/overflow. It does not silently modify profiles, start capture, resolve names by default arguments, or export objects. Exit 0 means successful uncapped execution, 124 timeout, 125 console-output cap, 1 other failure. Inspect stderr even on success: configuration warnings can affect interpretation. A file hash identifies bytes, not acquisition authenticity.

The runner is for offline read/dissection, not a sandbox for arbitrary extensions. It rejects capture/file-writing/extension flags that need separate supervision. Direct live capture, `-w`, Lua, object/PDU/key export and provider-specific workflows remain fully documented in the corresponding references; execute them deliberately with their own storage/permission boundaries. Never claim the console cap also bounds those outputs.

For direct commands, set timeout and storage monitoring appropriate to the capture. Use argv arrays, no shell interpolation of packet strings; write raw data to separate artifacts. POSIX pipelines need TShark's own exit status, not just the consumer's. On timeout/overflow, preserve diagnostics, label partial and change the query. A final successful pipeline stage is not completion of its producer. Pipeline, scripting and many-capture batch patterns, including the [batch helper](../scripts/batch_tshark.py), are in [automation-and-pipelines.md](automation-and-pipelines.md).

## Interpretation gates

1. Check exit code, input identity, warnings, decode settings and read errors.
2. Separate scan coverage from returned-output coverage. Capped state/cardinality can bias rankings; output-only truncation need not invalidate an independently exact total.
3. Preserve units and denominators: frames, messages, field occurrences, unique values, captured bytes, wire frame lengths and goodput differ.
4. Match content/causal claims to actually inspected frames/streams. A proposed command is not evidence. Mask secrets while keeping anchors.
5. For no-match claims, require a complete successful query and observable protocol in a stated scope. Missing keys or a one-sided view limits the conclusion.

## Multi-file ledger

For each input retain capture ID/path/hash, size, time range/precision, interface/vantage and known clock correction. For each query retain exact argv/filter, engine/plugin/profile versions, decode overrides, key identifiers (never bytes), exit/coverage, output artifact and evidence anchors. For each claim retain confidence, supporting query IDs, rejected alternatives and remaining gap.

Revalidate identity/settings before reuse. Frame/stream numbers belong to one capture. A derived file can renumber them; preserve its parent relationship. Cross-file ordering needs clock uncertainty; overlap requires deduplication and directional/sequence/payload corroboration, not timestamp equality alone. NAT, proxies, reused tuples and QUIC migration complicate identity. Do not merge inputs or adjust timestamps merely to make a story consistent.

## Cost-aware progression

Start with the smallest query that distinguishes explanations. Reuse verified summaries while identity/settings remain unchanged. Use native statistics when they have the needed semantics; use bounded field reductions otherwise. Select only necessary layers/fields before increasing output caps. Do not silently broaden scope or repeat successful overview components. Stop once the question is answered, the leading explanation is sufficiently supported with checked alternatives, or missing evidence lies outside available captures.

For handoff, provide the answer, scope/quality, executed queries, evidence, material limitations and next discriminating observation. A simple count needs no incident-report template.
