# Automation, shell pipelines and batch processing

Use this guide when TShark output feeds another program: a shell pipeline, a script, a scheduled job, a CI gate or a run over many captures. The question still decides the query; automation only changes who consumes the result. Examples are bash with an existing `capture`, unused `new_*` paths and `-n`; check fields against the installed engine before scripting them.

## Pipeline contract

A pipeline is complete only when **every** stage succeeded. The consumer's exit status alone hides a TShark failure, an unknown field or a truncated read.

```sh
set -o pipefail
tshark -n -r "$capture" -Y 'dns.flags.response == 0' -T fields -e dns.qry.name \
  2> "$new_stderr" | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn > "$new_counts"
echo "tshark=${PIPESTATUS[0]} sort=${PIPESTATUS[1]} uniq=${PIPESTATUS[2]}"
```

- Keep stderr in a file, not in the data stream; read it even when the exit status is 0.
- `pipefail` and `PIPESTATUS` are bash/zsh (`pipestatus` in zsh) features. In plain POSIX `sh`, write TShark output to a file first and check its status before post-processing.
- `head`, `grep -m` or any consumer that stops early closes the pipe; TShark then exits on a write error or SIGPIPE (status 141 in bash), or may still exit 0 when the input happened to be small. Either way the result is a **preview**, never a count or an absence claim. Use `-c` or a narrower filter to bound input deliberately and report it as partial.
- Use `LC_ALL=C` for `sort`/`uniq`/`comm` so ordering and byte comparison do not depend on the user's locale.
- Never feed packet strings to `eval`, `sh -c`, `xargs` without `-0`, or a filter expression. They are untrusted data.

## Field extraction for machines

```sh
tshark -n -r "$capture" -Y 'tcp.flags.syn == 1 and tcp.flags.ack == 0' \
  -T fields -E header=n -E separator=/t -E occurrence=f \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport \
  > "$new_tsv" 2> "$new_stderr"
```

- Fix the separator (`/t`), header policy and occurrence mode explicitly; defaults vary by version and profile.
- `occurrence=f` or `l` deliberately keeps one value per frame. With `occurrence=a` a cell can hold several values joined by the aggregator (default `,`), so `cut`/`awk` columns are not one value per row. Change the aggregator with `-E aggregator=` only to a byte that cannot appear in the field, and still treat free-text fields as ambiguous.
- An absent field yields an empty cell, not a removed row. Use `awk -F '\t' '$3 != ""'` when blank means "not present".
- IPv4 and IPv6 live in different fields. Extract both, or the IPv6 rows silently become empty.
- Prefer `frame.time_epoch` for machine time; `-t` only changes rendered summary columns.

### Common reductions

```sh
# Distinct values (after a complete, successful scan)
cut -f3 "$new_tsv" | LC_ALL=C sort -u | wc -l

# Top talkers by SYN count
cut -f3 "$new_tsv" | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -n 20

# Sum and maximum of a numeric field
tshark -n -r "$capture" -T fields -e frame.len 2> "$new_stderr" |
  awk '{ s += $1; if ($1 > m) m = $1 } END { printf "frames=%d bytes=%d max=%d\n", NR, s, m }'
```

`head -n 20` applied to the already complete `sort` output is a display cap, not a scan cap; the totals above it remain exact. When TShark has a native statistic with the needed semantics, prefer it to a shell reduction because it avoids transferring per-packet rows:

```sh
tshark -n -r "$capture" -q -z 'io,stat,60,SUM(frame.len)frame.len,COUNT(dns.qry.name)dns.qry.name'
tshark -n -r "$capture" -q -z conv,tcp
```

## JSON and EK pipelines

```sh
# One compact object per packet with only the selected layers
tshark -n -r "$capture" -Y 'http.request' -T json --no-duplicate-keys -j 'http' \
  2> "$new_stderr" | jq -c '.[]._source.layers.http' > "$new_ndjson"

# Newline-delimited records; skip the bulk "index" action lines
tshark -n -r "$capture" -Y 'dns' -T ek -e frame.number -e dns.qry.name \
  2> "$new_stderr" | jq -c 'select(.layers) | .layers' > "$new_ndjson"
```

- `-T json` emits one array, so `jq` must parse the whole document; prefer `-T ek` or `-T fields` for large inputs that should stream.
- With `--no-duplicate-keys`, repeated fields become arrays; scripts must accept either a scalar or an array. Without it, ordinary JSON parsers keep only the last duplicate key.
- `-T ek` field names and value types differ from `-T json` (dots become underscores, values are often arrays of strings). Do not reuse one schema for the other.
- Field values in JSON are strings unless the version documents otherwise; convert numbers explicitly (`tonumber`).

## Live capture into a pipeline

```sh
set -o pipefail
tshark -n -l -i "$iface" -f 'udp port 53' -a duration:60 \
  -T fields -E separator=/t -e frame.time_epoch -e ip.src -e dns.qry.name \
  2> "$new_stderr" | while IFS=$'\t' read -r ts src name; do
    printf '%s\t%s\t%s\n' "$ts" "$src" "$name"
  done > "$new_tsv"
```

- `-l` flushes each packet so a consumer sees rows promptly; it does not reduce memory use or prove completeness.
- Bound the run with `-a duration:`/`-a packets:` (or `-c`) and record the stop condition; an interrupted consumer can drop rows TShark captured.
- If the consumer is slow, packets queue in the kernel buffer and can be dropped. For anything that must be re-examined, write a ring buffer and post-process files instead (next section). Capture permissions and interface choice are covered in [capture-and-input.md](capture-and-input.md).

## Ring buffers and scheduled post-processing

```sh
tshark -n -i "$iface" -f "$bpf" -w "$ring_dir/ring.pcapng" \
  -b duration:300 -b files:288 2> "$ring_dir/capture.stderr"
```

The ring rotates every 300 seconds and keeps at most 288 files (one day); the writer names files `ring_<number>_<timestamp>.pcapng`. Process **closed** files only: the newest file is still being written, so skip it (or wait for the next rotation) rather than reading a growing capture.

```sh
# Process every closed ring file once; the newest file is still open.
find "$ring_dir" -maxdepth 1 -name 'ring_*.pcapng' -print | LC_ALL=C sort | sed '$d' |
  while IFS= read -r file; do
    done_marker="$results_dir/$(basename "$file").done"
    [ -e "$done_marker" ] && continue
    tshark -n -r "$file" -q -z conv,tcp > "$results_dir/$(basename "$file").conv" \
      2> "$results_dir/$(basename "$file").stderr" && : > "$done_marker"
  done
```

- A marker written only after success makes re-runs idempotent and retries failed files.
- With `files:N` the oldest files are deleted on rotation; a slow job can lose input. Size the ring for the processing lag.
- Schedule with cron, launchd, a systemd timer or Task Scheduler. Use absolute paths to `tshark`; scheduled environments often lack the interactive `PATH` and profile settings.

## Batch processing many captures

For bounded offline runs over a set of captures, use the [batch helper](../scripts/batch_tshark.py). It applies one query to each input in sorted order, gives every input its own run directory with the same execution record as the [bounded runner](../scripts/run_tshark.py), and writes a summary that separates complete from partial or failed inputs:

```sh
python "$skill_dir/scripts/batch_tshark.py" --input-dir "$capture_dir" --pattern '*.pcap*' \
  --output-dir "$new_batch_dir" --timeout 60 --max-output-bytes 4194304 --jobs 4 \
  -- -Y 'dns.flags.rcode != 0' -T fields -E separator=/t \
  -e frame.number -e frame.time_epoch -e dns.qry.name -e dns.flags.rcode
```

`batch.json` lists each input's path, SHA-256, status, coverage, TShark exit code and the paths of its record, stdout and stderr; `counts` separates `complete`, `partial` (timeout, output cap, `-c` input cap or changed input) and `error` (unreadable input or TShark failure) inputs. `summary.tsv` has the essentials in one row per input. Exit status is 0 only when every input completed with full coverage, 1 when any input was partial, failed or changed during the run, and 2 for invalid arguments. The helper accepts the same offline arguments as the runner and rejects capture, file-writing and extension flags. Reduce per-input outputs afterwards, for example:

```sh
jq -r '.runs[] | select(.coverage == "complete") | .stdout' "$new_batch_dir/batch.json" |
  while IFS= read -r out; do cut -f3 "$out"; done | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn
```

Without the helper, a shell loop must handle odd file names and keep per-file status:

```sh
find "$capture_dir" -type f -name '*.pcap*' -print0 | LC_ALL=C sort -z |
  while IFS= read -r -d '' file; do
    id=$(printf '%s' "$file" | shasum -a 256 | cut -c1-16)   # sha256sum on Linux
    tshark -n -r "$file" -q -z io,phs > "$new_out_dir/$id.phs" 2> "$new_out_dir/$id.stderr"
    printf '%s\t%s\t%s\n' "$id" "$?" "$file" >> "$new_out_dir/index.tsv"
  done
```

- Derive output names from a hash or sequence number, not the bare basename: captures in different directories often share names.
- For parallelism prefer the helper's `--jobs`; with `xargs -0 -P` each job still needs its own output and status file, and total memory is roughly jobs × per-TShark memory.
- Frame and stream numbers are per file. Keep the source path with every row before combining results, and see [operations-and-evidence.md](operations-and-evidence.md) before correlating across captures.

## Preparing inputs: merge, split, inspect

Wireshark ships helper programs next to TShark. They are optional on some packages; check they exist before scripting them.

```sh
capinfos -T -c -a -e -u "$capture"                       # tab table: count, first/last time, duration
mergecap -w "$new_merged" "$capture_a" "$capture_b"     # merge by timestamp (-a concatenates instead)
editcap -i 300 "$capture" "$new_split_prefix.pcapng"     # split into 300-second files
editcap -c 100000 "$capture" "$new_split_prefix.pcapng"  # split every 100000 packets
```

- Splitting lets a batch run in parallel and bounds per-run memory, but stream reassembly, `tcp.analysis.*` and conversation statistics lose context at file boundaries. Run stream-dependent questions on the unsplit capture or a filtered derivative.
- `mergecap` interleaves by timestamp; captures from different clocks need a stated correction, not a silent merge. Merged frame numbers no longer match either source.
- These tools write new files; they never modify their inputs. Keep the originals.

## Scripts and CI gates

In a program, call TShark with an argument list, stream stdout and read stderr concurrently:

```python
import csv, subprocess, sys

argv = ["tshark", "-n", "-r", capture, "-Y", "dns.flags.response == 0",
        "-T", "fields", "-E", "separator=/t", "-e", "frame.number", "-e", "dns.qry.name"]
with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                      encoding="utf-8", errors="replace") as proc:
    rows = sum(1 for _ in csv.reader(proc.stdout, delimiter="\t"))
    stderr = proc.stderr.read()
if proc.returncode != 0:
    sys.exit(f"tshark failed ({proc.returncode}): {stderr.strip()}")
```

Reading stderr only after stdout is safe here because TShark's diagnostics are small; for unbounded diagnostics or a hard timeout use [run_tshark.py](../scripts/run_tshark.py), which drains both pipes and enforces limits.

A CI or monitoring gate should fail on an incomplete scan as well as on the threshold:

```sh
python "$skill_dir/scripts/run_tshark.py" --input "$capture" --output-dir "$new_run_dir" \
  -- -Y 'tcp.analysis.retransmission' -T fields -e frame.number || exit 1
jq -e '.coverage.status == "complete"' "$new_run_dir/execution.json" > /dev/null || exit 1
count=$(wc -l < "$new_run_dir/stdout.bin")
[ "$count" -le "$max_retransmissions" ] || { echo "retransmissions=$count"; exit 1; }
```

- Pin the TShark version in CI and record `tshark --version` with results; dissector changes alter field names and counts between releases.
- Use `-o` overrides or a dedicated profile (`-C`) rather than the runner's personal profile, so results do not depend on the machine.
- Windows PowerShell can re-encode native-command pipeline output; let TShark write to a file (`-w`, or redirect in `cmd`) or use the Python pattern above for byte-exact data. Check `$LASTEXITCODE`, not `$?`.

## Reporting automated results

State the exact argv and pipeline, input identity, TShark version, which stages succeeded and whether any stage was a preview. For batches, report how many inputs were complete, partial and failed; an aggregate over complete inputs only must say so. Mark each claim `confirmed`, `likely`, `candidate` or `unresolved` as the skill entrypoint requires; a gate that passed is not, by itself, a root-cause claim.
