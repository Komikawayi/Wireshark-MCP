# Capture and input

## Discover before collecting

`tshark -D` lists interfaces. `tshark -i <interface> -L` lists link types; `--list-time-stamp-types` lists timestamp methods. Select an explicit adapter. Drivers/permissions vary (libpcap/Npcap, monitor-mode hardware, remote support and installed extcaps). Interface discovery may invoke installed extcap executables; inspect unfamiliar providers before using them.

For live collection requested by the task, use a bounded capture:

```sh
tshark -n -i "$interface" -f 'host 192.0.2.10 and tcp port 443' \
  -a duration:30 -a filesize:10000 -w "$new_capture"
```

Reserved example addresses are placeholders. `-f` is libpcap/BPF, not display-filter syntax: `tcp.port == 443` belongs to `-Y`. Capture filtering permanently excludes packets. `-s` limits captured bytes per packet; truncation can destroy content/reassembly evidence. `-p` disables promiscuous mode but does not guarantee host-only traffic. `-I` requests monitor mode and may disconnect Wi-Fi; use only for an intentional wireless capture.

`-B` sets kernel buffer MiB, not an output budget. `-y` selects a discovered link type; `--time-stamp-type` selects a supported source. With repeated `-i`, placement of per-interface options such as `-f`, `-s`, `-B`, `-p`, `-I`, `-y` matters: defaults before the first interface and overrides after each interface must be deliberate. Multi-interface capture uses pcapng to preserve interface metadata.

## Stop and rotate

| Option | Meaning / distinction |
|---|---|
| `-c N` | N input packets, including packets failing a display filter; works offline too |
| `-a duration:N` | Duration stop; not a display-filter time window |
| `-a filesize:N` | File-size condition in kB, not MiB or a strict global storage quota |
| `-a files:N`, `-a packets:N` | Files / packets-written conditions; packets-written can differ from `-c` |
| `-b duration:N`, `-b filesize:N`, `-b packets:N` | Rotate at duration/size/packet thresholds |
| `-b interval:N` | Rotate on aligned wall-clock multiples of N seconds |
| `-b files:N` | Bounded ring that replaces earlier files |
| `-b printname:FILE` | Record completed filenames; supports stdout/stderr |
| `-b nametimenum:N` | Filename ordering where supported; consult the installed manual |

Example: `tshark -i "$interface" -b filesize:10000 -b files:5 -a duration:60 -w "$new_capture"`. Use a dedicated directory; a ring is not an immutable archive. Monitor total storage including logs/exports. For sustained acquisition prefer dumpcap collection followed by offline TShark dissection when appropriate; do not assume line-rate dissection.

## Offline, pipes and remote input

- `-r "$capture"` detects supported input formats by content, including compression when a codec exists. A suffix does not establish type. `-X read_format:<format>` forces a discovered reader for ambiguous input.
- `-r -` reads capture bytes from stdin. `-i -`, FIFO or Windows named pipe is a capture source, not text. `TCP@host:port` reads a capture stream where supported. Confirm format and endianness constraints in the installed manual.
- `-2` requires seeking; materialize a bounded copy before two-pass analysis of a pipe. Never apply two-pass assumptions to an infinite live source.
- Remote `rpcap://` support is build-dependent; `-A user:password` supplies remote authentication where available. Avoid recording credentials in command logs/process listings. Extcap providers such as sshdump have their own configuration, not arbitrary TShark flags.

Record source/interface, filter, snaplen, time basis, stop policy, exit status and available drop counters. A completed command does not certify visibility of the whole network.

Sources: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html), [BPF syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html).

## Long-option aliases

The same controls are spelled `--interface` (`-i`), `--list-interfaces` (`-D`), `--read-file` (`-r`), `--list-data-link-types` (`-L`), `--linktype` (`-y`), `--snapshot-length` (`-s`), `--buffer-size` (`-B`), `--monitor-mode` (`-I`), `--no-promiscuous-mode` (`-p`), `--autostop` (`-a`) and `--ring-buffer` (`-b`). They do not change the short options' stage, units or per-interface placement semantics.
