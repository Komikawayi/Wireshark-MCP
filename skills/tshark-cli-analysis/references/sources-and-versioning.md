# Sources, version coverage and updates

Checked 2026-10-16 against the official manual source tag `v4.6.9` and installed TShark 4.6.9 (`2d548b197c75`, macOS arm64). The website can track a different release; prefer the installed manual/registry for execution. The catalog is a reviewed inventory, not a claim of universal platform support.

## Primary sources

- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html): command grammar and all capability families.
- [Pinned TShark source](https://github.com/wireshark/wireshark/blob/v4.6.9/doc/man_pages/tshark.adoc), [shared dissection options](https://github.com/wireshark/wireshark/blob/v4.6.9/doc/man_pages/dissection-options.adoc), [diagnostic options](https://github.com/wireshark/wireshark/blob/v4.6.9/doc/man_pages/diagnostic-options.adoc): include manual-only flags, not just `--help`.
- [Display-filter manual](https://www.wireshark.org/docs/man-pages/wireshark-filter.html) and [official field reference](https://www.wireshark.org/docs/dfref/): field types, repeated values and exact protocol names.
- [BPF manual](https://www.tcpdump.org/manpages/pcap-filter.7.html): acquisition filters, distinct from display filters.
- [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html), [capinfos](https://www.wireshark.org/docs/man-pages/capinfos.html), [editcap](https://www.wireshark.org/docs/man-pages/editcap.html), [mergecap](https://www.wireshark.org/docs/man-pages/mergecap.html), [text2pcap](https://www.wireshark.org/docs/man-pages/text2pcap.html): companion tools, not TShark subcommands.
- [Lua API](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html), [extcap contract](https://www.wireshark.org/docs/man-pages/extcap.html): programmable dissectors/taps/readers and external acquisition.
- [TLS](https://wiki.wireshark.org/TLS), [WLAN decryption](https://wiki.wireshark.org/HowToDecrypt802.11), [Expert Info](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvExpert.html): prerequisites and interpretation limits.

References summarize decision-relevant semantics and add original workflow examples; they do not embed a copied manual, full field database or opaque third-party recipes. Full registry output belongs in versioned local artifacts, not the skill entrypoint.

## Recheck on an engine/plugin upgrade

```sh
python "$skill_dir/scripts/tshark_inventory.py" --output "$new_inventory_json" --check
```

The helper executes only version/help/report-list/statistic-list discovery. It saves argv, actual return codes, stdout/stderr, parsed capabilities, new undocumented items and baseline items unavailable in this build. Expected discovery error exits are not silently normalized to successful analysis. Empty or failed discovery does not pass coverage.

For additions, read the corresponding installed/official grammar, add a reference section/example and catalog mapping, and run targeted tests. Do not auto-accept a new flag because its name looks familiar. Removed items are compatibility differences; do not require a Linux/Windows build to contain every macOS tap. Record plugin-specific additions. Reinspect manual-only options and include files on version bumps; local help alone is not sufficient.

Run the repository skill validation, catalog-coverage tests and real-engine smoke tests. Review actual behavior separately: a complete option index is not proof that an Agent selected the right operation or reached a justified conclusion.
