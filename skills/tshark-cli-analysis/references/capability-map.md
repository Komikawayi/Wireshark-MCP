# Full capability map

Read this short routing index for unfamiliar capabilities; skip it when the task already maps to a guide in SKILL.md. The reviewed baseline covers **93 option spellings/aliases, 18 glossary reports and 197 registered statistics/follow names**. Option coverage includes manual-only entries not shown in the local help. See [sources and versioning](sources-and-versioning.md) for provenance and how coverage is checked.

All installed protocol fields, dissectors, preference keys, output codecs and extcap providers are discovered through their registries. They are open-ended extension surfaces, not a finite list that this document can truthfully freeze for every future build. Every capability family below has execution guidance and limitations; future unknown options/reports/taps are explicit coverage gaps.

| Capability | Guide |
|---|---|
| Acquisition, filters, adapters, ring buffers, pipes and remote sources | [Capture and input](capture-and-input.md) |
| Read/display filters, packet vs occurrence semantics, two-pass and state resets | [Filters and fields](filters-and-fields.md) |
| All text/tree/structured formats, writing/conversion, objects/PDUs/keys | [Output and export](output-and-export.md) |
| All native statistics families and all stream/substream follow facilities | [Statistics and streams](statistics-and-streams.md) |
| Decode As, profiles/UAT, reassembly, decryption and name resolution | [Decode and decrypt](decode-and-decrypt.md) |
| Every glossary, Lua/compiled plugins, extcap, environment/logging and profiling | [Extensions and environment](extensions-and-environment.md) |

For one exact option, search [option-index.md](option-index.md) rather than loading the whole index. For report/statistic names, search [capability-catalog.json](capability-catalog.json) or the installed registries.
