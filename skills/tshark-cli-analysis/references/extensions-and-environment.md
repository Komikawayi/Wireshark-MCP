# Registries, extensions, environment and diagnostics

## Every glossary/report family

Use `-G help` first. The baseline reports are `column-formats`, `currentprefs`, `decodes`, `defaultprefs`, `dissector-tables`, `dissectors`, `elastic-mapping`, `enterprises`, `fieldcount`, `fields`, `folders`, `ftypes`, `heuristic-decodes`, `manuf`, `plugins`, `protocols`, `services`, and `values`. They are capability/configuration data, not observations in a capture. Output structure differs by report and version. `fields,prefix` and filtered elastic mappings are version-dependent; avoid dumping every field into Agent context.

Store full registries as local artifacts, search exact abbreviations and preserve version/profile/plugin provenance. `currentprefs`, `folders` and plugin listings can expose local paths/key references; redact before sharing. The [catalog](capability-catalog.json) and [inventory helper](../scripts/tshark_inventory.py) keep report coverage auditable. A later version adding a report should trigger a documentation-gap review.

## Lua and compiled plugins

`-X lua_script:<file>` loads a selected Lua script; repeated `-X lua_scriptN:<argument>` sends arguments to the Nth script. Lua may provide dissectors, taps and capture readers/writers; compiled plugins add engine capabilities too. Inspect scripts and dependencies before execution; loading a capture is not authorization to load a script named inside it. Plugin load order, Lua runtime and ABI can vary by release. Record plugin versions/hashes and verify registration before making protocol conclusions. Use `-G plugins`, `-G dissectors` and `-G folders` to discover actual locations, not hard-coded OS paths.

`-X read_format:<format>` chooses a capture reader, not a display format. Other `-X` extensions are version-specific; consult the installed manual or provider before use. Custom Lua taps are useful for a recurring reduction, but do not replace a supported native statistic with fresh code for every query.

## Extcap

Extcap providers are separate executables that implement interface, configuration and capture discovery (`--extcap-interfaces`, `--extcap-interface`, `--extcap-config`, `--extcap-dlts`, capture/FIFO controls). These are provider flags, not generic TShark flags. Inspect the installed provider's help/version, discover interfaces, then use the supported TShark interface workflow or the provider's documented pipe workflow. Remote credentials and hardware initialization have side effects; use only for the requested acquisition, not offline triage.

## Runtime configuration

`WIRESHARK_CONFIG_DIR` relocates personal configuration; inspect `-G folders` to confirm. `XDG_CONFIG_HOME`, `HOME`/Windows application-data directories, global data/plugin/extcap locations and named profile/UAT files affect startup. Record relevant overrides rather than copying an entire environment (which may contain secrets). `WIRESHARK_DATA_DIR`, `WIRESHARK_PLUGIN_DIR` and extcap path overrides have build/platform rules; discover supported names from installed documentation. `--temp-dir` chooses temporary storage and does not cap its size.

Logging supports `--log-level`, `--log-domains`, `--log-debug`, `--log-noisy`, `--log-file`; corresponding `WIRESHARK_LOG_*` variables can affect output. `--log-fatal` and `--log-fatal-domains` deliberately abort on selected messages, so they are debugging controls, not routine analysis defaults. `WIRESHARK_ABORT_ON_DISSECTOR_BUG` and `WIRESHARK_ABORT_ON_TOO_MANY_ITEMS` are diagnostic crash controls. Retain stderr and exit status, including configuration/UAT warnings emitted before packet processing.

`--print-timers` emits pass/dissection/filter timing JSON where supported. Keep it separate from packet output, record pass count, input and decode settings, and distinguish startup from steady-state work. Timings do not establish answer correctness. `--help`/`--version` describe the actual build; new documented-but-not-help-listed flags still need a trial or manual check (e.g. remote authentication or timers).

Sources: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [Lua support](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html), [extcap](https://www.wireshark.org/docs/man-pages/extcap.html).
