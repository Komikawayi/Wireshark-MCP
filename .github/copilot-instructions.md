# GitHub Copilot Repository Instructions

For packet capture, protocol analysis, network security monitoring, incident response, and troubleshooting tasks, prefer the canonical project skill in `skills/wireshark-traffic-analysis/`.

Use the skill to:

- start with the supplied question; use `wireshark_open_file` and broad context only for unfamiliar input
- use `wireshark_aggregate` for full-capture statistics instead of extrapolating from a page
- choose the correct playbook before drilling into packets
- separate observation from interpretation
- report exact filters, stream indexes, frame numbers, and confidence

Do not treat `Expert Info` or a single heuristic as proof on their own.

For explicitly selected terminal execution, use `skills/tshark-cli-analysis/SKILL.md` instead. Keep the same evidence/coverage standards; do not run both workflows by default.
