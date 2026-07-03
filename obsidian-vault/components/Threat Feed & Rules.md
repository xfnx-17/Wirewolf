---
title: Threat Feed & Rules
type: component
tags: [component, backend, threat-intel]
status: documented
created: 2026-06-26
module: "Threat Intelligence"
---
# Threat Feed & Rules

Loads bad-IP/domain/JA3 indicator lists and signature rules from the rules directory for indicator matching.

## Key Files
- `include/threat_feed.hpp`
- `rules/bad_ips.txt`
- `rules/bad_domains.txt`
- `rules/bad_ja3.txt`
- `rules/signatures.txt`

## Module
[[Threat Intelligence]]

## Dependencies
[[WirewolfConfig]]

## Used By
[[TCP Reassembler]] · [[WinDivert Inline Blocker]]

## Related
[[TLS JA3 Inspector]] · [[Configuration]]

---
#component #backend #threat-intel
