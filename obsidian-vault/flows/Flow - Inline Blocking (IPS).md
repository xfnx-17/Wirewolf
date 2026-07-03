---
title: Flow - Inline Blocking (IPS)
type: flow
tags: [flow]
status: documented
created: 2026-06-26
---
# Flow - Inline Blocking (IPS)

Optional active blocking of malicious traffic.

## Steps
1. [[WirewolfConfig]] enables `inline_block` + WinDivert filter
2. A verdict (anomaly or LLM) marks a connection malicious
3. [[WinDivert Inline Blocker]] drops matching packets inline
4. [[Threat Feed & Rules]] allowlist shields critical assets from blocking
5. Blocked counts appear in [[PipelineStats]]

## Related
[[Capture Layer]] · [[Error Handling]] · [[Architecture]] · [[00 - Project Map (MOC)]]

---
#flow
