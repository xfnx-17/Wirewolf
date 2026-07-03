---
title: WinDivert Inline Blocker
type: component
tags: [component, backend, network]
status: in-progress
created: 2026-06-26
module: "Capture Layer"
---
# WinDivert Inline Blocker

Optional IPS mode: intercepts and drops malicious packets inline via WinDivert. A `block_allowlist` of critical assets is never blocked, as a safety rail.

## Key Files
- `src/wirewolf_capi.cpp`
- `include/config.hpp`

## Module
[[Capture Layer]]

## Dependencies
[[WirewolfConfig]] · [[Threat Feed & Rules]]

## Used By
[[Pipeline Controller]]

## Flows
[[Flow - Inline Blocking (IPS)]]

## Related
[[Packet Capture]] · [[Error Handling]]

---
#component #backend #network
