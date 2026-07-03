---
title: Error Handling
type: meta
tags: [meta]
status: in-progress
created: 2026-06-26
---
# Error Handling

Failure surfaces: pipeline error state + last-error string (over FFI), dropped-item tracking, IPS allowlist safety rail, and LLM hallucination guards.

## Mechanisms
- Pipeline `Error` state + `get_last_error` → [[FFI Lifecycle & Control]]
- Queue drop tracking → [[Backpressure & Queue Drops]]
- Block allowlist safety → [[WinDivert Inline Blocker]]
- Output validation → [[Hallucination Suppression]]

## Related
[[Logging]] · [[Pipeline Controller]] · [[00 - Project Map (MOC)]]

---
#meta
