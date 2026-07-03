---
title: Flow - Live Monitoring (Flutter)
type: flow
tags: [flow]
status: documented
created: 2026-06-26
---
# Flow - Live Monitoring (Flutter)

The desktop GUI drives a live capture and renders results.

## Steps
1. [[App Shell]] → [[Wirewolf Service]] `initialize` (dlopen) via [[Wirewolf Bindings]] → [[C FFI Library]]
2. [[FFI Configuration]] setters populate [[WirewolfConfig]] (incl. threat DB)
3. [[FFI Lifecycle & Control]] `start` → [[Pipeline Controller]]
4. Engine runs ([[Packet Capture]] → … → [[LLM Inference Engine]])
5. Poll timers call [[FFI Event Polling]] → Streams → `setState`
6. [[Dashboard Screen]] / [[Alert Inspector]] render, enriched by [[GeoIP Resolver]]

## Related
[[Flutter Frontend]] · [[Geo Enrichment]] · [[Architecture]] · [[00 - Project Map (MOC)]]

---
#flow
