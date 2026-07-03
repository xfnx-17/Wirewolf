---
title: C FFI Library
type: component
tags: [component, backend, api]
status: documented
created: 2026-06-26
module: "Interfaces & FFI"
---
# C FFI Library

The `wirewolf_ffi` shared lib — a flat C ABI wrapping PipelineController so non-C++ frontends create a handle, set config, register callbacks / poll events, and start/stop.

## Key Files
- `include/wirewolf_capi.h`
- `src/wirewolf_capi.cpp`

## Module
[[Interfaces & FFI]]

## Dependencies
[[Pipeline Controller]] · [[WirewolfConfig]]

## Used By
[[Wirewolf Bindings]]

## Data Touched
[[ThreatAlert]] · [[PipelineStats]] · [[FlowEvent]] · [[LogEntry]]

## Flows
[[Flow - Live Monitoring (Flutter)]]

## Related
[[C FFI API]] · [[Build System]]

---
#component #backend #api
