---
title: WirewolfConfig
type: component
tags: [component, backend, config]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# WirewolfConfig

Single config struct + CLI parser that parameterizes every stage: capture source, queue capacity, payload/token limits, model paths, OpenVINO toggle, GPU layers, rules dir, threat DB and inline-block options.

## Key Files
- `include/config.hpp`

## Module
[[Detection Engine]]

## Used By
[[Pipeline Controller]] · [[CLI Entry Point]] · [[C FFI Library]]

## Data Touched
[[ConnectionInfo]]

## Related
[[Configuration]] · [[Unit Tests]]

---
#component #backend #config
