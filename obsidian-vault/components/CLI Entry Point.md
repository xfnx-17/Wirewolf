---
title: CLI Entry Point
type: component
tags: [component, backend]
status: documented
created: 2026-06-26
module: "Interfaces & FFI"
---
# CLI Entry Point

The `wirewolf` executable. Parses args into WirewolfConfig, registers a stdout alert callback, starts the controller, and blocks until the capture finishes or SIGINT.

## Key Files
- `cli/main.cpp`

## Module
[[Interfaces & FFI]]

## Dependencies
[[WirewolfConfig]] · [[Pipeline Controller]] · [[Logger]]

## Flows
[[Flow - Offline PCAP Analysis (CLI)]]

## Related
[[Build System]]

---
#component #backend
