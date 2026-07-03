---
title: Packet Capture
type: component
tags: [component, backend, network]
status: documented
created: 2026-06-26
module: "Capture Layer"
---
# Packet Capture

Reads raw packets from a live Npcap interface or an offline `.pcap`. Interface enumeration is exposed via `PipelineController::list_interfaces()`.

## Key Files
- `src/pipeline_controller.cpp`
- `include/packet_types.hpp`
- `npcap-sdk/`

## Module
[[Capture Layer]]

## Dependencies
[[WirewolfConfig]]

## Used By
[[Pipeline Controller]] · [[TCP Reassembler]]

## Data Touched
[[ConnectionInfo]]

## Flows
[[Flow - Offline PCAP Analysis (CLI)]] · [[Flow - Live Monitoring (Flutter)]]

## Related
[[WinDivert Inline Blocker]] · [[Network vs Application Layer]]

---
#component #backend #network
