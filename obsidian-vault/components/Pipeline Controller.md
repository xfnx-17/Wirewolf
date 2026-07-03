---
title: Pipeline Controller
type: component
tags: [component, backend]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# Pipeline Controller

The orchestrator. Owns the three stages, the inter-stage queues and worker threads; exposes a non-blocking start/stop lifecycle, a thread-safe stats snapshot, and threat/stats/state/flow callbacks.

## Key Files
- `include/pipeline_controller.hpp`
- `src/pipeline_controller.cpp`

## Module
[[Detection Engine]]

## Dependencies
[[Packet Capture]] · [[TCP Reassembler]] · [[Statistical Pre-Filter]] · [[LLM Inference Engine]] · [[Thread-Safe Queue]] · [[WirewolfConfig]] · [[WinDivert Inline Blocker]]

## Used By
[[C FFI Library]] · [[CLI Entry Point]] · [[ImGui Panels]]

## Data Touched
[[PipelineStats]] · [[ThreatAlert]]

## Flows
[[Flow - Offline PCAP Analysis (CLI)]] · [[Flow - Live Monitoring (Flutter)]]

## Related
[[Architecture]] · [[Error Handling]]

---
#component #backend
