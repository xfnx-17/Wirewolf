---
title: TCP Reassembler
type: component
tags: [component, backend, network]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# TCP Reassembler

Reconstructs interleaved/out-of-order TCP segments into continuous application-layer payloads and emits FlowData into the first queue. Hosts the connection-level anomaly logic.

## Key Files
- `include/tcp_reassembly.hpp`
- `src/tcp_reassembly.cpp`

## Module
[[Detection Engine]]

## Dependencies
[[Packet Capture]] · [[Payload Normalizer]] · [[Thread-Safe Queue]] · [[Threat Intelligence]] · [[Connection Anomaly Detector]]

## Used By
[[Pipeline Controller]]

## Data Touched
[[FlowData]] · [[ConnectionInfo]]

## Flows
[[Flow - Offline PCAP Analysis (CLI)]] · [[Flow - Connection Anomaly Detection]]

## Related
[[Statistical Pre-Filter]] · [[Network vs Application Layer]] · [[Behavioral C2 Detector]] (scores each completed connection)

---
#component #backend #network
