---
title: Flow - Offline PCAP Analysis (CLI)
type: flow
tags: [flow]
status: documented
created: 2026-06-26
---
# Flow - Offline PCAP Analysis (CLI)

Replay a capture file through the full pipeline from the command line.

## Steps
1. [[CLI Entry Point]] parses args → [[WirewolfConfig]]
2. [[Pipeline Controller]] starts; queues set to **blocking** (offline)
3. [[Packet Capture]] reads the `.pcap`
4. [[TCP Reassembler]] → [[FlowData]] → [[Thread-Safe Queue]]
5. [[Statistical Pre-Filter]] gates flows → queue
6. [[LLM Inference Engine]] classifies → [[ThreatAlert]]
7. `on_threat_detected` prints the alert to stdout

## Related
[[Detection Engine]] · [[Benchmarking & Datasets]] · [[Architecture]] · [[00 - Project Map (MOC)]]

---
#flow
