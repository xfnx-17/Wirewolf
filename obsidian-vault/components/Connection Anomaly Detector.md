---
title: Connection Anomaly Detector
type: component
tags: [component, backend, network]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# Connection Anomaly Detector

Within the reassembler, flags behavioral anomalies from connection metadata — port scans, SSH brute force, worm/DDoS floods, beaconing, TTL spoofing and TCP-overlap evasion. These alert directly, bypassing the LLM.

## Key Files
- `src/tcp_reassembly.cpp`

## Module
[[Detection Engine]]

## Dependencies
[[Proxy DB Reader]] · [[WirewolfConfig]]

## Used By
[[TCP Reassembler]]

## Data Touched
[[ThreatAlert]] · [[SeverityInfo & Threat Catalog]]

## Flows
[[Flow - Connection Anomaly Detection]]

## Related
[[Threat Tagging & False-Positive Tuning]] · [[Severity & CVSS Scoring]]

---
#component #backend #network
