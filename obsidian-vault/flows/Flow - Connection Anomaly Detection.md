---
title: Flow - Connection Anomaly Detection
type: flow
tags: [flow]
status: documented
created: 2026-06-26
---
# Flow - Connection Anomaly Detection

Behavioral alerts derived from connection metadata, bypassing the LLM.

## Steps
1. [[Packet Capture]] feeds [[TCP Reassembler]]
2. [[Connection Anomaly Detector]] tracks per-connection counters
3. Thresholds trip (port scan ≥50, SSH brute, worm/DDoS, beaconing, TTL spoof, overlap evasion)
4. [[Proxy DB Reader]] adds BOTNET/SCANNER/SPAM tags for external IPs
5. A [[ThreatAlert]] is emitted directly with [[SeverityInfo & Threat Catalog]]

## Related
[[Detection Engine]] · [[Threat Tagging & False-Positive Tuning]] · [[Architecture]] · [[00 - Project Map (MOC)]]

---
#flow
