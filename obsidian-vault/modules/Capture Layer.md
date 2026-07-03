---
title: Capture Layer
type: module
tags: [module, backend, network]
status: documented
created: 2026-06-26
---
# Capture Layer

Ingest + egress. Sniffs packets from a live Npcap interface or replays a `.pcap`; optionally blocks malicious packets inline via WinDivert (IPS mode).

## Components
[[Packet Capture]] · [[WinDivert Inline Blocker]]

## Child components (live index)
```dataview
LIST WHERE type = "component" AND module = "Capture Layer"
```

## Key Files
- `npcap-sdk/`

## Related
[[Detection Engine]] · [[Configuration]] · [[00 - Project Map (MOC)]] · [[Architecture]]

---
#module #backend #network
