---
title: ConnectionInfo
type: data
tags: [data, backend, network]
status: documented
created: 2026-06-26
---
# ConnectionInfo

The 5-tuple-ish connection descriptor (src/dst IP+port, proto) stored in network byte order.

## Key Files
- `include/packet_types.hpp`
- `include/wirewolf_types.hpp`

## Overview
[[Data Models]]

## Relationships
- embedded **1:1** in [[FlowData]] and [[ThreatAlert]]

## Touched By
[[Packet Capture]] · [[TCP Reassembler]] · [[Connection Anomaly Detector]]

## Related
[[IP2Location Tables]]

---
#data #backend #network
