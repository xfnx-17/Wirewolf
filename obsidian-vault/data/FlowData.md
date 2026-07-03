---
title: FlowData
type: data
tags: [data, backend]
status: documented
created: 2026-06-26
---
# FlowData

A reassembled flow: the application-layer payload plus its connection metadata, passed between pipeline stages.

## Key Files
- `include/wirewolf_types.hpp`
- `include/packet_types.hpp`

## Overview
[[Data Models]]

## Relationships
- **1:1** [[ConnectionInfo]] · produced by [[TCP Reassembler]], consumed by [[Statistical Pre-Filter]] / [[LLM Inference Engine]]

## Touched By
[[TCP Reassembler]] · [[Statistical Pre-Filter]] · [[LLM Inference Engine]]

## Related
[[Network vs Application Layer]]

---
#data #backend
