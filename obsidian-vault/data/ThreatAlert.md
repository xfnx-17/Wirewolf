---
title: ThreatAlert
type: data
tags: [data, backend]
status: documented
created: 2026-06-26
---
# ThreatAlert

The canonical alert struct: threat type, severity/CVSS, connection tuple, snippet, confidence and raw LLM output.

## Key Files
- `include/wirewolf_types.hpp`

## Overview
[[Data Models]]

## Relationships
- **1:1** [[ConnectionInfo]] · **1:1** [[SeverityInfo & Threat Catalog]] · maps to [[AlertData (Dart)]]

## Touched By
[[LLM Inference Engine]] · [[Connection Anomaly Detector]] · [[Pipeline Controller]] · [[C FFI Library]]

## Related
[[Severity & CVSS Scoring]]

---
#data #backend
