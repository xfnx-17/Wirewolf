---
title: SeverityInfo & Threat Catalog
type: data
tags: [data, backend]
status: documented
created: 2026-06-26
---
# SeverityInfo & Threat Catalog

Severity enum + CVSS score, and the static map from threat-type string → severity (Log4Shell 10.0, SQLi 9.3, …).

## Key Files
- `include/wirewolf_types.hpp`

## Overview
[[Data Models]]

## Relationships
- referenced **1:1** by each [[ThreatAlert]]

## Touched By
[[LLM Inference Engine]] · [[Connection Anomaly Detector]]

## Related
[[Severity & CVSS Scoring]]

---
#data #backend
