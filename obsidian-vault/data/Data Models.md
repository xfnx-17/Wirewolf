---
title: Data Models
type: data
tags: [data]
status: documented
created: 2026-06-26
---
# Data Models

Overview of the core data structures that flow through the system and their relationships.

## Entities
[[ThreatAlert]] · [[FlowData]] · [[ConnectionInfo]] · [[SeverityInfo & Threat Catalog]] · [[PipelineStats]] · [[FlowEvent]] · [[LogEntry]] · [[AlertData (Dart)]] · [[IP2Location Tables]]

## Relationships
- [[FlowData]] **1:1** [[ConnectionInfo]] (each flow has one connection tuple)
- [[ThreatAlert]] **1:1** [[ConnectionInfo]] and **1:1** [[SeverityInfo & Threat Catalog]]
- [[ThreatAlert]] (C++) **maps to** [[AlertData (Dart)]] across the [[C FFI API]] **1:1**
- [[ConnectionInfo]] **N:1** [[IP2Location Tables]] (many IPs resolve into the range tables)

## Related
[[C FFI API]] · [[00 - Project Map (MOC)]] · [[Architecture]]

---
#data
