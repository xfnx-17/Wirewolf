---
title: 00 - Project Map (MOC)
type: moc
tags: [moc]
status: documented
created: 2026-06-26
---
# 00 - Project Map (MOC)

Hub for the Wirewolf knowledge graph — a local AI-driven network intrusion detection/prevention system (C++20 engine + Flutter desktop GUI). Every major area links from here; any note is reachable in ≤2 hops.

## Orientation
Start with [[Architecture]] and [[Tech Stack]]. Domain terms live in [[Glossary]]. Key design decision: [[Operating Modes (Live NIDS vs Forensic)]]. Botnet behavior modelling: [[Markov Behavioral Detection]].

## Modules
[[Capture Layer]] · [[Detection Engine]] · [[Threat Intelligence]] · [[Interfaces & FFI]] · [[Flutter Frontend]] · [[Native GUI]] · [[Geo Enrichment]]

## Data & API
[[Data Models]] · [[C FFI API]]

## Flows
[[Flow - Offline PCAP Analysis (CLI)]] · [[Flow - Live Monitoring (Flutter)]] · [[Flow - Connection Anomaly Detection]] · [[Flow - LLM Threat Classification]] · [[Flow - Inline Blocking (IPS)]] · [[Flow - Threat Map Visualization]]

## Meta
[[Configuration]] · [[Environment & Models]] · [[Logging]] · [[Error Handling]] · [[Testing Strategy]] · [[Build System]] · [[CI-CD]] · [[Deployment]] · [[External Dependencies]] · [[Documentation Status]] · [[Orphan Check]] · [[Tasks]]

## All notes by type
```dataview
TABLE type, status, join(file.etags, ", ") AS tags
WHERE type != "moc"
SORT type ASC, file.name ASC
```

---
#moc
