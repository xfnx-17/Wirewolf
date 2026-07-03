---
title: Proxy DB Reader
type: component
tags: [component, backend, threat-intel]
status: documented
created: 2026-06-26
module: "Threat Intelligence"
---
# Proxy DB Reader

Reads the binary IP2Proxy table (sorted range rows + string side-table) and resolves an IP to proxy type/usage and BOTNET/SCANNER/SPAM threat tags via binary search.

## Key Files
- `include/proxy_db.hpp`

## Module
[[Threat Intelligence]]

## Dependencies
[[WirewolfConfig]]

## Used By
[[Connection Anomaly Detector]]

## Data Touched
[[IP2Location Tables]]

## Related
[[Threat Tagging & False-Positive Tuning]] · [[IP2Location Loader]]

---
#component #backend #threat-intel
