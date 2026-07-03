---
title: Threat Intelligence
type: module
tags: [module, backend, threat-intel]
status: documented
created: 2026-06-26
---
# Threat Intelligence

Indicator matching that augments behavioral detection: bad IP/domain/JA3 lists, signatures, a binary IP2Proxy threat DB, and TLS fingerprinting.

## Components
[[Proxy DB Reader]] · [[Threat Feed & Rules]] · [[TLS JA3 Inspector]]

## Child components (live index)
```dataview
LIST WHERE type = "component" AND module = "Threat Intelligence"
```

## Related
[[Detection Engine]] · [[Geo Enrichment]] · [[00 - Project Map (MOC)]] · [[Architecture]]

---
#module #backend #threat-intel
