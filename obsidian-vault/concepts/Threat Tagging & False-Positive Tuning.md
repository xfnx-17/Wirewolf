---
title: Threat Tagging & False-Positive Tuning
type: concept
tags: [concept, threat-intel]
status: documented
created: 2026-06-26
---
# Threat Tagging & False-Positive Tuning

Only curated tags (BOTNET/SCANNER/SPAM) alert; "is a proxy/VPN" never alerts alone. Detectors are scoped (e.g. IP-spoofing only for private sources) to avoid FP storms on anycast/OCSP/TLS traffic.

## Related
[[Connection Anomaly Detector]] · [[Proxy DB Reader]] · [[Alert Inspector]] · [[Glossary]]

---
#concept #threat-intel
