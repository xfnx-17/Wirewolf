---
title: Flow - Threat Map Visualization
type: flow
tags: [flow]
status: documented
created: 2026-06-26
---
# Flow - Threat Map Visualization

How alerts become the attacker→victim world map.

## Steps
1. [[App Shell]] passes alerts to [[Threat Map Screen]]
2. Each endpoint resolved by [[GeoIP Resolver]] (private → omitted)
3. Nodes coloured by role (attacker/target); arcs drawn external→external
4. Side list ranks attackers/targets; a row opens [[Host Telemetry]]
5. [[IP2Location Loader]] supplies city/ASN/proxy data

## Related
[[Geo Enrichment]] · [[Flutter Frontend]] · [[Architecture]] · [[00 - Project Map (MOC)]]

---
#flow
