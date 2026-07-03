---
title: GeoIP Resolver
type: component
tags: [component, frontend, threat-intel]
status: documented
created: 2026-06-26
module: "Geo Enrichment"
---
# GeoIP Resolver

Dart façade resolving any IP to city/lat-lng, ISP/ASN, anonymizer status and threat tags; returns null for private addresses so the map only plots real locations.

## Key Files
- `flutter_app/lib/ffi/geo_ip.dart`

## Module
[[Geo Enrichment]]

## Dependencies
[[IP2Location Loader]]

## Used By
[[Alert Inspector]] · [[Host Telemetry]] · [[Threat Map Screen]]

## Data Touched
[[IP2Location Tables]]

## Flows
[[Flow - Threat Map Visualization]]

## Related
[[Proxy DB Reader]]

---
#component #frontend #threat-intel
