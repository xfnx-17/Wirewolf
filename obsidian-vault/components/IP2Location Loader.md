---
title: IP2Location Loader
type: component
tags: [component, frontend, threat-intel]
status: documented
created: 2026-06-26
module: "Geo Enrichment"
---
# IP2Location Loader

Loads the compact binary range tables (city/ASN/proxy) and does binary-search lookups. CSVs are pre-processed by the converter tool into `.bin` + `.str` files.

## Key Files
- `flutter_app/lib/ffi/ip2location.dart`
- `flutter_app/tool/convert_ip2location.dart`
- `flutter_app/assets/geo/`

## Module
[[Geo Enrichment]]

## Used By
[[GeoIP Resolver]]

## Data Touched
[[IP2Location Tables]]

## Related
[[Proxy DB Reader]] · [[Geo Enrichment]]

---
#component #frontend #threat-intel
