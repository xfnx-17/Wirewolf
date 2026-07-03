---
title: IP2Location Tables
type: data
tags: [data, threat-intel]
status: documented
created: 2026-06-26
---
# IP2Location Tables

Compact binary range tables (city/ASN/proxy) with string side-tables, queried by binary search on a numeric IP.

## Key Files
- `flutter_app/assets/geo/`
- `include/proxy_db.hpp`

## Overview
[[Data Models]]

## Relationships
- **N:1** target of many [[ConnectionInfo]] lookups

## Touched By
[[IP2Location Loader]] · [[GeoIP Resolver]] · [[Proxy DB Reader]]

## Related
[[Geo Enrichment]]

---
#data #threat-intel
