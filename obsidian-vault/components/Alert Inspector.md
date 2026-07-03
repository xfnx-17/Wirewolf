---
title: Alert Inspector
type: component
tags: [component, frontend, threat-intel]
status: documented
created: 2026-06-26
module: "Flutter Frontend"
---
# Alert Inspector

Right-side panel showing a selected alert in depth: source/target IP + geo, ISP/ASN, anonymizer and threat-intel banners, CVSS, and the payload snippet.

## Key Files
- `flutter_app/lib/panels/alert_inspector.dart`
- `flutter_app/lib/panels/alert_detail_panel.dart`

## Module
[[Flutter Frontend]]

## Dependencies
[[GeoIP Resolver]]

## Used By
[[Dashboard Screen]] · [[App Shell]]

## Data Touched
[[AlertData (Dart)]]

## Related
[[Host Telemetry]] · [[Threat Tagging & False-Positive Tuning]]

---
#component #frontend #threat-intel
