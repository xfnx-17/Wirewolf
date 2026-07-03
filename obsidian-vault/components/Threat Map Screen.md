---
title: Threat Map Screen
type: component
tags: [component, frontend]
status: documented
created: 2026-06-26
module: "Flutter Frontend"
---
# Threat Map Screen

WebView2-embedded flat world map rendering an attacker→victim graph: external endpoints geolocated, coloured by role (red attacker / blue target), with animated arcs. Side list ranks attackers/targets; rows open Host Telemetry.

## Key Files
- `flutter_app/lib/screens/threat_map_screen.dart`
- `flutter_app/assets/globe/index.html`
- `flutter_app/assets/globe/world.js`

## Module
[[Flutter Frontend]]

## Dependencies
[[GeoIP Resolver]] · [[Host Telemetry]]

## Used By
[[App Shell]]

## Data Touched
[[AlertData (Dart)]]

## Flows
[[Flow - Threat Map Visualization]]

## Related
[[Geo Enrichment]]

---
#component #frontend
