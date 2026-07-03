---
title: App Shell
type: component
tags: [component, frontend]
status: documented
created: 2026-06-26
module: "Flutter Frontend"
---
# App Shell

The Flutter root (`main.dart`): owns shared state (alerts/flows/logs/stats), wires WirewolfService streams to setState, hosts the nav rail, top bar (incl. Clear), and routes screens.

## Key Files
- `flutter_app/lib/main.dart`

## Module
[[Flutter Frontend]]

## Dependencies
[[Wirewolf Service]] · [[Dashboard Screen]] · [[Threat Map Screen]] · [[Secondary Screens]] · [[Command Palette]]

## Data Touched
[[AlertData (Dart)]]

## Related
[[Alert Inspector]] · [[Tasks]]

---
#component #frontend
