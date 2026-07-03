---
title: Wirewolf Service
type: component
tags: [component, frontend, api]
status: documented
created: 2026-06-26
module: "Flutter Frontend"
---
# Wirewolf Service

Dart-side engine facade: initializes the dll, exposes config setters and start/stop, and turns FFI poll results into broadcast Streams (alerts/stats/state/flows/logs).

## Key Files
- `flutter_app/lib/ffi/wirewolf_service.dart`

## Module
[[Flutter Frontend]]

## Dependencies
[[Wirewolf Bindings]]

## Used By
[[App Shell]]

## Data Touched
[[AlertData (Dart)]] · [[PipelineStats]]

## Flows
[[Flow - Live Monitoring (Flutter)]]

## Related
[[C FFI API]]

---
#component #frontend #api
