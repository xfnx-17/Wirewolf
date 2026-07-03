---
title: FFI Lifecycle & Control
type: api
tags: [api]
status: documented
created: 2026-06-26
---
# FFI Lifecycle & Control

Handle creation and pipeline control.

## Endpoints
- `wirewolf_create()` → `WirewolfHandle`
- `wirewolf_destroy(h)`
- `wirewolf_start(h)` → int (1 = ok)
- `wirewolf_stop(h)`
- `wirewolf_get_state(h)` · `wirewolf_get_last_error(h, buf, n)`
- `wirewolf_list_interfaces(out, max)`

## Drives
[[Pipeline Controller]]

## Flows
[[Flow - Live Monitoring (Flutter)]]

## Part of
[[C FFI API]]

## Implemented by
[[C FFI Library]]

---
#api
