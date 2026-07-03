---
title: FFI Event Polling
type: api
tags: [api]
status: documented
created: 2026-06-26
---
# FFI Event Polling

Callback registration and poll-based draining of events (the Flutter side polls on a timer).

## Endpoints
- `set_alert_callback` · `set_state_callback` · `set_flow_event_callback` · `set_log_callback`
- `wirewolf_poll_alerts` · `wirewolf_poll_flow_events` · `wirewolf_poll_logs`
- `wirewolf_get_stats(h, out)`

## Produces
[[ThreatAlert]] · [[FlowEvent]] · [[LogEntry]] · [[PipelineStats]]

## Consumed by
[[Wirewolf Service]]

## Part of
[[C FFI API]]

## Implemented by
[[C FFI Library]]

---
#api
