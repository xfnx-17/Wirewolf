---
title: Thread-Safe Queue
type: component
tags: [component, backend]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# Thread-Safe Queue

Bounded blocking MPSC queue (default cap 1024) decoupling stages. In live mode it drops on overflow (tracked); for offline replay it blocks so nothing is lost.

## Key Files
- `include/thread_safe_queue.hpp`

## Module
[[Detection Engine]]

## Used By
[[Pipeline Controller]] · [[TCP Reassembler]] · [[Statistical Pre-Filter]] · [[LLM Inference Engine]]

## Flows
[[Flow - Live Monitoring (Flutter)]]

## Related
[[Backpressure & Queue Drops]] · [[Unit Tests]]

---
#component #backend
