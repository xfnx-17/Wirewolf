---
title: Backpressure & Queue Drops
type: concept
tags: [concept, backend]
status: documented
created: 2026-06-26
---
# Backpressure & Queue Drops

Bounded queues protect the live capture: when full they drop (tracked in stats) so capture never stalls; offline replay switches to blocking so nothing is lost.

## Related
[[Thread-Safe Queue]] · [[PipelineStats]] · [[Glossary]]

---
#concept #backend
