---
title: Payload Normalizer
type: component
tags: [component, backend]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# Payload Normalizer

Decodes/normalizes payloads (percent-decoding incl. %uXXXX) so heuristics and the LLM see canonical text rather than obfuscated input.

## Key Files
- `include/payload_normalizer.hpp`

## Module
[[Detection Engine]]

## Used By
[[TCP Reassembler]] · [[Statistical Pre-Filter]]

## Related
[[Network vs Application Layer]]

---
#component #backend
