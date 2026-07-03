---
title: Statistical Pre-Filter
type: component
tags: [component, backend, ml]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# Statistical Pre-Filter

The NpuFilter — a cheap gate before the LLM. Scores flows on entropy, packet-length variance, inter-arrival timing and suspicious-character ratio, dropping ~85% of benign traffic; also runs content heuristics (FTP exfil, credential content, HTTP brute force).

## Key Files
- `include/npu_filter.hpp`
- `src/npu_filter.cpp`

## Module
[[Detection Engine]]

## Dependencies
[[Payload Normalizer]] · [[Thread-Safe Queue]] · [[OpenVINO Accelerator]] · [[WirewolfConfig]]

## Used By
[[Pipeline Controller]]

## Data Touched
[[FlowData]] · [[FlowEvent]]

## Flows
[[Flow - LLM Threat Classification]]

## Related
[[Entropy Analysis]] · [[TCP Reassembler]] · [[Benchmarking & Datasets]]

---
#component #backend #ml
