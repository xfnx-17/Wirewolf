---
title: LLM Inference Engine
type: component
tags: [component, backend, ml]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# LLM Inference Engine

Runs a quantized Llama-3.1-8B-Instruct via llama.cpp on CUDA. Uses a strict ChatML few-shot template with hallucination suppression and tail-preserving truncation, emitting structured JSON parsed into a ThreatAlert.

## Key Files
- `include/llm_inference.hpp`
- `src/llm_inference.cpp`

## Module
[[Detection Engine]]

## Dependencies
[[Thread-Safe Queue]] · [[WirewolfConfig]] · [[Environment & Models]]

## Used By
[[Pipeline Controller]]

## Data Touched
[[ThreatAlert]] · [[SeverityInfo & Threat Catalog]]

## Flows
[[Flow - LLM Threat Classification]]

## Related
[[Hallucination Suppression]] · [[Statistical Pre-Filter]]

---
#component #backend #ml
