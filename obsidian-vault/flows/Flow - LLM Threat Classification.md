---
title: Flow - LLM Threat Classification
type: flow
tags: [flow]
status: documented
created: 2026-06-26
---
# Flow - LLM Threat Classification

How a surviving flow becomes a structured threat verdict.

## Steps
1. [[Statistical Pre-Filter]] passes a suspicious [[FlowData]]
2. [[Payload Normalizer]] canonicalizes the payload
3. [[LLM Inference Engine]] builds a ChatML few-shot prompt (truncated tail-preserving)
4. Llama 3.1 8B returns JSON (or `[Empty {}]` — [[Hallucination Suppression]])
5. JSON parsed → [[ThreatAlert]] with [[SeverityInfo & Threat Catalog]]

## Related
[[Detection Engine]] · [[Hallucination Suppression]] · [[Architecture]] · [[00 - Project Map (MOC)]]

---
#flow
