---
title: Markov Behavioral Detection
type: concept
tags: [concept, ml, threat-intel]
status: documented
created: 2026-06-27
---
# Markov Behavioral Detection

A way to detect botnets by **how connections behave over time** rather than by payload content or fixed thresholds. Inspired by the well-known behavioral-state-string idea (clean-room — our own buckets/alphabet/code, no Stratosphere/Slips code or models).

## How it works
1. **Encode** each flow as two characters: a **letter** from (total-bytes bucket × duration bucket) and a **symbol** from the inter-arrival gap (periodicity). A connection (4-tuple) becomes a string like `d.d*d-d*`.
2. **Train** a first-order Markov model per class (Botnet, Normal) — a transition matrix over the character alphabet with **add-k (Laplace) smoothing**.
3. **Score** a connection by the **log-likelihood ratio** `score_botnet − score_normal`; flag if it exceeds a threshold.
4. The **threshold** trades precision vs recall (sweep it — ~−0.25 balanced in-distribution; higher for fewer false alarms / cross-family).

## Why it complements the other detectors
- Catches periodic, low-byte beaconing patterns that look benign per-packet.
- Generalizes to *unseen* botnet families (partially) without a signature — unlike [[Threat Feed & Rules]].
- Distinct from the timing-only [[Connection Anomaly Detector]] (which uses interval regularity) and the content-based [[Statistical Pre-Filter]] / LLM.

## Honest limits
- Behavioral signatures are partly **family-specific** (cross-family F1 drops ~0.91→0.70).
- Trained on **NetFlow** (`.binetflow`); the live engine derives flows from **pcap** — a granularity gap that the threshold must absorb.

## Related
[[Behavioral C2 Detector]] · [[Behavioral Model Trainer]] · [[Severity & CVSS Scoring]] · [[Glossary]]

---
#concept #ml #threat-intel
