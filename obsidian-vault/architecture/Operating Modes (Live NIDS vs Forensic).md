---
title: Operating Modes (Live NIDS vs Forensic)
type: concept
tags: [architecture, concept, design, backend]
status: in-progress
created: 2026-06-27
---
# Operating Modes (Live NIDS vs Forensic)

> **Status: proposed design — not yet implemented.** This note captures the agreed architecture for running one engine in two modes. See [[Tasks]] for the build steps.

Wirewolf is **one engine with two operating modes**. The pipeline ([[Architecture]]) is identical in both — capture → reassembly → fast detectors → LLM. Only *how hard the LLM works* and *how the queue behaves* change between them. The mode is selected by an `AnalysisMode` field on [[WirewolfConfig]] (defaulting from `is_offline_capture()`, user-overridable).

- 🔴 **Live NIDS** — real-time monitoring of an interface → optimize for *keeping up*.
- 🟢 **Forensic** — deep analysis of a saved `.pcap` from an incident → optimize for *thoroughness* and a written report.

## Who decides a threat
The **fast, deterministic detectors decide**; the LLM judges only the leftover and explains everything:
1. [[Threat Feed & Rules]] — signature/indicator match → instant verdict.
2. [[Statistical Pre-Filter]] — clearly benign → dropped.
3. [[Connection Anomaly Detector]] — behavioral (scans, brute force, DDoS, beaconing) → instant verdict, no LLM.
4. **Leftover** ("suspicious but unmatched") → [[LLM Inference Engine]] (see queue strategy below).

Severity always comes from the catalog in [[SeverityInfo & Threat Catalog]], regardless of which stage decides.

## Queue strategy — buffer first, skip only as a last resort
This refines the naive "skip the LLM when busy" idea. The LLM is the slow stage, so suspicious flows wait in a queue ([[Thread-Safe Queue]]) in front of it. Strategy:

1. **Hold by default (buffering).** Queue suspicious flows and process them in order. Normal traffic never reaches the LLM (the fast detectors already dropped ~85%+), so the queue only holds the suspicious minority. During quiet periods the queue **drains and the system catches back up** to real-time.
2. **Priority queue.** Examine the **most-suspicious flows first**, so that if anything is ever dropped, it's the *least*-suspicious leftover — never a likely threat.
3. **Emergency-only skip.** Only skip/drop when a hard limit is hit (memory ceiling or "too far behind"), never during normal operation. Skipped flows are **still covered by the fast detectors** and surfaced as "Unclassified Anomaly".

**Why it rarely triggers:** the floods that could overwhelm the LLM (port scans, DDoS, worm bursts) are caught *instantly* by the [[Connection Anomaly Detector]] without the LLM — so the attack volume is absorbed by the fast detector and never piles onto the LLM queue. See [[Backpressure & Queue Drops]].

## Per-mode dials

| Dial (new [[WirewolfConfig]] field) | 🔴 Live | 🟢 Forensic |
|---|---|---|
| Queue on overflow | hold; emergency-skip least-suspicious | hold always, never skip |
| `llm_judge_unmatched` | yes (buffered) | yes, always |
| Priority queue | yes (scary first) | optional |
| `llm_explain_all` | no (template text for rule/anomaly hits) | **yes** — explain every alert |
| `generate_report` | no — stream alerts live | **yes** — incident report at the end |
| LLM token budget | smaller / faster | larger / detailed |

## Decision gate (pseudocode)
```
for each reassembled flow:
    if rules.match(flow):            -> ALERT (decided)            # fast, both modes
    else if statfilter.benign(flow): -> DROP                       # fast, both modes
    else:                                                          # suspicious, unmatched
        enqueue(flow, priority = suspicion_score)                  # HOLD — do not skip
# LLM worker drains the priority queue in order (most-suspicious first)
# Emergency only: if queue at hard memory/lag limit -> drop lowest-priority, tag "Unclassified Anomaly"
# Connection-level anomalies still alert directly (unchanged)
# Forensic mode: every alert also gets an LLM explanation pass
```

## What this would touch when built
- [[WirewolfConfig]] — `AnalysisMode` + dial fields
- [[Threat Feed & Rules]] — promote to a first-class decider
- [[Statistical Pre-Filter]] / [[TCP Reassembler]] — the ordering gate
- [[Thread-Safe Queue]] — priority ordering + hard-limit emergency drop
- [[LLM Inference Engine]] — explanation pass; honor priority/limits
- [[Pipeline Controller]] — read mode, set queue + dials
- Flutter config screen — Live ⇄ Forensic toggle; wire the incident report ([[Tasks]])

## Related
[[Architecture]] · [[Backpressure & Queue Drops]] · [[Flow - Live Monitoring (Flutter)]] · [[Flow - Offline PCAP Analysis (CLI)]] · [[Flow - LLM Threat Classification]] · [[Pipeline Controller]] · [[Tasks]] · [[00 - Project Map (MOC)]]

---
#architecture #concept #design #backend
