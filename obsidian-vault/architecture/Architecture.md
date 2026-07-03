---
title: Architecture
type: concept
tags: [architecture, concept]
status: documented
created: 2026-06-26
---
# Architecture

End-to-end control and data flow. Control flows top-down through the backend; alerts flow back out to the GUIs through a flat C ABI.

## Pipeline (in order)
1. [[Packet Capture]] — Npcap live iface or offline `.pcap`
2. [[TCP Reassembler]] — reorder segments → app-layer payloads (+ [[Connection Anomaly Detector]])
3. [[Statistical Pre-Filter]] — entropy/variance/IAT gate (~85% benign dropped)
4. [[LLM Inference Engine]] — Llama 3.1 8B → strict JSON [[ThreatAlert]]
5. [[Pipeline Controller]] — owns threads + queues + callbacks
6. [[C FFI Library]] → [[CLI Entry Point]] · [[Native GUI]] · [[Flutter Frontend]]

Stages are decoupled by [[Thread-Safe Queue]] and configured from one [[WirewolfConfig]]. Connection-level anomalies alert directly, bypassing the LLM ([[Flow - Connection Anomaly Detection]]).

The same pipeline runs in two modes — see [[Operating Modes (Live NIDS vs Forensic)]].

## Key Files
- `README.md`
- `include/pipeline_controller.hpp`
- `docs/plan.md`

## Related
[[Tech Stack]] · [[Detection Engine]] · [[Backpressure & Queue Drops]] · [[00 - Project Map (MOC)]]

---
#architecture #concept
