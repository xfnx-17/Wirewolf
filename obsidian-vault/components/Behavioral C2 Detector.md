---
title: Behavioral C2 Detector
type: component
tags: [component, backend, ml, threat-intel]
status: documented
created: 2026-06-27
module: "Detection Engine"
---
# Behavioral C2 Detector

Clean-room behavioral botnet/C2 detection using first-order **Markov models** over per-connection **state strings**. Each completed TCP connection is encoded (bytes×duration → letter, inter-arrival gap → symbol) and grouped by 4-tuple; the connection's state string is scored against a trained **Botnet** vs **Normal** model, and a positive log-likelihood-ratio (above the threshold) raises a `Botnet Host` alert. Runs **alongside** the timing-based beaconing detector — purely additive.

This is the single shared encoder/model implementation (`wirewolf_behavioral`) used by both the live engine and the offline [[Behavioral Model Trainer]], so training and runtime encode identically (model files carry a config fingerprint; a mismatch is logged).

## Key Files
- `include/behavioral_model.hpp`, `src/behavioral_model.cpp` (lib `wirewolf_behavioral`)
- `src/tcp_reassembly.cpp` (`record_and_score_behavioral`), `include/config.hpp` (`behavioral_models_dir`, `behavioral_threshold`)

## Module
[[Detection Engine]]

## Dependencies
[[TCP Reassembler]] · [[WirewolfConfig]] · [[SeverityInfo & Threat Catalog]]

## Used By
[[Pipeline Controller]] · [[C FFI Library]] (auto-loaded by the GUI at startup)

## Data Touched
[[ThreatAlert]] · [[ConnectionInfo]]

## Two-stage cascade (precision)
Markov is **stage 1** (high-recall, noisy). A **stage-2 contextual adjudicator** (app-side `_behavioralFalsePositive` in [[App Shell]]) then suppresses obvious false positives — a standard web/DNS port to a major cloud/CDN ASN with no threat-intel tag — using [[Geo Enrichment]]. Threat-intel-tagged endpoints always confirm. Deterministic (ASN-reputation + threat-intel + port), so it generalizes across networks without a per-site baseline; the LLM is kept only as the explainer.

**Live-deployment honesty:** trained on CTU-13 the offline F1 is strong (0.906), but on real/diverse benign traffic the raw Markov stage over-flags (e.g. benign HTTPS to AWS). The stage-2 adjudicator exists precisely to absorb that. Making the Markov stage itself generalize would need per-site baseline learning or bidirectional flow features (see [[Tasks]]).

## Related
[[Markov Behavioral Detection]] · [[Behavioral Model Trainer]] · [[Connection Anomaly Detector]] · [[Threat Tagging & False-Positive Tuning]] · [[App Shell]]

---
#component #backend #ml #threat-intel
