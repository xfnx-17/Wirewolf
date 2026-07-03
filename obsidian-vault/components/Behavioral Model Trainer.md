---
title: Behavioral Model Trainer
type: component
tags: [component, ml, test, tooling]
status: documented
created: 2026-06-27
module: "Detection Engine"
---
# Behavioral Model Trainer

Offline trainer (`tools/train_behavioral`) that builds the Markov models for the [[Behavioral C2 Detector]] from the public **CTU-13** dataset. Parses `.binetflow` NetFlow CSV (column-name mapped) → groups flows by 4-tuple → encodes each connection with the **same** `wirewolf_behavioral` encoder → trains per-class models with add-k smoothing → serializes to the `models/` format → runs a **holdout evaluation** (train vs different test scenarios) producing precision/recall/F1, a threshold-sweep CSV, and a JSON report.

## Results (real CTU-13 runs)
- **In-distribution** (held-out captures of trained families): **F1 0.906** @ threshold −0.25 (P 0.934 / R 0.879).
- **Cross-family** (train Neris+Rbot → unseen Virut): **F1 0.70** @ +0.25 — partial generalization to an unknown botnet; the optimal threshold shifts higher cross-family.

## Key Files
- `tools/train_behavioral/train.cpp`, `tools/train_behavioral/README.md`
- shares `include/behavioral_model.hpp` / `src/behavioral_model.cpp` (lib `wirewolf_behavioral`)

## Module
[[Detection Engine]]

## Dependencies
[[Benchmarking & Datasets]] · [[WirewolfConfig]]

## Used By
[[Behavioral C2 Detector]] (consumes the trained models)

## Related
[[Markov Behavioral Detection]] · [[Benchmarking & Datasets]] · [[Tools]]

---
#component #ml #test #tooling
