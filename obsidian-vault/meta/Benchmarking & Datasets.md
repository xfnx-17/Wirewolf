---
title: Benchmarking & Datasets
type: meta
tags: [meta, test]
status: documented
created: 2026-06-26
---
# Benchmarking & Datasets

`wirewolf_bench` scores detections against labeled captures (precision/recall); `wirewolf_probe` is a fast LLM-free harness. Captures + label CSVs live in `datasets/` and `bench/`. A PowerShell harness (`scripts/run_benchmark.ps1`, `scripts/make_benign_labels.ps1`, `wirewolf_ipscan --pairs`) automates accuracy + false-positive runs and writes a Markdown report.

The **CTU-13** corpus is used two ways: the labeled pcaps feed the pipeline benchmarks, and the **`.binetflow`** NetFlow files (`datasets/CTU13/`) train the [[Behavioral C2 Detector]] via the [[Behavioral Model Trainer]] (holdout eval: in-distribution F1 0.906, cross-family F1 0.70). Note: the shipped neris/friday excerpts are attack-only, so a real FP rate needs a benign-containing capture.

## Key Files
- `bench/benchmark.cpp`, `bench/probe.cpp`, `tool/ipscan.cpp`
- `bench/labels.neris.csv`, `bench/labels.cicids.csv`
- `scripts/run_benchmark.ps1`, `scripts/make_benign_labels.ps1`
- `datasets/`, `datasets/CTU13/*.binetflow`

## Exercises
[[Statistical Pre-Filter]] · [[TCP Reassembler]] · [[Connection Anomaly Detector]] · [[Behavioral Model Trainer]]

## Related
[[Testing Strategy]] · [[Tools]] · [[Behavioral C2 Detector]] · [[00 - Project Map (MOC)]]

---
#meta #test
