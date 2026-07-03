---
title: Detection Engine
type: module
tags: [module, backend]
status: documented
created: 2026-06-26
---
# Detection Engine

The C++ core (`wirewolf_core`): the staged producer/consumer pipeline that turns raw flows into classified threats.

## Components
[[TCP Reassembler]] · [[Connection Anomaly Detector]] · [[Statistical Pre-Filter]] · [[Payload Normalizer]] · [[OpenVINO Accelerator]] · [[LLM Inference Engine]] · [[Behavioral C2 Detector]] · [[Behavioral Model Trainer]] · [[Pipeline Controller]] · [[Thread-Safe Queue]] · [[Logger]] · [[WirewolfConfig]]

## Child components (live index)
```dataview
LIST WHERE type = "component" AND module = "Detection Engine"
```

## Related
[[Capture Layer]] · [[Threat Intelligence]] · [[Interfaces & FFI]] · [[00 - Project Map (MOC)]] · [[Architecture]]

---
#module #backend
