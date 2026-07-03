---
title: OpenVINO Accelerator
type: component
tags: [component, backend, ml]
status: documented
created: 2026-06-26
module: "Detection Engine"
---
# OpenVINO Accelerator

Optional OpenVINO-backed CNN path for the pre-filter ([[Statistical Pre-Filter]]). When unavailable or disabled, the filter falls back to the statistical heuristics, so the engine runs fine without it.

## How to enable
1. **Compile in support:** build with `-DWIREWOLF_USE_OPENVINO=ON` (or `build.ps1 -OpenVINO`). This defines `WIREWOLF_USE_OPENVINO`, which gates all the `ov::` code in `npu_filter.cpp` (the prepare-byte-tensor + inference path) and links the OpenVINO runtime.
2. **Provide a model:** pass the IR `model.xml` as the OpenVINO model path (CLI arg 2, or `setOpenvinoModel` over FFI).
3. **Turn it on at runtime:** `--openvino` (CLI) or `setOpenvinoEnabled(true)` / the "Use OpenVINO" toggle in the config screen.
4. The CNN uses a fixed input (`CNN_INPUT_SEQ_LEN=512`, pad token 256) and the device reported by `get_device()` ("NPU"/"CPU").

## Behavior
- Disabled or not compiled → `get_device()` returns `"Statistical"` and the entropy/variance/IAT heuristics decide.
- The `npu_threshold` config controls how aggressively the model forwards flows to the LLM.

## Key Files
- `openvino/` (vendored runtime), `src/npu_filter.cpp` (the `#ifdef WIREWOLF_USE_OPENVINO` paths), `include/config.hpp` (`openvino_enabled`, `openvino_model_path`, `npu_threshold`)

## Module
[[Detection Engine]]

## Dependencies
[[WirewolfConfig]]

## Used By
[[Statistical Pre-Filter]]

## Related
[[Tech Stack]] · [[External Dependencies]]

---
#component #backend #ml
