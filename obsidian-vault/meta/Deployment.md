---
title: Deployment
type: meta
tags: [meta, build]
status: documented
created: 2026-06-26
---
# Deployment

Windows desktop deployment. The Flutter app (`wirewolf_dashboard.exe`) loads `wirewolf.dll` (the FFI build of the engine) via dart:ffi, embeds a WebView2 threat map, and reads bundled IP2Location assets. Model weights are downloaded separately (they're too large to bundle).

## Artifacts to ship
- `wirewolf_dashboard.exe` (Flutter runner) + its `data/` and plugin DLLs
- `wirewolf.dll` (engine FFI) — placed next to the exe (loader search path in `main.dart`)
- `assets/geo/` (IP2Location city/ASN/proxy `.bin`+`.str`) and `assets/globe/` (map)
- `rules/` (signatures + bad IP/domain/JA3 lists)
- GGUF model (fetched at setup, not bundled)

## Runtime prerequisites
- **WebView2 runtime** (for the threat map) — ships with Win11; on older Win10 install the Evergreen runtime.
- **NVIDIA CUDA + driver** for GPU LLM inference (the `ggml-cuda.dll`/`llama.dll` set must be beside the exe). Without a GPU, the LLM path is unavailable; behavioral/rule detection still runs.
- Npcap installed (for live capture; not needed for pcap-file forensic analysis).

## Packaging checklist
1. `cmake --build build --config Release` (engine + `wirewolf.dll`).
2. `flutter build windows --release`.
3. Copy `wirewolf.dll` + the `ggml*/llama` DLLs next to `wirewolf_dashboard.exe`.
4. Copy `assets/geo`, `assets/globe`, `rules/` into the bundle.
5. Run `scripts/download_models.ps1` (or ship a download step) for the GGUF.
6. Smoke test: launch → load a sample `.pcap` in Forensic mode → confirm alerts + Export Incident Report.

## Engine DLL deployment (important)
The Flutter app loads `wirewolf.dll` from **next to the exe first**. The build does **not** auto-copy the freshly-built engine dll, so after any `wirewolf_ffi` rebuild you must redeploy it — otherwise the app loads a **stale dll** missing new FFI symbols, the binding lookup throws, and the app silently falls back to **DEMO mode**. Fix/avoid with:
```
cmake --build build --config Release --target wirewolf_ffi
.\scripts\deploy_engine_dll.ps1   # copies wirewolf.dll (+ llama/ggml/cuda deps) into the runner
```
The behavioral models are bundled as assets and auto-extracted at startup (`main._setupBehavioral`) — no manual model deployment needed.

## Honest note
This is desktop/forensic deployment. A true sensor deployment (Linux tap, headless, line-rate) is out of scope today — see [[Operating Modes (Live NIDS vs Forensic)]] for where live mode stands.

## Related
[[Build System]] · [[Environment & Models]] · [[External Dependencies]] · [[00 - Project Map (MOC)]]

---
#meta #build
