---
title: CI-CD
type: meta
tags: [meta, build]
status: documented
created: 2026-06-26
---
# CI-CD

No automated CI/CD pipeline exists in the repo today (no `.github/workflows`, no Azure/GitLab config). Builds and tests run locally via `build.ps1`. This note documents the current state and the recommended pipeline.

## Current state
- Local-only: `build.ps1` (build), `build.ps1 -Test` (build + run `wirewolf_tests`).
- Heavy native deps (CUDA, llama.cpp, Npcap) are fetched/built by the script.

## Recommended pipeline (GitHub Actions, Windows runner)
1. **Trigger:** push / PR to `main`.
2. **Cache:** `vcpkg/` and the llama.cpp build to avoid recompiling CUDA each run.
3. **Build:** `cmake -B build` + `cmake --build build --config Release` (a CPU-only/`-DWIREWOLF_USE_OPENVINO=OFF` job keeps CI fast; full CUDA build can be a nightly job since GH hosted runners lack NVIDIA GPUs).
4. **Test:** run `wirewolf_tests.exe` and fail on non-zero exit.
5. **Accuracy gate (optional, nightly):** run `wirewolf_probe` against a small labeled capture and assert recall/precision thresholds (see [[Benchmarking & Datasets]]).
6. **Artifacts:** publish `wirewolf.exe`, `wirewolf.dll`, and the Flutter `wirewolf_dashboard` bundle.

## Honest note
A full GPU LLM build won't run on standard hosted runners — split into a fast CPU build/test job (every push) and a self-hosted-GPU job for the LLM path.

## Related
[[Build System]] · [[Deployment]] · [[Testing Strategy]] · [[00 - Project Map (MOC)]]

---
#meta #build
