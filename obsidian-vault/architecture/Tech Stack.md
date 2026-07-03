---
title: Tech Stack
type: concept
tags: [architecture, concept]
status: documented
created: 2026-06-26
---
# Tech Stack

Every language, framework and library and the role it plays.

## Backend (C++20)
- **llama.cpp + CUDA** — local LLM inference → [[LLM Inference Engine]]
- **Npcap / libpcap** — packet capture → [[Packet Capture]]
- **WinDivert** — inline packet blocking (IPS) → [[WinDivert Inline Blocker]]
- **OpenVINO** (optional) — pre-filter acceleration → [[OpenVINO Accelerator]]
- **CMake + vcpkg** — build/deps → [[Build System]]

## Frontend
- **Flutter / Dart + dart:ffi** → [[Flutter Frontend]] / [[Wirewolf Bindings]]
- **WebView2** — embedded threat map → [[Threat Map Screen]]
- **Dear ImGui** — native GUI → [[Native GUI]]

## Data / intel
- **IP2Location LITE** (city/ASN/proxy) → [[Geo Enrichment]]
- **JA3** TLS fingerprinting → [[TLS JA3 Inspector]]

## Related
[[Architecture]] · [[External Dependencies]] · [[00 - Project Map (MOC)]]

---
#architecture #concept
