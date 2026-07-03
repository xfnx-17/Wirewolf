---
title: Tasks
type: meta
tags: [meta]
status: in-progress
created: 2026-06-26
---
# Tasks

Outstanding work and TODOs found in code or documentation gaps. The query below aggregates every unchecked task in the vault.

## Code TODOs
- [x] Wire **Export Incident Report** action — `buildIncidentReport()` → file save (see [[Command Palette]] / [[App Shell]])
- [x] Wire **Source mute** action — client-side: drops a source's alerts and suppresses future ones (`_muteSelectedSource` in [[App Shell]], shown via [[Alert Inspector]])

## Two-Mode Architecture (see [[Operating Modes (Live NIDS vs Forensic)]])
- [x] Add `AnalysisMode` (Auto/Live/Forensic) to [[WirewolfConfig]] + `is_forensic()` resolver, `--mode` CLI flag, and `wirewolf_set_config_mode()` FFI setter *(finer per-mode dials still TBD)*
- [x] Promote [[Threat Feed & Rules]] to a first-class **decider** — in Live mode a content-signature hit tags the flow and **skips the LLM**; Forensic keeps the LLM as arbiter
- [x] Decision gate ordering (rules → stat filter → leftover) via the signature tag → existing LLM short-circuit
- [x] Make [[Thread-Safe Queue]] a **priority queue** — leftover flows ordered by suspicion (named-threat > generic); FIFO within a band
- [x] Add **emergency-only skip**: at the hard capacity limit in live mode, evict the lowest-priority queued flow if the incoming outranks it; blocking (forensic) never drops
- [x] **Explanation for every alert** — deterministic, threat-type-aware explainer (`lib/util/incident_report.dart` `explainAlert()`), shown in the [[Alert Inspector]] and embedded in the report *(follow-up: upgrade to in-engine LLM narration in Forensic mode)*
- [x] [[Pipeline Controller]] / mode plumbing — `is_forensic()` resolves the mode; queue blocking follows offline/online; GUI selection flows via `wirewolf_set_config_mode`
- [x] Flutter config screen: **Operating Mode** dropdown (Auto/Live/Forensic) wired to `setMode` on Start
- [x] Forensic **incident report** — `buildIncidentReport()` wired to the Export Incident Report command (Markdown: summary, top hosts, chronological alerts + explanations)
- [ ] *Follow-up:* in-engine **LLM narration** pass for Forensic mode (replace the deterministic explainer with model-written narratives)

## Behavioral C2 Markov detector (clean-room, CTU-13)
- [x] Shared **encoder + MarkovModel** library (`wirewolf_behavioral`: `include/behavioral_model.hpp`, `src/behavioral_model.cpp`) — flow→letter+symbol state string, first-order Markov + add-k smoothing, models/ serialization with config fingerprint. Std-only so the engine can link the same code later (one encoder, no drift).
- [x] Offline **trainer + holdout eval** (`tools/train_behavioral/`) — `.binetflow` parse → 4-tuple connections → train per-class models → precision/recall/F1 + threshold-sweep CSV/JSON. Builds clean; verified end-to-end on synthetic data (P/R/F1 1.0 on separable smoke test).
- [x] README documenting binetflow→connections→state-strings→models data flow.
- [x] **Trained + evaluated on real CTU-13** (`datasets/CTU13/`, multi-family train Neris+Rbot+Virut → held-out test of different captures). 7.67M flows → 1.76M connections; 3,602 held-out test connections. **Best F1 0.906 @ threshold −0.25 (P 0.934 / R 0.879)**; precision-first +0.5 → P 0.989 / R 0.762. Sweep in `models/behavioral_eval.csv`, report in `models/behavioral_report.json`. Caveat: in-distribution-across-captures, not cross-family.
- [x] **Cross-family generalization** (train Neris+Rbot → unseen Virut): best **F1 0.70 @ threshold +0.25** (P 0.76/R 0.64); precision-first +0.5 → P 0.875. vs in-distribution F1 0.906 — shows behavioral detection generalizes partially to unseen families and that the optimal threshold shifts higher cross-family. Saved in `models/crossfamily/`. (Small Virut test set: 144 conns.)
- [x] Fixed trainer to auto-create `--out-dir` (`std::filesystem::create_directories`).
- [x] **Step B done:** `wirewolf_behavioral` linked into `wirewolf_core`; `TcpReassembler` loads the models (`--behavioral-models <dir>`, config fingerprint warning), records each completed connection per 4-tuple, scores with the shared encoder, and emits `Botnet Host` alerts on LLR > `--behavioral-threshold` — alongside the beaconing detector. Verified firing on the Neris pcap via `wirewolf_probe ... models 0.0` (`BEHAVIORAL C2 ALERT` logs; LLR 1.1–3.0 on botnet connections). FFI dll rebuilt. *Remaining (optional): FFI setter + Flutter config field to drive it from the GUI; pcap-vs-binetflow flow-granularity mismatch means runtime distribution differs from training — tune `behavioral_threshold` / consider deriving flow features to match.*

## Behavioral C2 — live deployment, findings & two-stage cascade
- [x] **GUI exposure**: `wirewolf_set_config_behavioral` FFI + Dart binding/service; models bundled as assets and auto-loaded at startup (`main._setupBehavioral`, threshold −0.25). No user config needed (encoder params are fixed to match training).
- [x] **Live FP finding (important):** on the user's own benign Wi-Fi the live detector FP-stormed (e.g. `192.168.0.107→AWS:443` flagged "Botnet Host"). Root cause: CTU-13's "Normal" is university traffic (model never saw home benign) + the model partly learned a length/size confound.
- [x] **Train-on-pcap pipeline** (the "translator", robust form): engine handles truncated pcaps (bytes from IP header); `export_states` tool dumps per-4-tuple state strings via the SAME engine encoder; trainer `--train-states/--test-states` joins them to binetflow labels. Built + verified.
- [x] **Train-on-pcap result = NEGATIVE finding:** with realistic benign (Background) the held-out P/R/F1 collapses (P 0.004) — no threshold separates botnet from diverse benign. Causes: (1) engine flows are *unidirectional & simpler* than binetflow's *bidirectional* Argus flows; (2) a simple char-Markov can't model diverse Background. So the binetflow F1 0.906 does **not** transfer to live pcap.
- [x] **Stage-2 contextual adjudicator (cascade):** app-side `_behavioralFalsePositive` in [[App Shell]] — a behavioral candidate is suppressed if it's a standard web/DNS port to a major cloud/CDN ASN with no threat-intel tag; threat-tagged endpoints always confirm. Deterministic (ASN-rep + threat-intel + port), reuses [[Geo Enrichment]]. Kills the AWS:443-type FPs; the [[LLM Inference Engine]] stays the explainer.
- [x] **LAN-outbound scoping fix (big FP cut):** live behavioral scoring now only fires on connections where an internal/private host is the SOURCE and the dest is external (the real C2 "beacon out" model) — return-direction traffic (external→internal ephemeral) is no longer scored. Export/training is left unscoped so CTU-13's public-IP scenarios still work. **Verified live on the user's Wi-Fi: 10 alerts/187 flows → 2 alerts/92 flows, and both survivors are internal→external (the return-traffic FP storm is gone).**
- [x] **Web-port adjudicator broadened (final FP fix):** the stage-2 rule now suppresses ALL outbound 443/80/53 with no threat-intel tag (not just a cloud-keyword list — which missed providers like Anthropic). Behavioral now only surfaces odd-port outbound; HTTPS-C2 is left to threat-intel + beaconing. **Verified live: the `160.79.104.10:443` Anthropic candidate (TLS SNI `api.anthropic.com` — the Claude session) is now logged "Suppressed benign behavioral candidate" and 0 false-positive alerts reach the analyst (65 flows, 0 shown).** Net: original 10 → scoping 2 → this 0.
- [x] **P2P/BitTorrent suppressor:** the engine detects the BitTorrent handshake ("BitTorrent protocol"), tracker (`info_hash=`) and DHT (`d1:ad2:id20:`) signatures in connection payloads, remembers those peers (`p2p_peers_`), and excludes them from behavioral scoring — torrent fan-out mimics botnet C2 and was the residual FP source (TLS SNI `tracker.pmman.tech` on the user's traffic). Built + dll deployed. *Caveat: unencrypted BT only; encrypted (MSE) BT has no plaintext marker and still slips through. Live GUI re-verification pending (computer-use display glitch).*
- [x] **Pcap-based FP test (headless, repeatable):** captured 4 min of the user's real Wi-Fi (`dumpcap -P`, 1.5 GB) and ran `wirewolf_probe ... models 0.0`. Engine-side web-port + threat-intel adjudication was added so the probe reflects the full cascade (not just the app layer). **Found one residual FP — the timing-based [[Connection Anomaly Detector]] beaconing path flagged the user's own Claude Code session (12 regular ~20s polls to Anthropic 160.79.104.10:443, CV=0.00) as "C2 Beaconing".** Classic beaconing FP: a polling app is indistinguishable from C2 by timing.
- [x] **Fixed:** extended the same contextual adjudication (port 80/443 + no threat-intel tag ⇒ benign) to the beaconing detector's emit path. **Re-test on the same capture: 0 alerts of any type** (Markov + beaconing both clean). Note: torrent traffic is mostly UDP so it isn't TCP-reassembled; behavioral Markov barely engages on this user's traffic regardless.
## Forensic deployability (F-track)
- [x] **F1 ingestion:** pcapng reading confirmed WORKING in the engine (earlier "0 flows" was a fluke — file still flushing). Not a blocker. Gotcha for docs: `dumpcap` writes pcapng; engine reads it, but use `-P`/`editcap -F pcap` if ever needed.
- [x] **F2 bounded-LLM cascade (the key forensic fix):** added `--max-llm-flows N` ([[WirewolfConfig]] `max_llm_flows`, [[LLM Inference Engine]] `llm_runs_`). Fast detectors decide/emit on every flow; the LLM budget caps expensive inference and the [[Thread-Safe Queue]] priority order means the capped N are the *most-suspicious* flows. **Verified: Friday-WorkingHours (8.8 GB, 100,177 flows passed the filter) went from ~15 hours → 3.3 minutes with `--max-llm-flows 50`.** Tradeoff: raise the cap to trade time for LLM coverage.
- [ ] *F3:* accuracy benchmark across CICIDS/CTU-13/malware pcaps → precision/recall/FP per class (extend `run_benchmark.ps1`).
- [ ] *F4:* rich incident report (timeline, IOCs, MITRE mapping, export) — headless CLI path.
- [ ] *F5:* packaging/installer; fix stale-DLL + manual-model papercuts.
- [ ] *Future (research-grade):* per-deployment baseline learning (calibrate "normal" on local traffic) and/or bidirectional Argus-style flow features + a stronger model (Random Forest) to make behavioral detection generalize across home/enterprise/university.

## Documentation TODOs
- [x] Flesh out [[CI-CD]] (current state + recommended GH Actions pipeline)
- [x] Expand [[Deployment]] with a packaging checklist
- [x] Document [[OpenVINO Accelerator]] enable path
- [x] Detail [[TLS JA3 Inspector]] fingerprint matching

## Validation & deployability (bigger picture)
- [x] Expand `rules/signatures.txt` with high-precision IOCs (Live mode decides on these) — [[Threat Feed & Rules]]
- [x] Real accuracy run — `wirewolf_probe` on Neris after the engine changes: **Precision 1.000 · Recall 0.989 · F1 0.994** (TP 4192 / FP 0 / FN 48), 0.32s, LLM-free. Confirms no regression. *(Single-bot dataset — not a diverse-benign FP test.)*
- [x] **Benchmark harness set up** — `scripts/run_benchmark.ps1` (recall on neris/cicids; FP run via `-FpPcap`), `scripts/make_benign_labels.ps1`, and `wirewolf_ipscan --pairs`. Runner validated; needs `-Model <gguf>` to execute.
- [ ] *Needs your model/GPU:* run `scripts/run_benchmark.ps1 -Model <gguf>` for real recall numbers + a live `DECIDE` alert + exported report
- [ ] *Needs a benign-containing capture:* the repo datasets are attack-only (no benign traffic), so FP can't be measured from them. Run `-FpPcap <full Friday-WorkingHours.pcap>` to get a real FP rate (the harness auto-builds benign labels for it)
- [ ] *Needs live interface:* throughput proof under load (priority queue + emergency-skip)
- [ ] Import a full Suricata/Emerging-Threats ruleset (needs a Suricata-rule parser; current feed is simplified substring format)
- [ ] In-engine **LLM narration** pass for Forensic mode (replace the deterministic explainer) + finer per-mode dials (`llm_explain_all`, token budgets)

## All open tasks (live)
```dataview
TASK WHERE !completed
```

## Related
[[Documentation Status]] · [[00 - Project Map (MOC)]]

---
#meta
