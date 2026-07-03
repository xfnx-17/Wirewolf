# train_behavioral — behavioral C2 Markov model trainer

Builds the malicious/benign **behavioral Markov models** for Wirewolf's
behavioral C2 detection by running **our own encoder** over the labeled flows of
the public **CTU-13** dataset.

## Data flow

```
.binetflow (CTU-13)            connections                state strings              Markov models            models/
─────────────────────  ─────────────────────────  ───────────────────────  ─────────────────────  ─────────────────────────
StartTime,Dur,Proto,    group flows by 4-tuple      behavioral::             first-order Markov      behavioral.botnet.model
SrcAddr,DstAddr,Dport,  (SrcAddr,DstAddr,Dport,  →  encode_connection()   →  per class, add-k     →  behavioral.normal.model
TotBytes,Label          Proto), ordered by time     letter+symbol per flow     (Laplace) smoothing     behavioral_eval.csv
                                                                                                       behavioral_report.json
```

1. **Parse** `.binetflow` CSV. The header row defines columns; we map by
   **name** (not position) and skip malformed rows.
2. **Group** flows into connections by the 4-tuple `(SrcAddr, DstAddr, Dport,
   Proto)`, preserving `StartTime` order.
3. **Encode** each connection with `behavioral::encode_connection()` — the
   *single* shared encoder in `include/behavioral_model.hpp` /
   `src/behavioral_model.cpp` that the live engine will also link. Each flow
   becomes two characters: a **letter** (total-bytes bucket × duration bucket)
   and a **symbol** (inter-arrival gap → periodicity).
4. **Label** each connection from its flows — `--label-rule any` (default: any
   Botnet flow ⇒ Botnet) or `majority`. Connections with fewer than
   `--min-flows` (default 4) flows are dropped (state strings too short).
5. **Train** a first-order Markov model per class with add-k smoothing
   (`--k`, default 0.5) — identical math to the detector's scoring.
6. **Serialize** to `models/behavioral.botnet.model` and
   `models/behavioral.normal.model` (text format, version 1, includes a config
   fingerprint so runtime can detect an encoding mismatch).

## Evaluation (holdout)

Train and test on **different CTU-13 scenarios** — never the same capture.
For each held-out connection we compute the log-likelihood ratio
`score_botnet − score_normal` and predict Botnet if it exceeds `--threshold`.
Outputs:
- `behavioral_eval.csv` — a threshold sweep (precision/recall/F1 per threshold)
  so you can pick an operating point.
- `behavioral_report.json` — the confusion matrix + P/R/F1 at the chosen
  threshold (drop these numbers straight into your report).

## Usage

```powershell
# from the repo root, after building:
cmake --build build --config Release --target train_behavioral

.\build\Release\train_behavioral.exe `
   --train datasets\ctu13\scenario3.binetflow,datasets\ctu13\scenario4.binetflow `
   --test  datasets\ctu13\scenario10.binetflow `
   --out-dir models --label-rule any --min-flows 4 --k 0.5 --threshold 0.0
```

Options: `--train`/`--test` (comma-separated `.binetflow` paths),
`--out-dir`, `--label-rule any|majority`, `--min-flows N`, `--k K`,
`--threshold T`, `--include-background` (treat Background flows as benign too).

## Getting the data

CTU-13 `.binetflow` files are **not** bundled (licensing + size). Download from
the Stratosphere Lab: <https://www.stratosphereips.org/datasets-ctu13> and place
the `.binetflow` files somewhere (e.g. `datasets/ctu13/`). Use different
scenarios for `--train` vs `--test`.

## Clean-room / licensing note

These models are built **from scratch** by our encoder over the public dataset's
labeled flows. No Stratosphere/Slips trained models or source code (GPL-2.0) are
copied or linked — only the raw labeled `.binetflow` data is consumed.

## One encoder, no drift

`behavioral::encode_connection` and `behavioral::MarkovModel` live in the
`wirewolf_behavioral` library. The trainer links it today; when the live engine
adopts behavioral detection (Step B) it links the **same** library, so training
and runtime encode identically. The serialized model carries the encoder's
config fingerprint; a runtime with a different `BehavioralConfig` can detect the
mismatch and warn rather than score against incompatible models.
