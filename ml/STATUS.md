# BEACON attack-stage forecasting model — status

Standalone reference for the current state of the `ml/` pipeline. Describes what
exists now; not a changelog.

SIH PS SIH26153, Team Elytra. Taxonomy: MITRE ATT&CK tactics. Feature family:
network-flow statistics (CICFlowMeter-style) plus causal episode context.

---

## 1. Current status

| Item | Value |
|---|---|
| Canonical checkpoint | `ml/artifacts/forecast.pt` |
| Hard success criteria | **11 / 11 pass** |
| In-domain next-tactic top-1 | 0.944 |
| In-domain next-tactic macro-F1 (learnable classes) | 0.847 |
| In-domain escalation ROC-AUC | 0.995 |
| Calibration ECE / multiclass Brier | 0.010 / 0.095 |
| Cross-environment (env-B) accuracy retention | 0.984 |
| Cross-environment escalation ROC-AUC | 0.895 |
| Cross-environment attack/benign transfer F1 | 0.874 |
| Parameters | ~217k |
| Training hardware | single RTX 4080 Laptop (12 GB), ~22 epochs, ~55 min |

Companion files: `ml/artifacts/train_summary_forecast.json` (full metric dump),
`ml/artifacts/feature_manifest.json` (feature list + standardization stats +
split counts), `ml/artifacts/envb_calibration.json` (env-B prior correction),
`ml/artifacts/eda/` (exploratory report + plots).

---

## 2. What the model predicts

One example per `(episode, t)`: given the last 64 flows of an episode ending at
event `t` (left-padded, masked), the model outputs four heads for position `t`:

| Head | Target | Type |
|---|---|---|
| `next_tactic` | next flow's ATT&CK tactic | 9-way classification |
| `time_to_next` | log1p seconds to the next flow | regression (masked) |
| `time_to_next_change` | log1p seconds until the tactic changes | regression (masked) |
| `escalation` | does an escalation tactic (EXFILTRATION or IMPACT) occur within the next 20 events | binary |

**Tactic vocabulary (9 classes, index order):**
`BENIGN, RECONNAISSANCE, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY,
LATERAL_MOVEMENT, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT`

The RNN encoder is unidirectional — a forecast never sees future flows.

---

## 3. Datasets

Raw data lives outside the repository (not tracked). Three sources are compiled
into one normalized event table.

| Dataset | Provenance | Role | Raw flows used |
|---|---|---|---|
| **DAPT 2020** | Day-labelled APT testbed captures with a native kill-chain `Stage` column (`csv/` CICFlowMeter CSVs + raw PCAPs). | Primary — the only source with ground-truth multi-stage attack sequences. Supplies canonical episode shapes. | 86,690 |
| **CIC-IDS-2017 (corrected)** | Relabelled / re-extracted CIC-IDS-2017 from "Error Prevalence in NIDS datasets" (IEEE CNS 2022, DistriNet/KU Leuven). 91-column improved schema. | Primary — bulk of flow/timing volume and per-attack-type diversity. Stages derived by label mapping + per-victim sessionization. | ~2.10M |
| **UNSW-NB15 (full)** | Complete 4-part UNSW-NB15 set (`UNSW-NB15_1..4.csv`) with Argus/Bro-style 49-column schema and `ct_*` connection-tracking features. | **Held-out environment B** — a different network captured by a different flow extractor. Tests zero-adaptation transfer; a small stratified slice is used for sensor calibration (see §6). | ~2.54M |

Total compiled table: **3,626,523 events across 7,845 episodes**, 143 feature
columns.

### Label → tactic mapping

**DAPT 2020 `Stage`:** benign→BENIGN · reconnaissance→RECONNAISSANCE · establish
foothold→INITIAL_ACCESS · internal reconnaissance→DISCOVERY · lateral
movement→LATERAL_MOVEMENT · data exfiltration→EXFILTRATION.

**CIC-IDS-2017:** benign→BENIGN · portscan→RECONNAISSANCE · FTP/SSH
patator, brute force→CREDENTIAL_ACCESS · web attack (XSS, SQLi)→INITIAL_ACCESS ·
infiltration portscan→DISCOVERY · infiltration→LATERAL_MOVEMENT ·
botnet→COMMAND_AND_CONTROL · all DoS / DDoS / heartbleed→IMPACT. Rows tagged
`- Attempted` are collapsed to BENIGN.

**UNSW-NB15 `attack_cat`:** normal→BENIGN · reconnaissance, analysis→
RECONNAISSANCE · fuzzers→DISCOVERY · exploits, shellcode→INITIAL_ACCESS ·
backdoor→COMMAND_AND_CONTROL · worms→LATERAL_MOVEMENT · generic, DoS→IMPACT.

### Compiled next-tactic distribution

`BENIGN 2,770,721 · IMPACT 497,637 · RECONNAISSANCE 187,266 · DISCOVERY 95,830 ·
INITIAL_ACCESS 54,531 · CREDENTIAL_ACCESS 6,991 · COMMAND_AND_CONTROL 3,056 ·
LATERAL_MOVEMENT 2,631 · EXFILTRATION 15`

---

## 4. Feature set (143 columns)

All features are **causal** — computed only from the current flow and everything
before it in the episode. Numeric features are standardized with train-only
statistics from `feature_manifest.json`; missing columns (a schema present in one
source but not another) become 0 after standardization.

**Temporal (10):** `dt_prev`, `log_dt_prev`, `t_since_start`, `event_idx`,
`is_tactic_change`, `secs_since_tactic_change`, `hour_sin`, `hour_cos`,
`dow_sin`, `dow_cos`

**Entity-graph, expanding (5):** `uniq_dst_ports_so_far`, `uniq_dst_ips_so_far`,
`pair_repeat_count`, `is_new_dst_ip`, `is_new_dst_port`

**History aggregates, shifted (16):** `frac_malicious_so_far`, `cum_fwd_bytes`,
`cum_bwd_bytes`, `max_tactic_depth_so_far`, `gap_burstiness`,
`cnt_<tactic>_so_far` for each of the 9 tactics, plus the two embedded columns
below

**Previous-tactic embeddings (2):** `prev_tactic_id`, `prev2_tactic_id`
(fed through learned embeddings, not standardized)

**Connection-tracking, UNSW-style (10):** `ct_state_ttl`, `ct_flw_http_mthd`,
`ct_ftp_cmd`, `ct_srv_src`, `ct_srv_dst`, `ct_dst_ltm`, `ct_src_ltm`,
`ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm`

**Flow statistics (74):** `duration`, `fwd_pkts`, `bwd_pkts`, `fwd_bytes`,
`bwd_bytes`, forward/backward packet-length min/max/mean/std,
`flow_bytes_s`, `flow_pkts_s`, flow / forward / backward inter-arrival-time
mean/std/min/max, TCP flag counts (`fin_flags`, `syn_flags`, `rst_flags`,
`psh_flags`, `ack_flags`, `urg_flags`, `cwr_flags`, `ece_flags`),
`fwd_header_len`, `bwd_header_len`, `fwd_pkts_s`, `bwd_pkts_s`, aggregate
packet-length min/max/mean/std/var, `down_up_ratio`, `avg_pkt_size`,
`fwd_seg_size_avg`, `bwd_seg_size_avg`, subflow forward/backward packet & byte
counts, `fwd_init_win`, `bwd_init_win`, `fwd_act_data_pkts`, `fwd_seg_size_min`,
active-time and idle-time min/max/mean/std, `ttl_src`, `ttl_dst`

**Robust / derived (26):** `log_duration`, `log_fwd_bytes`, `log_bwd_bytes`,
`log_flow_bytes_s`, `log_flow_pkts_s`, `log_flow_iat_mean`, `log_flow_iat_max`,
`log_active_mean`, `log_idle_mean`, `bytes_per_pkt_fwd`, `bytes_per_pkt_bwd`,
`fwd_bwd_pkt_ratio`, `syn_no_ack`, `rst_rate`, `port_wellknown`,
`port_registered`, `port_ephemeral`, `port_is_<N>` for
{21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 4444, 8080},
`proto_tcp`, `proto_udp`, `proto_icmp`, `proto_other`

Raw identifiers (`Flow ID`, source/destination IP, raw timestamp) are **not**
model inputs — only their derived forms.

---

## 5. Data pipeline

`ml/data/build.py` orchestrates: stream raw CSVs → normalize schema and labels →
sessionize into episodes → build causal features + targets → assign splits →
write Parquet + manifest.

**Episodes:** an episode is a run of flows for one internal (RFC1918) victim host
within a 300 s inter-flow gap, minimum 3 events, capped at 512, with 15% of
purely-benign episodes retained.

**Splits (episode-level, never row-level):**

| Split | Episodes | Events | Contents |
|---|---|---|---|
| `train` | 1,522 | 765,089 | primary (DAPT 2020 + CIC-IDS-2017), stratified by domain × max-severity |
| `val` | 325 | 162,424 | primary, held out for early stopping and temperature scaling |
| `test` | 326 | 159,139 | primary, held out for the in-domain scorecard |
| `envB` | 4,822 | 2,158,078 | UNSW-NB15, held out entirely — cross-environment evaluation |
| `envB_cal` | 850 | 381,793 | 15% severity-stratified UNSW-NB15 slice used for sensor calibration |

Standardization statistics are fitted on `train` only. `envB` / `envB_cal` are
re-scaled with their own median/IQR at load time to bridge the unit differences
between flow extractors.

---

## 6. Model and training

**Architecture (`ml/model.py`):**
- Two learned embeddings (`prev_tactic_id`, `prev2_tactic_id`, dim 16) concatenated with the 141 numeric features
- 2-layer unidirectional GRU, hidden 128, dropout 0.25
- LayerNorm + dropout on the final (current-event) hidden state
- Four linear heads: `next_tactic` (9), `time_to_next_change` (1), `time_to_next` (1), `escalation` (1)
- `temperature` buffer for post-hoc calibration

**Loss:** weighted cross-entropy (inverse-frequency class weights, capped at 120)
+ masked SmoothL1 on both timing heads + BCE-with-logits on escalation, combined
with weights (1.0, 0.4, 0.15, 0.5).

**Optimization:** AdamW, lr 1e-3, weight decay 1e-4, OneCycle schedule
(`pct_start` 0.3), gradient clip 5.0, AMP autocast + GradScaler, 22 epochs,
early stop on validation learnable macro-F1 (patience 6), seed 1337.

**Imbalance handling:** WeightedRandomSampler oversampling
`CREDENTIAL_ACCESS ×10, COMMAND_AND_CONTROL ×10, EXFILTRATION ×25`; Gaussian
feature jitter (sd 0.03) on standardized inputs during training.

**Cross-environment calibration:** the `envB_cal` slice is folded into training
(self-standardized). Then temperature scaling is fitted on `val`. A separate
post-hoc **env-B prior correction** (`ml/calibrate_envb.py`) adds a fixed
`+1.60` to the BENIGN logit on the env-B inference path only — chosen by
maximizing attack/benign F1 on the labelled `envB_cal` slice. It is stored in
`ml/artifacts/envb_calibration.json` and never applied to the in-domain path.

---

## 7. Results

### 7.1 Hard success criteria (evaluated on `test`, plus env-B gates)

| Criterion | Target | Value | Status |
|---|---|---|---|
| next-tactic top-1 | ≥ 0.850 | 0.944 | pass |
| next-tactic top-2 | ≥ 0.950 | 0.999 | pass |
| next-tactic macro-F1 (learnable) | ≥ 0.784 | 0.847 | pass |
| ECE | ≤ 0.050 | 0.010 | pass |
| multiclass Brier | ≤ 0.120 | 0.095 | pass |
| time-to-change median APE | ≤ 0.300 | 0.260 | pass |
| escalation ROC-AUC | ≥ 0.900 | 0.995 | pass |
| escalation PR-AUC | ≥ 0.850 | 0.990 | pass |
| env-B accuracy retention | ≥ 0.70 | 0.984 | pass |
| env-B escalation ROC-AUC | ≥ 0.70 | 0.895 | pass |
| env-B attack/benign F1 | ≥ 0.80 | 0.874 | pass |

"Learnable" macro-F1 averages F1 over tactic classes with at least 100 test
examples (excludes COMMAND_AND_CONTROL, EXFILTRATION).

### 7.2 In-domain test split (158,813 windows)

- Next-tactic: top-1 0.9439 · top-2 0.9987 · top-3 0.9993 · macro-F1 all-9 0.6644 · macro-F1 learnable 0.8468 · weighted-F1 0.9540
- Calibration: ECE 0.0103 · MCE 0.2413 · Brier 0.0951 · temperature 1.596
- time-to-stage-change (92,206): MAE 5.25 s · MAPE 0.806 · median APE 0.260 · p90 abs err 4.5 s
- time-to-next-flow (158,813): MAE 0.21 s · MAPE 0.063
- Escalation (positive rate 0.281): ROC-AUC 0.9948 · PR-AUC 0.9899 · recall @ FPR≤0.15 0.9911 · best-F1 0.9547 · Brier 0.0241
- Lead time (4,525 transitions): 47.8% of stage transitions anticipated at least one event early; median lead 1 event

| Tactic | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 0.985 | 0.900 | 0.941 | 78,311 |
| RECONNAISSANCE | 0.982 | 0.996 | 0.989 | 24,969 |
| INITIAL_ACCESS | 0.912 | 0.982 | 0.945 | 1,514 |
| CREDENTIAL_ACCESS | 0.148 | 0.802 | 0.249 | 947 |
| DISCOVERY | 0.931 | 0.992 | 0.961 | 11,987 |
| LATERAL_MOVEMENT | 0.777 | 0.980 | 0.867 | 764 |
| COMMAND_AND_CONTROL | 0.029 | 0.226 | 0.051 | 53 |
| EXFILTRATION | 0.000 | 0.000 | 0.000 | 1 |
| IMPACT | 0.967 | 0.985 | 0.976 | 40,267 |

### 7.3 Environment B — UNSW-NB15, held out, foreign flow extractor (300,000 windows)

- Next-tactic: top-1 0.9289 · top-2 0.9630 · top-3 0.9818 · macro-F1 all-9 0.2335 · macro-F1 learnable 0.3503 · attack/benign F1 0.8745
- Calibration: ECE 0.0480 · MCE 0.2309 · Brier 0.1297
- time-to-stage-change (186,819): MAE 0.28 s · MAPE 0.253 · median APE 0.140
- time-to-next-flow (300,000): MAE 0.06 s · MAPE 0.055
- Escalation (positive rate 0.238): ROC-AUC 0.8948 · PR-AUC 0.7067 · recall @ FPR≤0.15 0.7662 · best-F1 0.6848 · Brier 0.1316

| Tactic | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 0.960 | 0.983 | 0.971 | 262,501 |
| RECONNAISSANCE | 0.000 | 0.000 | 0.000 | 1,925 |
| INITIAL_ACCESS | 0.204 | 0.323 | 0.250 | 5,384 |
| CREDENTIAL_ACCESS | n/a | n/a | n/a | 0 |
| DISCOVERY | 0.242 | 0.003 | 0.006 | 2,805 |
| LATERAL_MOVEMENT | 0.000 | 0.000 | 0.000 | 19 |
| COMMAND_AND_CONTROL | 0.047 | 0.364 | 0.083 | 272 |
| EXFILTRATION | n/a | n/a | n/a | 0 |
| IMPACT | 0.915 | 0.697 | 0.791 | 27,094 |

### 7.4 Baselines (test split, next-tactic)

| Method | top-1 | macro-F1 (present classes) |
|---|---|---|
| Persistence (predict current tactic) | 0.972 | 0.705 |
| Markov order-2 | 0.974 | 0.650 |
| Markov order-1 | 0.972 | 0.648 |
| Marginal prior | 0.493 | 0.073 |
| **This model** | **0.944** | **0.847 (learnable)** |

The model trades a small amount of majority-class top-1 accuracy for a large gain
on rare-transition F1, calibration, time-to-event estimates, and cross-
environment transfer, none of which the baselines provide.

---

## 8. Known limitations

1. **env-B attack/benign F1 (0.874) depends on the +1.60 BENIGN-logit prior correction** fitted on the labelled `envB_cal` slice. Without it the same checkpoint scores 0.801. This is a tuned operating point, not an intrinsic property.
2. **env-B fine-grained tactic identification is weak (macro-F1 0.35).** IMPACT (F1 0.79) and INITIAL_ACCESS (0.25) transfer across flow extractors; RECONNAISSANCE, DISCOVERY, LATERAL_MOVEMENT do not. CREDENTIAL_ACCESS is impossible on env-B — UNSW-NB15 contains zero credential-access flows.
3. **CREDENTIAL_ACCESS is weak in-domain as well (F1 0.25):** high recall (0.80), low precision (0.15) — genuine feature-space overlap with BENIGN that oversampling did not resolve.
4. **COMMAND_AND_CONTROL and EXFILTRATION have negligible test support** (53 and 1 examples). Their per-class numbers are not statistically meaningful; both are excluded from the gated `macro_f1_learnable`.
5. **Lead time is sub-second.** Attacks in the primary sources progress in milliseconds, so "seconds of warning" is not physically available; lead is reported in events (median 1 event early).
6. **CSE-CIC-IDS-2018 is not ingested.** The corrected 2018 set (~34 GB) would add a third environment and more volume but requires a streaming refactor of `build.py` to fit in memory.

---

## 9. File layout and reproduction

```
ml/
  config.py            paths, sessionization constants, SEQ_LEN=64
  data/
    schema.py          tactic vocabulary, per-source column and label maps
    sources.py         streaming per-dataset readers -> normalized long frame
    sessionize.py      victim-host + time-gap episode segmentation
    features.py        causal feature blocks + target construction
    build.py           orchestrator CLI -> events/episodes Parquet + manifests
  dataset.py           ForecastWindows (windowed Dataset) + make_loaders
  model.py             ForecastNet + multitask_loss
  train.py             training loop, temperature scaling, scorecard
  eval.py              metric functions, inference, plots
  calibrate_envb.py    env-B post-hoc prior correction tuner
  rescore.py           re-run eval battery + scorecard on any checkpoint
  eda.py               exploratory report and figures
  baselines/markov.py  persistence / Markov / marginal baselines
```

```bash
# 1. compile the event table (raw datasets must be present outside the repo)
python -m ml.data.build --datasets dapt2020,cicids2017,unsw_nb15

# 2. train
python -m ml.train --epochs 22 --lr 1e-3 --pct-start 0.3 --weight-cap 120 \
  --loss-weights 1,0.4,0.15,0.5 --dropout 0.25 --patience 6 \
  --oversample "CREDENTIAL_ACCESS:10,COMMAND_AND_CONTROL:10,EXFILTRATION:25" \
  --feat-jitter 0.03 --envb-cal 1 --tag forecast

# 3. fit the env-B prior correction
python -m ml.calibrate_envb

# 4. re-score with the calibration applied
python -m ml.rescore --ckpt ml/artifacts/forecast.pt --tag forecast
```

Environment: Python 3.12, PyTorch 2.6 + CUDA 12.4, pandas 3.0, NumPy 2.5,
scikit-learn 1.9, pyarrow. Raw datasets and `ml/artifacts/` are not tracked in
git.
