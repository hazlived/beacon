# `ml/data` — raw NIDS CSVs → training artifacts

Compiles the raw datasets into the Parquet tables and manifests the forecasting
model trains and evaluates on. Current-state reference; see `ml/STATUS.md` for
the model side.

## Run

```bash
# primary domain only (DAPT 2020 + corrected CIC-IDS-2017)
python -m ml.data.build --datasets dapt2020,cicids2017

# full build: adds UNSW-NB15 as held-out environment B + its calibration slice
python -m ml.data.build --datasets dapt2020,cicids2017,unsw_nb15

# everything, capping the large CSE-CIC-IDS-2018 set for a fast pass
python -m ml.data.build --datasets all --nrows 1200000
```

Environment variables: `BEACON_DATA_ROOT` (raw CSV root, default
`D:\Coding\datasets\beacon`), `BEACON_ARTIFACT_DIR` (output root, default
`ml/artifacts/`).

### CLI flags

| flag | default | meaning |
|---|---|---|
| `--datasets` | `dapt2020,cicids2017` | comma list, or `all` |
| `--nrows` | `0` (all) | cap rows read per CSV |
| `--day-limit` | `0` (all) | cap CSVs read per dataset |
| `--gap` | `300` | seconds; inter-flow gap that starts a new episode |
| `--min-events` | `3` | drop episodes shorter than this |
| `--max-events` | `512` | hard-split episodes longer than this |
| `--benign-keep` | `0.15` | fraction of pure-benign episodes kept as negatives |
| `--cal-frac` | `0.15` | fraction of env-B episodes carved into `envB_cal` |
| `--cal-carve` | `severity` | `severity` = stratified-random within each severity bucket; `transition` = greedily prefer episodes rich in rare tactics |
| `--out` | `ml/artifacts` | output directory |

## Datasets

| key | source | role |
|---|---|---|
| `dapt2020` | DAPT 2020 CICFlowMeter CSVs with a native kill-chain `Stage` column | primary — the only source with ground-truth multi-stage sequences |
| `cicids2017` | CIC-IDS-2017, corrected labels + re-extracted flows (IEEE CNS 2022, DistriNet/KU Leuven), 91-column improved schema | primary — bulk of flow/timing volume and attack-type diversity |
| `cicids2018` | CSE-CIC-IDS-2018, same corrected source (large; not part of the standard build) | optional extra volume / third environment |
| `unsw_nb15` | UNSW-NB15 full set (`UNSW-NB15_1..4.csv`), Argus/Bro 49-column schema with `ct_*` connection-tracking features | held-out **environment B** (different network, different flow extractor); a stratified slice becomes `envB_cal` |

## Pipeline

1. **`sources.py`** — per-dataset streaming reader → one normalized long frame
   (`ts`, 5-tuple, ~60 canonical flow features, `tactic`, `dataset`, `day`,
   `domain`). Reads CSVs in 400k-row chunks. Handles the DAPT file that ships
   without a header, maps the corrected-CIC `- Attempted` labels to BENIGN, and
   restores UNSW rows whose `attack_cat` is blank to `Normal`. Timestamps are
   kept in float64 (float32 loses ~2 minutes of epoch resolution).

2. **`sessionize.py`** — an episode is a run of flows sharing one internal
   (RFC1918) victim host within a `--gap` window. Assigns `episode_id`,
   `seq_idx`, `dt_prev`. Drops episodes below `--min-events`; hard-splits at
   `--max-events`; keeps `--benign-keep` of purely-benign episodes as negatives.
   Victim heuristic (`_victim`): whichever endpoint is RFC1918, preferring the
   destination.

3. **`features.py`** — strictly causal blocks (each value uses only the current
   flow and earlier ones in the episode):
   - temporal — gaps, time-since-start, event index, tactic-change flags, cyclical hour/day-of-week
   - entity-graph, expanding — unique destination ports/IPs so far, pair-repeat count, new-entity flags
   - history aggregates — per-tactic running counts, previous/second-previous tactic ids, cumulative bytes, gap burstiness, fraction malicious so far
   - connection-tracking — the UNSW `ct_*` features (passed through where present)
   - flow statistics — packet-length / inter-arrival / flag / subflow / active-idle statistics
   - robust / derived — log transforms, byte-per-packet and forward/backward ratios, SYN-without-ACK, RST rate, well-known/registered/ephemeral port buckets, explicit `port_is_<N>` flags, protocol one-hots

   Targets: `next_tactic_id`, `time_to_next`, `time_to_next_change`,
   `reached_impact_h` (an escalation tactic within `IMPACT_HORIZON_EVENTS` = 20).

4. **`build.py`** — orchestrates the above, assigns splits, fits standardization
   statistics on `train` only, writes the artifacts.

## Splits (`_assign_splits`)

Episode-level, never row-level.

- **Primary** (`dapt2020` + `cicids2017`) — stratified by `(domain, severity)`
  where severity is the highest ATT&CK tactic id present in the episode, then
  70 / 15 / 15 into `train` / `val` / `test`. Strata with ≤3 episodes go
  entirely to `train`.
- **Environment B** (`unsw_nb15`) — held out from training. `--cal-frac` of its
  episodes are carved into `envB_cal` (used for cross-sensor calibration); the
  rest are `envB` (zero-adaptation evaluation).

Current full-build artifact:

| split | episodes | events |
|---|---|---|
| `train` | 1,522 | 765,089 |
| `val` | 325 | 162,424 |
| `test` | 326 | 159,139 |
| `envB` | 4,822 | 2,158,078 |
| `envB_cal` | 850 | 381,793 |

## Outputs (`ml/artifacts/`)

| file | contents |
|---|---|
| `events.parquet` | one row per flow: engineered features + causal targets + `split` |
| `episodes.parquet` | one row per episode: victim, `n_events`, `tactics_seen`, `reached_impact`, `duration_s`, `n_malicious`, `split` |
| `feature_manifest.json` | ordered feature columns, embedding columns, target columns, train-only standardization stats, tactic vocabulary, split / next-tactic counts, `envb_cal_frac`, `envb_cal_carve` |
| `label_map.json` | the label→tactic maps actually applied + raw label counts per dataset |

Raw datasets and `ml/artifacts/` are not tracked in git.

## Tactic vocabulary (9 classes)

`BENIGN, RECONNAISSANCE, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY,
LATERAL_MOVEMENT, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT`

Label→tactic mappings live in `schema.py` and are echoed into `label_map.json`.
Notable judgment calls: PortScan → RECONNAISSANCE, Infiltration-PortScan →
DISCOVERY, Infiltration → LATERAL_MOVEMENT, UNSW Fuzzers → DISCOVERY, UNSW
Generic / DoS → IMPACT, Botnet / Backdoor → COMMAND_AND_CONTROL.

## Config tunables (`ml/config.py`)

`GAP_SECONDS` 300 · `MIN_EVENTS` 3 · `MAX_EVENTS` 512 · `BENIGN_EPISODE_KEEP`
0.15 · `IMPACT_HORIZON_EVENTS` 20 · `SPLIT_FRACS` (0.70, 0.15, 0.15) · `SEED`
1337 · `SEQ_LEN` 64. Per-dataset paths are in `config.PATHS`.
