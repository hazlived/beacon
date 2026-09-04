# `ml/data` — dataset loader → training artifacts

Turns raw NIDS CSVs into two Parquet files the forecasting model trains on.

## Run

```bash
# quick (DAPT2020 + improved CIC-IDS2017 only)
python -m ml.data.build --datasets dapt2020,cicids2017

# full v1 (adds UNSW-NB15 as held-out env B)
python -m ml.data.build --datasets dapt2020,cicids2017,unsw_nb15

# everything, capping the 44 GB CIC-IDS2018 for a fast pass
python -m ml.data.build --datasets all --nrows 1200000
```

Env vars: `BEACON_DATA_ROOT` (default `D:\Coding\datasets\beacon`), `BEACON_ARTIFACT_DIR`.

## Outputs (`ml/artifacts/`)

| file | contents |
|---|---|
| `events.parquet` | one row per flow, engineered features + causal targets + `split` |
| `episodes.parquet` | one row per episode: victim, n_events, tactics_seen, reached_impact, split |
| `feature_manifest.json` | ordered feature columns, embedding cols, target cols, train-only standardization stats, tactic vocab, split/label counts |
| `label_map.json` | the label→tactic maps actually applied + raw label counts per dataset |

## Pipeline

1. **sources.py** — per-dataset reader → normalised long frame (`ts`,5-tuple,~60 canonical CICFlowMeter features,`tactic`,`dataset`,`day`,`domain`). Streams CSVs in 400k-row chunks. Handles the DAPT file that ships without a header and the DistriNet `- Attempted` labels (→ BENIGN).
2. **sessionize.py** — episode = run of flows sharing one internal victim host within a `--gap` (300 s) window; `episode_id`, `seq_idx`, `dt_prev`. Drops episodes < `--min-events`; keeps `--benign-keep` (15%) of pure-benign episodes as negatives.
3. **features.py** — strictly causal blocks: temporal · entity-graph (expanding fan-out / unique ports·IPs / new-entity) · history aggregates (per-tactic running counts, prev tactic ids, cumulative bytes, burstiness) · robust flow-derived (log transforms, ratios, SYN-no-ACK, RST rate, port buckets, proto one-hots). Targets: `next_tactic_id`, `time_to_next`, `time_to_next_change`, `reached_impact_h` (escalation within `IMPACT_HORIZON_EVENTS`).
4. **build.py** — orchestrates, splits **by `(dataset,day,victim)` hash** (70/15/15) so a victim-day never straddles splits; UNSW → `split="envB"` (never trained on). Writes manifests.

## Tunables needing a team review pass

- **`schema.py` label→tactic maps** — several judgment calls (PortScan→RECON vs DISCOVERY; Fuzzers→DISCOVERY; Generic→IMPACT; Infiltration→LATERAL_MOVEMENT). One pass to agree.
- `GAP_SECONDS`, `MIN_EVENTS`, `BENIGN_EPISODE_KEEP`, `IMPACT_HORIZON_EVENTS` in `config.py`.
- Victim heuristic in `sessionize._victim` (currently: whichever endpoint is RFC1918, preferring dst).
