"""Orchestrator: raw dataset CSVs -> events.parquet + episodes.parquet + manifests.

Usage:
    python -m ml.data.build --datasets dapt2020,cicids2017
    python -m ml.data.build --datasets all --nrows 0 --day-limit 0
    python -m ml.data.build --datasets cicids2018 --nrows 2000000     # quick slice
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from .. import config
from . import features, schema, sessionize
from .sources import load_source

ALL = ["dapt2020", "cicids2017", "cicids2018", "unsw_nb15"]


ENVB_CAL_FRAC = 0.15   # A5: reserve a small stratified slice of the held-out
#                        env-B (foreign-sensor) domain for supervised calibration
#                        -- adapts the next-tactic head across the CICFlowMeter->
#                        Argus schema gap that pure zero-shot cannot bridge.


def _envb_cal_ids(envb: pd.DataFrame, sev: pd.Series, rng, carve: str) -> set:
    """Pick the ``envB_cal`` episode ids (~ENVB_CAL_FRAC of env-B).

    carve="severity"  : stratified-random within each severity bucket (default).
    carve="transition": greedily prefer episodes rich in *rare* tactics, so the
                        small labelled slice maximises coverage of the rare
                        attack-stage transitions the head can't otherwise learn
                        on the foreign schema.
    """
    eids = envb["episode_id"].to_numpy()
    if len(eids) < 10:
        return set()
    if carve == "transition":
        from collections import Counter
        freq: Counter = Counter()
        for ts in envb["tactics_seen"]:
            for t in set(ts):
                freq[t] += 1
        def score(ts):
            rare = set(ts) - {"BENIGN"}
            return sum(1.0 / freq[t] for t in rare) if rare else 0.0
        sc = envb["tactics_seen"].map(score).to_numpy(dtype=float)
        sc = sc + rng.random(len(sc)) * 1e-3           # tie-break / de-determinise
        k = int(round(len(eids) * ENVB_CAL_FRAC))
        return set(eids[np.argsort(-sc)[:k]].tolist())
    cal: set = set()
    for _s, g in envb.assign(_sev=sev.loc[envb.index]).groupby("_sev", sort=False):
        gi = g["episode_id"].to_numpy().copy()
        rng.shuffle(gi)
        kk = int(round(len(gi) * ENVB_CAL_FRAC)) if len(gi) >= 10 else 0
        cal.update(gi[:kk].tolist())
    return cal


def _assign_splits(episodes: pd.DataFrame, cal_carve: str = "severity") -> dict:
    """Episode-level train/val/test split, stratified by (domain, severity).

    Severity = the highest ATT&CK tactic id present in the episode, so every
    rare stage (LATERAL_MOVEMENT, C2, EXFILTRATION, ...) is represented in all
    three splits instead of landing in one bucket by a raw victim hash.

    env-B is otherwise held out entirely; ``ENVB_CAL_FRAC`` is carved off as
    ``envB_cal`` for the calibration slice (see ``_envb_cal_ids``).
    """
    tr, va, _ = config.SPLIT_FRACS
    rng = np.random.default_rng(config.SEED)
    sev = episodes["tactics_seen"].map(
        lambda ts: max((schema.TACTIC_TO_ID.get(t, 0) for t in ts), default=0))
    out: dict[int, str] = {}

    envb = episodes[episodes["domain"] == "envB"]
    if len(envb):
        cal = _envb_cal_ids(envb, sev, rng, cal_carve)
        for e in envb["episode_id"].to_numpy():
            out[int(e)] = "envB_cal" if int(e) in cal else "envB"

    prim = episodes[episodes["domain"] != "envB"]
    for _s, grp in prim.assign(_sev=sev.loc[prim.index]).groupby("_sev", sort=False):
        ids = grp["episode_id"].to_numpy().copy()
        rng.shuffle(ids)
        n = len(ids)
        a, b = max(1, int(round(n * tr))), max(1, int(round(n * (tr + va))))
        if n <= 3:                       # too few to split -- keep for training
            out.update({int(e): "train" for e in ids})
            continue
        out.update({int(e): "train" for e in ids[:a]})
        out.update({int(e): "val" for e in ids[a:b]})
        out.update({int(e): "test" for e in ids[b:]})
    return out


def _feature_columns(f: pd.DataFrame) -> list[str]:
    drop = {"episode_id", "seq_idx", "dataset", "day", "domain", "victim", "ts",
            "tactic", "tactic_id", "raw_label", "split",
            "next_tactic_id", "time_to_next", "time_to_next_change", "reached_impact_h"}
    return [c for c in f.columns
            if c not in drop and pd.api.types.is_numeric_dtype(f[c])]


def main() -> None:
    global ENVB_CAL_FRAC
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", default="dapt2020,cicids2017")
    ap.add_argument("--nrows", type=int, default=0, help="cap rows per CSV (0 = all)")
    ap.add_argument("--day-limit", type=int, default=0, help="cap CSVs per dataset (0 = all)")
    ap.add_argument("--gap", type=float, default=config.GAP_SECONDS)
    ap.add_argument("--min-events", type=int, default=config.MIN_EVENTS)
    ap.add_argument("--max-events", type=int, default=config.MAX_EVENTS)
    ap.add_argument("--benign-keep", type=float, default=config.BENIGN_EPISODE_KEEP)
    ap.add_argument("--out", default=str(config.ARTIFACT_DIR))
    ap.add_argument("--cal-frac", type=float, default=ENVB_CAL_FRAC,
                    help="fraction of env-B episodes carved into envB_cal")
    ap.add_argument("--cal-carve", choices=["severity", "transition"], default="severity",
                    help="how to pick the envB_cal slice")
    args = ap.parse_args()
    ENVB_CAL_FRAC = args.cal_frac

    datasets = ALL if args.datasets.strip() == "all" else \
        [d.strip() for d in args.datasets.split(",") if d.strip()]
    nrows = args.nrows or None
    day_limit = args.day_limit or None
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    raw_parts, label_counts = [], {}
    for ds in datasets:
        ts = time.time()
        df = load_source(ds, nrows=nrows, day_limit=day_limit)
        label_counts[ds] = df["raw_label"].value_counts().to_dict() if not df.empty else {}
        print(f"[load] {ds:11s} {len(df):>10,} flows  "
              f"tactics={df['tactic'].value_counts().to_dict() if not df.empty else {}}  "
              f"({time.time()-ts:.1f}s)")
        if not df.empty:
            raw_parts.append(df)
    if not raw_parts:
        raise SystemExit("no data loaded")
    flows = pd.concat(raw_parts, ignore_index=True)
    del raw_parts

    ev_parts, ep_parts = [], []
    for domain in ("primary", "envB"):
        sub = flows[flows["domain"] == domain]
        if sub.empty:
            continue
        sess, summ = sessionize.sessionize(
            sub, gap_s=args.gap, min_events=args.min_events,
            max_events=args.max_events,
            benign_keep=(1.0 if domain == "envB" else args.benign_keep))
        if sess.empty:
            continue
        offset = sum(len(p) for p in ep_parts)          # keep episode_id globally unique
        sess["episode_id"] += offset
        summ["episode_id"] += offset
        feat = features.build_features(sess)
        feat = features.add_targets(feat, horizon=config.IMPACT_HORIZON_EVENTS)
        ev_parts.append(feat)
        ep_parts.append(summ)
        print(f"[sessionize] {domain:8s} episodes={len(summ):>7,}  events={len(feat):>10,}  "
              f"reached_impact={int(summ['reached_impact'].sum()):,}")

    events = pd.concat(ev_parts, ignore_index=True)
    episodes = pd.concat(ep_parts, ignore_index=True)

    split_map = _assign_splits(episodes, cal_carve=args.cal_carve)
    events["split"] = events["episode_id"].map(split_map).astype("string")
    episodes["split"] = episodes["episode_id"].map(split_map).astype("string")

    # --- standardisation stats on TRAIN only -----------------------------
    feat_cols = _feature_columns(events)
    all_nan = [c for c in feat_cols if events[c].isna().all()]
    if all_nan:
        print(f"[manifest] excluding {len(all_nan)} all-NaN feature cols "
              f"(kept in parquet): {all_nan}")
        feat_cols = [c for c in feat_cols if c not in all_nan]
    tr = events[events["split"] == "train"]
    stats = {c: {"mean": float(np.nan_to_num(tr[c].mean())),
                 "std": float(np.nan_to_num(tr[c].std()) or 1.0)}
             for c in feat_cols if pd.api.types.is_numeric_dtype(events[c])}

    events.to_parquet(out / "events.parquet", index=False)
    episodes.to_parquet(out / "episodes.parquet", index=False)
    manifest = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "datasets": datasets,
        "envb_cal_frac": args.cal_frac, "envb_cal_carve": args.cal_carve,
        "n_events": int(len(events)), "n_episodes": int(len(episodes)),
        "seq_len": config.SEQ_LEN,
        "tactics": schema.TACTICS,
        "feature_columns": feat_cols,
        "embedding_columns": ["prev_tactic_id", "prev2_tactic_id"],
        "target_columns": ["next_tactic_id", "time_to_next", "time_to_next_change",
                           "reached_impact_h"],
        "standardization": stats,
        "split_counts": events.groupby("split").size().to_dict(),
        "tactic_counts": events["tactic"].value_counts().to_dict(),
        "next_tactic_counts": events[events["next_tactic_id"] >= 0]["next_tactic_id"]
            .map(schema.ID_TO_TACTIC).value_counts().to_dict(),
        "episodes_by_split": episodes.groupby("split").size().to_dict(),
        "reached_impact_episodes": int(episodes["reached_impact"].sum()),
    }
    (out / "feature_manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    (out / "label_map.json").write_text(json.dumps({
        "label_to_tactic_source": {
            "dapt2020": schema.DAPT_STAGE_TO_TACTIC,
            "cicids": schema.CIC_LABEL_TO_TACTIC,
            "unsw_nb15": schema.UNSW_CAT_TO_TACTIC,
        },
        "raw_label_counts": label_counts,
    }, indent=2))

    print(f"\n[done] {time.time()-t0:.1f}s  ->  {out}")
    print(f"  events.parquet     {len(events):>10,} rows  x {len(feat_cols)} features")
    print(f"  episodes.parquet   {len(episodes):>10,} rows")
    print(f"  split (events):     {manifest['split_counts']}")
    print(f"  next-tactic dist:   {manifest['next_tactic_counts']}")


if __name__ == "__main__":
    main()
