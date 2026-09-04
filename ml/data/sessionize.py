"""Group normalised flows into attack episodes (sequences)."""
from __future__ import annotations

import ipaddress

import numpy as np
import pandas as pd

from .. import config
from . import schema


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def _victim(src_ip: str, dst_ip: str) -> str:
    """Episode anchor = the internal host under attack (prefer dst)."""
    if _is_private(dst_ip):
        return str(dst_ip)
    if _is_private(src_ip):
        return str(src_ip)
    return str(dst_ip)


def sessionize(df: pd.DataFrame,
               gap_s: float = config.GAP_SECONDS,
               min_events: int = config.MIN_EVENTS,
               max_events: int = config.MAX_EVENTS,
               benign_keep: float = config.BENIGN_EPISODE_KEEP,
               seed: int = config.SEED) -> pd.DataFrame:
    """Return the frame with episode_id / seq_idx / dt_prev added, filtered."""
    if df.empty:
        return df
    df = df.sort_values(["dataset", "day", "ts"]).reset_index(drop=True)
    df["victim"] = [_victim(s, d) for s, d in zip(df["src_ip"], df["dst_ip"])]

    grp = df.groupby(["dataset", "day", "victim"], sort=False)
    df["dt_prev"] = grp["ts"].diff().fillna(0.0).clip(lower=0.0)

    # new episode on long gap or when a run exceeds max_events
    new_ep = np.array(df["dt_prev"] > gap_s, dtype=bool)
    pos_in_grp = grp.cumcount().to_numpy()
    new_ep |= (pos_in_grp % max_events == 0) & (pos_in_grp > 0)
    # first row of every (dataset,day,victim) group also starts an episode
    first_mask = ~df.duplicated(["dataset", "day", "victim"]).to_numpy()
    new_ep |= first_mask
    df["episode_id"] = (np.cumsum(new_ep) - 1).astype("int64")

    ep = df.groupby("episode_id", sort=False)
    df["seq_idx"] = ep.cumcount().astype("int32")
    df["dt_prev"] = np.where(df["seq_idx"].to_numpy() == 0, 0.0, df["dt_prev"].to_numpy())

    # per-episode summary + filter
    summ = ep.agg(n_events=("ts", "size"),
                  n_malicious=("tactic", lambda s: int((s != "BENIGN").sum())),
                  ts_start=("ts", "min"), ts_end=("ts", "max"),
                  dataset=("dataset", "first"), day=("day", "first"),
                  victim=("victim", "first"), domain=("domain", "first"))
    summ["tactics_seen"] = ep["tactic"].agg(lambda s: sorted(set(s)))
    summ["reached_impact"] = ep["tactic"].agg(
        lambda s: int(any(t in schema.ESCALATION_TACTICS for t in s)))
    summ["duration_s"] = (summ["ts_end"] - summ["ts_start"]).astype("float32")

    rng = np.random.default_rng(seed)
    long_enough = summ["n_events"] >= min_events
    has_attack = summ["n_malicious"] > 0
    benign_sample = (~has_attack) & (rng.random(len(summ)) < benign_keep)
    keep_ids = summ.index[long_enough & (has_attack | benign_sample)]

    df = df[df["episode_id"].isin(keep_ids)].copy()
    # renumber episodes 0..K-1 contiguously
    remap = {old: new for new, old in enumerate(sorted(df["episode_id"].unique()))}
    df["episode_id"] = df["episode_id"].map(remap).astype("int64")
    summ = summ.loc[keep_ids].reset_index(drop=True)
    summ["episode_id"] = [remap[i] for i in keep_ids]
    return df.reset_index(drop=True), summ
