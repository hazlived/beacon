"""Causal per-episode feature engineering + supervised targets.

Everything here is strictly causal: feature row t may only use flows 0..t.
Produced blocks (see ml/data/README.md for the spec):
    temporal | entity-graph | history-aggregate | robust-flow | prev-tactic
Targets:
    next_tactic_id | time_to_next | time_to_next_change | reached_impact_h
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .. import config
from . import schema

EXPLICIT_PORTS = [22, 23, 25, 53, 80, 443, 445, 3389, 3306, 1433, 8080, 4444, 21, 139, 135]
_LOG_COLS = ["duration", "fwd_bytes", "bwd_bytes", "flow_bytes_s", "flow_pkts_s",
             "flow_iat_mean", "flow_iat_max", "active_mean", "idle_mean"]


def _safe_log1p(x: pd.Series) -> pd.Series:
    return np.log1p(x.clip(lower=0).fillna(0.0))


def _expanding_nunique(s: pd.Series) -> np.ndarray:
    seen, out = set(), np.empty(len(s), dtype="int32")
    for i, v in enumerate(s.to_numpy()):
        seen.add(v)
        out[i] = len(seen)
    return out


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """df must carry episode_id, seq_idx, dt_prev, ts, tactic + canon flow feats."""
    df = df.sort_values(["episode_id", "seq_idx"]).reset_index(drop=True)
    g = df.groupby("episode_id", sort=False)
    n = len(df)
    f = pd.DataFrame(index=df.index)

    # ---- temporal ----------------------------------------------------------
    f["dt_prev"] = df["dt_prev"].astype("float32")
    f["log_dt_prev"] = np.log1p(df["dt_prev"].clip(lower=0)).astype("float32")
    f["t_since_start"] = (df["ts"] - g["ts"].transform("min")).astype("float32")
    f["event_idx"] = df["seq_idx"].astype("float32")
    tac_change = (df["tactic"].to_numpy() != g["tactic"].shift(1).to_numpy())
    f["is_tactic_change"] = tac_change.astype("float32")
    secs_since = np.zeros(n, dtype="float32")
    last_change_t = {}
    for i, (ep, t, ch) in enumerate(zip(df["episode_id"], df["ts"], tac_change)):
        if ch or ep not in last_change_t:
            last_change_t[ep] = t
        secs_since[i] = t - last_change_t[ep]
    f["secs_since_tactic_change"] = secs_since
    dt = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    hr = dt.dt.hour.fillna(0).to_numpy(); dow = dt.dt.dayofweek.fillna(0).to_numpy()
    f["hour_sin"] = np.sin(2 * np.pi * hr / 24).astype("float32")
    f["hour_cos"] = np.cos(2 * np.pi * hr / 24).astype("float32")
    f["dow_sin"] = np.sin(2 * np.pi * dow / 7).astype("float32")
    f["dow_cos"] = np.cos(2 * np.pi * dow / 7).astype("float32")

    # ---- entity-graph (expanding, causal) --------------------------------
    f["uniq_dst_ports_so_far"] = g["dst_port"].transform(_expanding_nunique).astype("float32")
    f["uniq_dst_ips_so_far"] = g["dst_ip"].transform(_expanding_nunique).astype("float32")
    pair = df["src_ip"].astype(str) + ">" + df["dst_ip"].astype(str)
    f["pair_repeat_count"] = pair.groupby(df["episode_id"]).cumcount().astype("float32")
    f["is_new_dst_ip"] = (g["dst_ip"].transform(_expanding_nunique)
                          > g["dst_ip"].transform(_expanding_nunique).groupby(df["episode_id"]).shift(1).fillna(0)).astype("float32")
    f["is_new_dst_port"] = (g["dst_port"].transform(_expanding_nunique)
                            > g["dst_port"].transform(_expanding_nunique).groupby(df["episode_id"]).shift(1).fillna(0)).astype("float32")

    # ---- history aggregates (shifted -> exclude current row) -------------
    mal = (df["tactic"].to_numpy() != "BENIGN").astype("float32")
    f["frac_malicious_so_far"] = (pd.Series(mal, index=df.index).groupby(df["episode_id"]).apply(
        lambda s: s.shift(1).expanding().mean()).reset_index(level=0, drop=True).fillna(0.0).astype("float32"))
    f["cum_fwd_bytes"] = _safe_log1p(g["fwd_bytes"].cumsum().groupby(df["episode_id"]).shift(1).fillna(0)).astype("float32")
    f["cum_bwd_bytes"] = _safe_log1p(g["bwd_bytes"].cumsum().groupby(df["episode_id"]).shift(1).fillna(0)).astype("float32")
    tac_id = df["tactic"].map(schema.TACTIC_TO_ID).fillna(0).astype("int64")
    f["prev_tactic_id"] = tac_id.groupby(df["episode_id"]).shift(1).fillna(0).astype("int64")
    f["prev2_tactic_id"] = tac_id.groupby(df["episode_id"]).shift(2).fillna(0).astype("int64")
    f["max_tactic_depth_so_far"] = tac_id.groupby(df["episode_id"]).apply(
        lambda s: s.shift(1).expanding().max()).reset_index(level=0, drop=True).fillna(0).astype("float32")
    # per-tactic running counts (causal)
    for t, tid in schema.TACTIC_TO_ID.items():
        col = (tac_id == tid).astype("float32")
        f[f"cnt_{t.lower()}_so_far"] = col.groupby(df["episode_id"]).apply(
            lambda s: s.shift(1).expanding().sum()).reset_index(level=0, drop=True).fillna(0.0).astype("float32")
    # burstiness of inter-event gaps so far
    f["gap_burstiness"] = (df["dt_prev"].groupby(df["episode_id"]).apply(
        lambda s: s.shift(1).expanding().std() / (s.shift(1).expanding().mean() + 1e-6))
        .reset_index(level=0, drop=True).fillna(0.0).clip(-10, 10).astype("float32"))

    # ---- UNSW connection-tracking passthrough (NaN elsewhere) -----------
    for c in schema.UNSW_CT_FEATURES:
        f[c] = pd.to_numeric(df[c], errors="coerce").astype("float32")

    # ---- robust flow-derived -------------------------------------------
    for c in schema.CANON_FLOW_FEATURES:
        f[c] = pd.to_numeric(df[c], errors="coerce").astype("float32")
    for c in _LOG_COLS:
        f[f"log_{c}"] = _safe_log1p(df[c].astype("float32")).astype("float32")
    tot_pkts = (df["fwd_pkts"].fillna(0) + df["bwd_pkts"].fillna(0)).replace(0, np.nan)
    f["bytes_per_pkt_fwd"] = (df["fwd_bytes"] / df["fwd_pkts"].replace(0, np.nan)).fillna(0).astype("float32")
    f["bytes_per_pkt_bwd"] = (df["bwd_bytes"] / df["bwd_pkts"].replace(0, np.nan)).fillna(0).astype("float32")
    f["fwd_bwd_pkt_ratio"] = (df["fwd_pkts"] / df["bwd_pkts"].replace(0, np.nan)).fillna(0).clip(0, 1e4).astype("float32")
    f["syn_no_ack"] = (df["syn_flags"].fillna(0) / (df["ack_flags"].fillna(0) + 1)).astype("float32")
    f["rst_rate"] = (df["rst_flags"].fillna(0) / (tot_pkts.fillna(1))).astype("float32")
    dp = df["dst_port"].fillna(0).astype("int64")
    f["port_wellknown"] = (dp < 1024).astype("float32")
    f["port_registered"] = ((dp >= 1024) & (dp < 49152)).astype("float32")
    f["port_ephemeral"] = (dp >= 49152).astype("float32")
    for p in EXPLICIT_PORTS:
        f[f"port_is_{p}"] = (dp == p).astype("float32")
    proto = df["protocol"].fillna(0).astype("int64")
    f["proto_tcp"] = (proto == 6).astype("float32")
    f["proto_udp"] = (proto == 17).astype("float32")
    f["proto_icmp"] = (proto == 1).astype("float32")
    f["proto_other"] = (~proto.isin([6, 17, 1])).astype("float32")

    # ---- carry ids + raw tactic -------------------------------------------
    carry = {c: df[c].values for c in
             ("episode_id", "seq_idx", "dataset", "day", "domain", "victim", "ts", "tactic")}
    carry["tactic_id"] = tac_id.values
    f = pd.concat([f, pd.DataFrame(carry, index=f.index)], axis=1).copy()

    f = f.replace([np.inf, -np.inf], np.nan)
    return f


def add_targets(f: pd.DataFrame,
                horizon: int = config.IMPACT_HORIZON_EVENTS) -> pd.DataFrame:
    """Append causal supervised targets. Last event per episode -> next_tactic_id = -1."""
    f = f.sort_values(["episode_id", "seq_idx"]).reset_index(drop=True)
    g = f.groupby("episode_id", sort=False)
    f["next_tactic_id"] = g["tactic_id"].shift(-1).fillna(-1).astype("int64")
    f["time_to_next"] = (g["ts"].shift(-1) - f["ts"]).astype("float32")

    # time until the tactic actually changes next (NaN if it never does).
    # Backward scan per episode: track the timestamp of the next stage change.
    ttc = np.full(len(f), np.nan, dtype="float32")
    for _, idx in g.groups.items():
        idx = list(idx)
        tac = f.loc[idx, "tactic_id"].to_numpy()
        ts = f.loc[idx, "ts"].to_numpy()
        next_change_t = np.nan
        for j in range(len(idx) - 1, -1, -1):
            if j + 1 < len(idx) and tac[j + 1] != tac[j]:
                next_change_t = ts[j + 1]
            ttc[idx[j]] = (next_change_t - ts[j]) if not np.isnan(next_change_t) else np.nan
    f["time_to_next_change"] = ttc

    # reached an escalation tactic within the next `horizon` events
    esc = f["tactic"].isin(schema.ESCALATION_TACTICS).to_numpy().astype("int8")
    out = np.zeros(len(f), dtype="int8")
    for _, idx in g.groups.items():
        idx = list(idx)
        e = esc[idx]
        for j in range(len(idx)):
            out[idx[j]] = int(e[j + 1: j + 1 + horizon].any())
    f["reached_impact_h"] = out
    return f
