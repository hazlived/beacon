"""Windowed PyTorch dataset + loaders for the forecasting model.

One training example per (episode, t): the model sees the last `seq_len` flows
ending at t (left-padded, with a mask) and predicts, for position t:
    y_next  -- next tactic id                       (classification, 10-way)
    y_ttn   -- log1p seconds to the next flow        (regression, masked)
    y_ttc   -- log1p seconds until the tactic changes(regression, masked)
    y_esc   -- escalation within H events            (binary)

Numeric features are standardised with TRAIN-only stats from feature_manifest.json;
NaNs -> 0 (== the train mean after standardisation), which is also how env-B's
missing CICFlowMeter columns degrade gracefully.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset

from .config import ARTIFACT_DIR, SEED, SEQ_LEN


def load_manifest(artifact_dir=ARTIFACT_DIR) -> dict:
    return json.loads((Path(artifact_dir) / "feature_manifest.json").read_text())


def _rank_normal(X: np.ndarray) -> np.ndarray:
    """Per-column rank -> Gaussian quantile (inverse-normal / "rankit").

    Unit- and shape-invariant: every column is remapped to ~N(0,1) through its
    own empirical CDF, so CICFlowMeter (seconds, one distribution) and Argus
    (mSec, a different distribution) land on the same axis. This is the correct
    normaliser for zero-shot cross-schema transfer; plain median/IQR only fixes
    center+scale, not distribution shape. Ties get the average rank, so binary
    flags collapse to two point masses instead of being smeared into noise.
    """
    from scipy.special import ndtri
    from scipy.stats import rankdata

    out = np.zeros_like(X, dtype="float32")
    for j in range(X.shape[1]):
        c = X[:, j]
        fin = np.isfinite(c)
        k = int(fin.sum())
        if k < 8:
            continue
        v = c[fin]
        if v.max() == v.min():
            continue
        ranks = rankdata(v, method="average") - 0.5      # in (0, k)
        p = np.clip(ranks / k, 1e-6, 1.0 - 1e-6)
        out[fin, j] = ndtri(p).astype("float32")
    return out


class ForecastWindows(Dataset):
    def __init__(self, artifact_dir=ARTIFACT_DIR, split="train", seq_len=SEQ_LEN,
                 standardize=True, log_time=True, min_context=1, manifest=None,
                 max_samples=None, zero_substr=None, keep_substr=None,
                 self_standardize=False, rank_norm=False):
        artifact_dir = Path(artifact_dir)
        self.split, self.seq_len = split, seq_len
        man = manifest or load_manifest(artifact_dir)
        self.manifest = man
        self.tactics = man["tactics"]
        self.n_tactics = len(self.tactics)
        self.emb_cols = list(man["embedding_columns"])
        _std = man["standardization"]
        self.num_cols = [c for c in man["feature_columns"]
                         if c not in self.emb_cols and c in _std]

        cols = (self.num_cols + self.emb_cols +
                ["episode_id", "seq_idx", "ts", "tactic_id", "next_tactic_id",
                 "time_to_next", "time_to_next_change", "reached_impact_h"])
        df = pd.read_parquet(artifact_dir / "events.parquet", columns=cols,
                             filters=[("split", "==", split)])
        if df.empty:
            raise ValueError(f"no rows for split={split!r} in {artifact_dir/'events.parquet'}")
        df = df.sort_values(["episode_id", "seq_idx"]).reset_index(drop=True)

        X = df[self.num_cols].to_numpy("float32")
        if rank_norm:
            # A5 v3: inverse-normal rank transform per column on THIS split's own
            # CDF. Supersedes standardize/self_standardize -- units and shape both
            # drop out, which is what cross-schema (CIC<->UNSW) transfer needs.
            X = _rank_normal(X)
        elif standardize:
            if self_standardize:
                # A5: re-scale this split with ITS OWN robust stats (median / IQR).
                # Scaling is not fitting -> no leakage; fixes CIC<->UNSW unit mismatch.
                med = np.nanmedian(X, axis=0)
                iqr = np.nanpercentile(X, 75, axis=0) - np.nanpercentile(X, 25, axis=0)
                iqr[~np.isfinite(iqr) | (iqr == 0)] = 1.0
                med = np.nan_to_num(med)
                X = (X - med) / (iqr * 0.7413)      # 0.7413*IQR ~= sigma for normal
            else:
                st = man["standardization"]
                mean = np.array([st[c]["mean"] for c in self.num_cols], "float32")
                std = np.array([st[c]["std"] for c in self.num_cols], "float32")
                std[std == 0] = 1.0
                X = (X - mean) / std
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        # ablation / transfer masking: zero whole feature columns by name-substring
        self.zeroed_cols: list[str] = []
        if zero_substr or keep_substr:
            zsub = [s for s in (zero_substr or []) if s]
            ksub = [s for s in (keep_substr or []) if s]
            for j, c in enumerate(self.num_cols):
                drop = any(s in c for s in zsub)
                if ksub and not any(s in c for s in ksub):
                    drop = True
                if drop:
                    X[:, j] = 0.0
                    self.zeroed_cols.append(c)
        self.X = X

        E = df[self.emb_cols].to_numpy("int64")
        self.E = np.clip(E, 0, self.n_tactics - 1)

        self.ep = df["episode_id"].to_numpy("int64")
        self.seq_idx = df["seq_idx"].to_numpy("int64")
        self.ts = df["ts"].to_numpy("float64")
        self.cur_tactic = df["tactic_id"].to_numpy("int64")
        self.y_next = df["next_tactic_id"].to_numpy("int64")
        ttn = df["time_to_next"].to_numpy("float32")
        ttc = df["time_to_next_change"].to_numpy("float32")
        self.y_esc = df["reached_impact_h"].to_numpy("float32")
        self.ttn_valid = (np.isfinite(ttn) & (self.y_next >= 0)).astype("float32")
        self.ttc_valid = np.isfinite(ttc).astype("float32")
        if log_time:
            ttn = np.log1p(np.clip(ttn, 0, None))
            ttc = np.log1p(np.clip(ttc, 0, None))
        self.y_ttn = np.nan_to_num(ttn).astype("float32")
        self.y_ttc = np.nan_to_num(ttc).astype("float32")

        # episode start row for each row (df is episode-sorted)
        bounds = np.r_[0, np.where(np.diff(self.ep) != 0)[0] + 1, len(df)]
        ep_start = np.empty(len(df), "int64")
        for a, b in zip(bounds[:-1], bounds[1:]):
            ep_start[a:b] = a
        self.ep_start = ep_start

        ctx = np.arange(len(df)) - ep_start
        self.samples = np.where((self.y_next >= 0) & (ctx >= min_context - 1))[0].astype("int64")
        if max_samples and len(self.samples) > max_samples:
            rng = np.random.default_rng(SEED)
            self.samples = np.sort(rng.choice(self.samples, int(max_samples), replace=False))

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, i: int) -> dict:
        row = int(self.samples[i])
        s = max(int(self.ep_start[row]), row - self.seq_len + 1)
        L = row + 1 - s
        x = np.zeros((self.seq_len, self.X.shape[1]), "float32")
        e = np.zeros((self.seq_len, self.E.shape[1]), "int64")
        m = np.zeros(self.seq_len, "float32")
        x[-L:], e[-L:], m[-L:] = self.X[s:row + 1], self.E[s:row + 1], 1.0
        return {
            "x": torch.from_numpy(x),
            "emb": torch.from_numpy(e),
            "mask": torch.from_numpy(m),
            "y_next": torch.tensor(int(self.y_next[row]), dtype=torch.long),
            "y_ttn": torch.tensor(self.y_ttn[row]),
            "y_ttn_valid": torch.tensor(self.ttn_valid[row]),
            "y_ttc": torch.tensor(self.y_ttc[row]),
            "y_ttc_valid": torch.tensor(self.ttc_valid[row]),
            "y_esc": torch.tensor(self.y_esc[row]),
        }

    def sample_meta(self) -> dict:
        """Per-sample ids aligned with iteration order (loader must be shuffle=False)."""
        s = self.samples
        return {"episode_id": self.ep[s], "seq_idx": self.seq_idx[s],
                "ts": self.ts[s], "tactic_id": self.cur_tactic[s],
                "y_next": self.y_next[s]}

    def class_weights(self) -> torch.Tensor:
        cnt = np.bincount(self.y_next[self.samples], minlength=self.n_tactics).astype("float64")
        w = cnt.sum() / (self.n_tactics * np.clip(cnt, 1, None))
        return torch.tensor(w, dtype=torch.float32)

    def sample_weights(self, mult: dict[int, float]) -> np.ndarray:
        """Per-sample weights for WeightedRandomSampler (A4 oversampling).

        `mult` maps next-tactic id -> multiplier; unlisted classes get 1.0.
        """
        yn = self.y_next[self.samples]
        w = np.ones(len(yn), dtype="float64")
        for cid, m in mult.items():
            w[yn == cid] = float(m)
        return w

    def tactic_counts(self) -> dict:
        c = np.bincount(self.y_next[self.samples], minlength=self.n_tactics)
        return {self.tactics[i]: int(c[i]) for i in range(self.n_tactics)}


def make_loaders(artifact_dir=ARTIFACT_DIR, batch_size=256, seq_len=SEQ_LEN,
                 splits=("train", "val", "test"), num_workers=0,
                 zero_substr=None, keep_substr=None, rank_norm=False):
    man = load_manifest(artifact_dir)
    loaders, datasets = {}, {}
    for sp in splits:
        ds = ForecastWindows(artifact_dir, split=sp, seq_len=seq_len, manifest=man,
                             zero_substr=zero_substr, keep_substr=keep_substr,
                             rank_norm=rank_norm)
        datasets[sp] = ds
        loaders[sp] = DataLoader(
            ds, batch_size=batch_size, shuffle=(sp == "train"),
            num_workers=num_workers, drop_last=(sp == "train"),
            pin_memory=torch.cuda.is_available())
    info = {
        "n_num_features": len(datasets[splits[0]].num_cols),
        "n_emb": len(man["embedding_columns"]),
        "n_tactics": len(man["tactics"]),
        "tactics": man["tactics"],
        "seq_len": seq_len,
    }
    return loaders, datasets, info


if __name__ == "__main__":                      # smoke test
    import time
    t0 = time.time()
    loaders, ds, info = make_loaders(batch_size=128, splits=("train", "val", "test"))
    print("info:", info)
    for sp, d in ds.items():
        print(f"{sp:6s} windows={len(d):>9,}  next-tactic={d.tactic_counts()}")
    print("class_weights(train):", ds["train"].class_weights().round(decimals=3).tolist())
    b = next(iter(loaders["train"]))
    print("batch shapes:", {k: tuple(v.shape) for k, v in b.items()})
    print(f"x dtype {b['x'].dtype}  emb dtype {b['emb'].dtype}  "
          f"mask mean {b['mask'].mean():.3f}")
    n = 0
    for b in loaders["val"]:
        n += b["x"].shape[0]
    print(f"iterated val: {n:,} rows  ({time.time()-t0:.1f}s total)")
