"""Markov-chain next-tactic baselines.

The main model must beat markov_order2 by >= 15 macro-F1 points (success bar).
Also reports two floor baselines:
    persistence -- predict next tactic == current tactic
    marginal    -- always predict the most frequent next tactic (train prior)

Run:  python -m ml.baselines.markov
Out:  ml/artifacts/baseline_markov.json  + a printed table
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from ..config import ARTIFACT_DIR
from ..data.schema import TACTICS

N = len(TACTICS)
_COLS = ["episode_id", "seq_idx", "tactic_id", "prev_tactic_id", "next_tactic_id"]


def _load(split: str, artifact_dir=ARTIFACT_DIR) -> pd.DataFrame:
    df = pd.read_parquet(Path(artifact_dir) / "events.parquet",
                         columns=_COLS + ["split"],
                         filters=[("split", "==", split)])
    return df.sort_values(["episode_id", "seq_idx"]).reset_index(drop=True)


def fit(train: pd.DataFrame, alpha: float = 1.0) -> dict:
    cur = train["tactic_id"].to_numpy()
    prv = np.clip(train["prev_tactic_id"].to_numpy(), 0, N - 1)
    nxt = train["next_tactic_id"].to_numpy()
    ok = nxt >= 0
    m1 = np.full((N, N), alpha)
    m2 = np.full((N, N, N), alpha)
    np.add.at(m1, (cur[ok], nxt[ok]), 1.0)
    np.add.at(m2, (prv[ok], cur[ok], nxt[ok]), 1.0)
    marg = np.bincount(nxt[ok], minlength=N).astype("float64")
    return {
        "P1": m1 / m1.sum(1, keepdims=True),
        "P2": m2 / m2.sum(2, keepdims=True),
        "marg": marg / marg.sum(),
    }


def _probs(model: dict, df: pd.DataFrame, kind: str) -> np.ndarray:
    cur = np.clip(df["tactic_id"].to_numpy(), 0, N - 1)
    prv = np.clip(df["prev_tactic_id"].to_numpy(), 0, N - 1)
    if kind == "markov_order2":
        return model["P2"][prv, cur]
    if kind == "markov_order1":
        return model["P1"][cur]
    if kind == "persistence":
        return np.eye(N, dtype="float32")[cur]
    if kind == "marginal":
        return np.tile(model["marg"], (len(df), 1))
    raise ValueError(kind)


def _metrics(probs: np.ndarray, y: np.ndarray) -> dict:
    ok = y >= 0
    probs, y = probs[ok], y[ok]
    top1 = probs.argmax(1)
    order = np.argsort(-probs, axis=1)
    top2_hit = ((order[:, 0] == y) | (order[:, 1] == y)).mean()
    f1 = np.zeros(N)
    for c in range(N):
        tp = int(((top1 == c) & (y == c)).sum())
        fp = int(((top1 == c) & (y != c)).sum())
        fn = int(((top1 != c) & (y == c)).sum())
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1[c] = 2 * p * r / (p + r) if p + r else 0.0
    present = [c for c in range(N) if (y == c).any()]
    return {
        "n": int(len(y)),
        "acc_top1": round(float((top1 == y).mean()), 4),
        "acc_top2": round(float(top2_hit), 4),
        "macro_f1": round(float(f1.mean()), 4),
        "macro_f1_present": round(float(f1[present].mean()), 4),
        "per_class_f1": {TACTICS[c]: round(float(f1[c]), 4) for c in range(N)},
        "support": {TACTICS[c]: int((y == c).sum()) for c in range(N)},
    }


def main() -> None:
    t0 = time.time()
    train = _load("train")
    model = fit(train)
    kinds = ["markov_order2", "markov_order1", "persistence", "marginal"]
    results = {}
    for sp in ["train", "val", "test", "envB"]:
        df = _load(sp)
        if df.empty:
            continue
        y = df["next_tactic_id"].to_numpy()
        results[sp] = {k: _metrics(_probs(model, df, k), y) for k in kinds}

    out = Path(ARTIFACT_DIR) / "baseline_markov.json"
    out.write_text(json.dumps({
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "tactics": TACTICS,
        "transition_matrix_order1": model["P1"].round(4).tolist(),
        "results": results,
    }, indent=2))

    print(f"\nMarkov baselines  ({time.time()-t0:.1f}s)   -> {out}\n")
    hdr = f"{'split':6s} {'model':14s} {'top1':>7s} {'top2':>7s} {'macroF1':>8s} {'F1(present)':>11s}"
    print(hdr); print("-" * len(hdr))
    for sp, d in results.items():
        for k in kinds:
            m = d[k]
            print(f"{sp:6s} {k:14s} {m['acc_top1']:>7.3f} {m['acc_top2']:>7.3f} "
                  f"{m['macro_f1']:>8.3f} {m['macro_f1_present']:>11.3f}")
        print()
    test = results.get("test", {})
    if test:
        strongest = max(test[k]["macro_f1"] for k in kinds)
        who = max(kinds, key=lambda k: test[k]["macro_f1"])
        print(f"BAR: strongest non-learned baseline on test = macro-F1 {strongest:.3f} ({who})")
        print(f"     main model target: >= {strongest + 0.15:.3f} (relative) and >= 0.80 (absolute)")
        print("per-class F1 (test, markov_order2):", test["markov_order2"]["per_class_f1"])


if __name__ == "__main__":
    main()
