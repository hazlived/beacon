"""Evaluation harness for the forecasting model.

Model-agnostic metric functions take plain arrays, so the same code scores the
trained net, the Markov baseline, and (later) the ablations.

    python -m ml.eval --from-markov              # self-test: score baselines
    python -m ml.eval --ckpt ml/artifacts/forecast.pt --split test [--plots]

Reports: next-tactic (top-1/2, macro-F1, per-class P/R/F1, confusion),
calibration (ECE, multiclass Brier, reliability bins), timing (MAE/RMSE/MAPE
in seconds), escalation (ROC-AUC, PR-AUC, recall@FPR<=0.15, Brier), and
episode-level lead time (how early the correct next stage first fires).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support, roc_auc_score)

from .config import ARTIFACT_DIR


# --------------------------------------------------------------------------- --
# metric primitives
# --------------------------------------------------------------------------- --
def next_tactic_metrics(probs: np.ndarray, y: np.ndarray, tactics: list[str],
                        min_support: int = 100) -> dict:
    C = len(tactics)
    top1 = probs.argmax(1)
    order = np.argsort(-probs, axis=1)
    top2 = float(((order[:, 0] == y) | (order[:, 1] == y)).mean())
    top3 = float((order[:, :3] == y[:, None]).any(1).mean())
    P, R, F1, S = precision_recall_fscore_support(
        y, top1, labels=list(range(C)), zero_division=0)
    present = [c for c in range(C) if S[c] > 0]
    learnable = [c for c in range(C) if S[c] >= min_support]
    # binary attack-vs-benign collapse: does the model know the next flow is
    # part of an attack, even when it can't resolve WHICH tactic. This is the
    # honest zero-shot cross-schema transfer claim (envB / foreign extractor).
    b_idx = tactics.index("BENIGN") if "BENIGN" in tactics else 0
    yb, pb = (y != b_idx).astype(int), (top1 != b_idx).astype(int)
    macro_f1_binary = float(f1_score(yb, pb, labels=[0, 1], average="macro",
                                     zero_division=0)) if len(set(yb.tolist())) > 1 else 0.0
    return {
        "n": int(len(y)),
        "acc_top1": float((top1 == y).mean()),
        "acc_top2": top2,
        "acc_top3": top3,
        "macro_f1_binary": macro_f1_binary,
        "macro_f1": float(f1_score(y, top1, labels=list(range(C)),
                                   average="macro", zero_division=0)),
        "macro_f1_present": float(np.mean(F1[present])) if present else 0.0,
        # macro-F1 over tactics with >= min_support examples in this split
        # (excludes structural zeros: EXECUTION always, EXFILTRATION until A4)
        "macro_f1_learnable": float(np.mean(F1[learnable])) if learnable else 0.0,
        "learnable_classes": [tactics[c] for c in learnable],
        "weighted_f1": float(f1_score(y, top1, average="weighted", zero_division=0)),
        "per_class": {tactics[c]: {"precision": round(float(P[c]), 4),
                                   "recall": round(float(R[c]), 4),
                                   "f1": round(float(F1[c]), 4),
                                   "support": int(S[c])} for c in range(C)},
        "confusion": confusion_matrix(y, top1, labels=list(range(C))).tolist(),
    }


def calibration_metrics(probs: np.ndarray, y: np.ndarray, bins: int = 15) -> dict:
    conf = probs.max(1)
    pred = probs.argmax(1)
    correct = (pred == y).astype(float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    ece, mce, rel = 0.0, 0.0, []
    for i in range(bins):
        m = (conf >= edges[i]) & (conf < edges[i + 1] if i < bins - 1 else conf <= 1.0)
        if not m.any():
            continue
        gap = abs(correct[m].mean() - conf[m].mean())
        ece += m.mean() * gap
        mce = max(mce, gap)
        rel.append({"conf": float(conf[m].mean()), "acc": float(correct[m].mean()),
                    "n": int(m.sum())})
    C = probs.shape[1]
    brier = float(((probs - np.eye(C)[y]) ** 2).sum(1).mean())
    return {"ece": float(ece), "mce": float(mce), "brier_multiclass": brier,
            "reliability": rel}


def timing_metrics(pred_log: np.ndarray, tgt_log: np.ndarray, valid: np.ndarray) -> dict:
    v = valid.astype(bool)
    if v.sum() == 0:
        return {"n": 0}
    p = np.expm1(np.clip(pred_log[v], 0, 20))
    t = np.expm1(np.clip(tgt_log[v], 0, 20))
    ae = np.abs(p - t)
    ape = ae / np.clip(np.abs(t), 1.0, None)      # floor 1 s -> avoid /0 blow-up
    return {"n": int(v.sum()),
            "mae_s": float(ae.mean()), "rmse_s": float(np.sqrt(((p - t) ** 2).mean())),
            "mape": float(ape.mean()), "median_ape": float(np.median(ape)),
            "p50_abs_err_s": float(np.median(ae)), "p90_abs_err_s": float(np.quantile(ae, .9))}


def escalation_metrics(score: np.ndarray, y: np.ndarray, max_fpr: float = 0.15) -> dict:
    y = y.astype(int)
    if y.min() == y.max():
        return {"n": int(len(y)), "note": "single-class", "positive_rate": float(y.mean())}
    auc = float(roc_auc_score(y, score))
    ap = float(average_precision_score(y, score))
    order = np.argsort(-score)
    ys = y[order]
    tp = np.cumsum(ys); fp = np.cumsum(1 - ys)
    P, Nn = ys.sum(), (1 - ys).sum()
    recall = tp / max(P, 1); fpr = fp / max(Nn, 1)
    ok = np.where(fpr <= max_fpr)[0]
    rec_at = float(recall[ok[-1]]) if len(ok) else 0.0
    f1s = 2 * tp / (2 * tp + fp + (P - tp) + 1e-9)
    return {"n": int(len(y)), "positive_rate": float(y.mean()),
            "roc_auc": auc, "pr_auc": ap,
            f"recall_at_fpr_{max_fpr}": rec_at,
            "best_f1": float(f1s.max()),
            "brier": float(((score - y) ** 2).mean())}


def lead_time_metrics(meta: pd.DataFrame) -> dict:
    """meta columns: episode_id, seq_idx, ts, tactic_id, y_next, pred_next.

    For every stage *transition* in an episode (row j where tactic_id[j] !=
    tactic_id[j-1]), find the earliest row i < j in the same stage-run ending at
    j-1 where pred_next[i] == tactic_id[j]. Lead = ts[j]-ts[i] and (j-i) events.
    """
    leads_s, leads_e, hit, total = [], [], 0, 0
    for _, ep in meta.groupby("episode_id", sort=False):
        ep = ep.sort_values("seq_idx")
        tac = ep["tactic_id"].to_numpy()
        ts = ep["ts"].to_numpy()
        pred = ep["pred_next"].to_numpy()
        change = np.where(np.diff(tac) != 0)[0] + 1        # indices j where tactic changes
        run_start = 0
        for j in change:
            total += 1
            target = tac[j]
            window = range(run_start, j)                    # the run just before the change
            first = next((i for i in window if pred[i] == target), None)
            if first is not None:
                hit += 1
                leads_s.append(float(ts[j] - ts[first]))
                leads_e.append(int(j - first))
            run_start = j
    if not total:
        return {"transitions": 0}
    ls = np.array(leads_s) if leads_s else np.array([0.0])
    le = np.array(leads_e) if leads_e else np.array([0])
    return {
        "transitions": int(total),
        "anticipated_frac": round(hit / total, 4),
        "lead_seconds_mean": float(ls.mean()), "lead_seconds_median": float(np.median(ls)),
        "lead_seconds_p90": float(np.quantile(ls, .9)),
        "lead_events_mean": float(le.mean()), "lead_events_median": float(np.median(le)),
        "meets_60s_bar_frac": round(float((ls >= 60).mean()), 4),
    }


# --------------------------------------------------------------------------- --
# orchestration
# --------------------------------------------------------------------------- --
def load_envb_calibration(artifact_dir=ARTIFACT_DIR):
    """Return the env-B post-hoc logit-bias vector (np.ndarray) or None.

    Written by ml/calibrate_envb.py. Applied to next_logits (post-temperature,
    pre-softmax) for env-B / foreign-sensor inference ONLY -- never in-domain.
    """
    p = Path(artifact_dir) / "envb_calibration.json"
    if not p.exists():
        return None
    return np.asarray(json.loads(p.read_text())["logit_bias"], dtype="float32")


def run_inference(model, dataset, device="cpu", batch_size=512, logit_bias=None):
    import torch
    from torch.utils.data import DataLoader
    model.eval().to(device)
    dl = DataLoader(dataset, batch_size=batch_size, shuffle=False)
    bias = None if logit_bias is None else torch.as_tensor(
        logit_bias, dtype=torch.float32, device=device)
    P, TTC, TTN, ESC = [], [], [], []
    with torch.no_grad():
        for b in dl:
            out = model(b["x"].to(device), b["emb"].to(device), b["mask"].to(device),
                        calibrated=True)
            nl = out["next_logits"] if bias is None else out["next_logits"] + bias
            P.append(torch.softmax(nl, -1).cpu().numpy())
            TTC.append(out["ttc"].cpu().numpy())
            TTN.append(out["ttn"].cpu().numpy())
            ESC.append(torch.sigmoid(out["esc_logit"]).cpu().numpy())
    return (np.concatenate(P), np.concatenate(TTC), np.concatenate(TTN),
            np.concatenate(ESC))


def compute_all(probs, ttc_log, ttn_log, esc_score, dataset, tactics,
                with_lead_time: bool = True) -> dict:
    m = dataset.sample_meta()
    y = m["y_next"]
    # regression targets live on the dataset in log space already
    y_ttc = dataset.y_ttc[dataset.samples]; v_ttc = dataset.ttc_valid[dataset.samples]
    y_ttn = dataset.y_ttn[dataset.samples]; v_ttn = dataset.ttn_valid[dataset.samples]
    y_esc = dataset.y_esc[dataset.samples]
    res = {
        "next_tactic": next_tactic_metrics(probs, y, tactics),
        "calibration": calibration_metrics(probs, y),
        "time_to_change": timing_metrics(ttc_log, y_ttc, v_ttc),
        "time_to_next": timing_metrics(ttn_log, y_ttn, v_ttn),
        "escalation": escalation_metrics(esc_score, y_esc),
        "lead_time": {"transitions": 0},
    }
    if with_lead_time:
        meta = pd.DataFrame({"episode_id": m["episode_id"], "seq_idx": m["seq_idx"],
                             "ts": m["ts"], "tactic_id": m["tactic_id"], "y_next": y,
                             "pred_next": probs.argmax(1)})
        res["lead_time"] = lead_time_metrics(meta)
    return res


def render(res: dict, title: str = "") -> str:
    nt, cal = res["next_tactic"], res["calibration"]
    lines = [f"== {title} ==" if title else "==",
             f"next-tactic   n={nt['n']:>8,}  top1={nt['acc_top1']:.3f}  "
             f"top2={nt['acc_top2']:.3f}  macroF1={nt['macro_f1']:.3f}  "
             f"learnable={nt.get('macro_f1_learnable', nt['macro_f1_present']):.3f}",
             f"calibration   ECE={cal['ece']:.3f}  MCE={cal['mce']:.3f}  "
             f"Brier={cal['brier_multiclass']:.3f}"]
    tc, tn = res["time_to_change"], res["time_to_next"]
    if tc.get("n"):
        lines.append(f"time->change  n={tc['n']:>8,}  MAE={tc['mae_s']:.1f}s  "
                     f"MAPE={tc['mape']:.2f}  medAPE={tc['median_ape']:.2f}")
    if tn.get("n"):
        lines.append(f"time->next    n={tn['n']:>8,}  MAE={tn['mae_s']:.1f}s  "
                     f"MAPE={tn['mape']:.2f}")
    es = res["escalation"]
    if "roc_auc" in es:
        lines.append(f"escalation    ROC-AUC={es['roc_auc']:.3f}  PR-AUC={es['pr_auc']:.3f}  "
                     f"recall@FPR.15={es.get('recall_at_fpr_0.15', 0):.3f}  "
                     f"Brier={es['brier']:.3f}")
    lt = res["lead_time"]
    if lt.get("transitions"):
        lines.append(f"lead-time     transitions={lt['transitions']:,}  "
                     f"anticipated={lt['anticipated_frac']:.2f}  "
                     f"median={lt['lead_seconds_median']:.1f}s / "
                     f"{lt['lead_events_median']:.0f}ev  "
                     f">=60s={lt['meets_60s_bar_frac']:.2f}")
    lines.append("per-class F1: " + "  ".join(
        f"{k[:4]}={v['f1']:.2f}" for k, v in nt["per_class"].items()))
    return "\n".join(lines)


def plot_all(res: dict, tactics: list[str], outdir: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    outdir.mkdir(parents=True, exist_ok=True)

    cm = np.array(res["next_tactic"]["confusion"], float)
    cmn = cm / cm.sum(1, keepdims=True).clip(min=1)
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cmn, cmap="magma", vmin=0, vmax=1)
    ax.set_xticks(range(len(tactics))); ax.set_yticks(range(len(tactics)))
    ax.set_xticklabels([t[:5] for t in tactics], rotation=90)
    ax.set_yticklabels([t[:5] for t in tactics])
    ax.set_xlabel("predicted"); ax.set_ylabel("true"); ax.set_title("row-normalised confusion")
    fig.colorbar(im); fig.tight_layout(); fig.savefig(outdir / "confusion.png", dpi=120)
    plt.close(fig)

    rel = res["calibration"]["reliability"]
    if rel:
        fig, ax = plt.subplots(figsize=(5, 5))
        ax.plot([0, 1], [0, 1], "k--", lw=1)
        ax.plot([r["conf"] for r in rel], [r["acc"] for r in rel], "o-")
        ax.set_xlabel("confidence"); ax.set_ylabel("accuracy")
        ax.set_title(f"reliability (ECE={res['calibration']['ece']:.3f})")
        fig.tight_layout(); fig.savefig(outdir / "reliability.png", dpi=120); plt.close(fig)


# --------------------------------------------------------------------------- --
def _markov_selftest(artifact_dir: Path) -> None:
    """Score the Markov / persistence baselines through this harness."""
    from .baselines.markov import _load, _probs, fit
    from .data.schema import TACTICS
    tr = _load("train", artifact_dir)
    model = fit(tr)
    for sp in ("val", "test", "envB"):
        df = _load(sp, artifact_dir)
        if df.empty:
            continue
        y = df["next_tactic_id"].to_numpy()
        ok = y >= 0
        probs = _probs(model, df, "markov_order2")[ok]
        y = y[ok]
        meta = pd.DataFrame({
            "episode_id": df["episode_id"].to_numpy()[ok],
            "seq_idx": df["seq_idx"].to_numpy()[ok],
            "ts": np.arange(ok.sum()),                    # no ts in markov cols -> event index
            "tactic_id": np.clip(df["tactic_id"].to_numpy()[ok], 0, len(TACTICS) - 1),
            "y_next": y, "pred_next": probs.argmax(1)})
        res = {"next_tactic": next_tactic_metrics(probs, y, TACTICS),
               "calibration": calibration_metrics(probs, y),
               "time_to_change": {"n": 0}, "time_to_next": {"n": 0},
               "escalation": {"n": 0, "note": "n/a for markov"},
               "lead_time": lead_time_metrics(meta)}
        print(render(res, f"markov_order2 / {sp}"), "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-markov", action="store_true")
    ap.add_argument("--ckpt")
    ap.add_argument("--split", default="test")
    ap.add_argument("--artifact-dir", default=str(ARTIFACT_DIR))
    ap.add_argument("--plots", action="store_true")
    args = ap.parse_args()
    outdir = Path(args.artifact_dir)

    if args.from_markov or not args.ckpt:
        _markov_selftest(outdir)
        return

    import torch
    from .dataset import ForecastWindows, load_manifest
    from .model import ForecastNet
    man = load_manifest(outdir)
    ds = ForecastWindows(outdir, split=args.split, manifest=man)
    ck = torch.load(args.ckpt, map_location="cpu")
    net = ForecastNet(ck["n_num_features"], ck["n_emb"], ck["n_tactics"], **ck.get("arch", {}))
    net.load_state_dict(ck["state_dict"])
    device = "cuda" if torch.cuda.is_available() else "cpu"
    probs, ttc, ttn, esc = run_inference(net, ds, device)
    res = compute_all(probs, ttc, ttn, esc, ds, man["tactics"])
    print(render(res, f"{Path(args.ckpt).name} / {args.split}"))
    (outdir / f"eval_{args.split}.json").write_text(json.dumps(res, indent=2, default=str))
    if args.plots:
        plot_all(res, man["tactics"], outdir / f"eval_plots_{args.split}")


if __name__ == "__main__":
    main()
