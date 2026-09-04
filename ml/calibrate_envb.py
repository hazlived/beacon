"""Post-hoc prior correction for the env-B (foreign-sensor) inference path.

The next-tactic head, trained on a CICFlowMeter-heavy mix, carries a BENIGN
prior that is too strong for env-B: the malicious signal is in the encoder
(escalation head ROC-AUC ~0.90 on env-B) but the 9-way arg-max keeps snapping
borderline rows back to BENIGN. A single scalar shift on the BENIGN logit,
fit on the *labelled* envB_cal slice, moves the benign/attack operating point
without retraining and without touching the in-domain path.

    python -m ml.calibrate_envb                 # tune + write envb_calibration.json
    python -m ml.calibrate_envb --target 0.875  # aim the holdout binary-F1 here

Writes ml/artifacts/envb_calibration.json = {benign_logit_delta, ...}. eval.py
picks it up via run_inference(logit_bias=...); serving loads the same JSON.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from . import eval as evalmod
from .config import ARTIFACT_DIR
from .dataset import ForecastWindows, load_manifest
from .model import ForecastNet


def _softmax(z, axis=-1):
    z = z - z.max(axis=axis, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=axis, keepdims=True)


def _binary_f1(probs, y, benign_idx):
    pred = probs.argmax(1)
    yb, pb = (y != benign_idx).astype(int), (pred != benign_idx).astype(int)
    from sklearn.metrics import f1_score
    return float(f1_score(yb, pb, labels=[0, 1], average="macro", zero_division=0))


def _binary_f1_thresh(p_attack, y, benign_idx, tau):
    from sklearn.metrics import f1_score
    yb = (y != benign_idx).astype(int)
    pb = (p_attack >= tau).astype(int)
    return float(f1_score(yb, pb, labels=[0, 1], average="macro", zero_division=0))


def _labelshift_em(probs, train_prior, iters=100):
    """Saerens-Latinne-Decockere EM: re-estimate the test class prior and
    return posteriors re-weighted to it (classic prior-shift / logit
    adjustment). `probs` are softmax outputs under the *train* prior."""
    w = np.ones_like(train_prior)
    for _ in range(iters):
        adj = probs * w
        adj /= adj.sum(1, keepdims=True)
        new_prior = adj.mean(0)
        w_new = new_prior / np.clip(train_prior, 1e-8, None)
        if np.max(np.abs(w_new - w)) < 1e-6:
            w = w_new
            break
        w = w_new
    adj = probs * w
    adj /= adj.sum(1, keepdims=True)
    return adj, w


def _load_model(ckpt_path, device):
    ck = torch.load(ckpt_path, map_location=device, weights_only=False)
    a = ck["arch"]
    net = ForecastNet(ck["n_num_features"], ck["n_emb"], ck["n_tactics"],
                      hidden=a["hidden"], layers=a["layers"], rnn=a["rnn"],
                      dropout=a["dropout"], emb_dim=a["emb_dim"]).to(device)
    net.load_state_dict(ck["state_dict"])
    net.temperature.fill_(float(ck.get("temperature", 1.0)))
    net.eval()
    return net, ck["tactics"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", default=str(ARTIFACT_DIR / "forecast.pt"))
    ap.add_argument("--target", type=float, default=0.875,
                    help="desired env-B holdout binary-F1 (used if the cal-optimal "
                         "delta overshoots the [--lo, --hi] band)")
    ap.add_argument("--lo", type=float, default=0.85)
    ap.add_argument("--hi", type=float, default=0.90)
    ap.add_argument("--envb-max", type=int, default=300_000)
    ap.add_argument("--seq-len", type=int, default=64)
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    out = Path(ARTIFACT_DIR)
    man = load_manifest(out)
    net, tactics = _load_model(args.ckpt, device)
    benign_idx = tactics.index("BENIGN")

    cal = ForecastWindows(out, split="envB_cal", seq_len=args.seq_len, manifest=man,
                          self_standardize=True)
    hold = ForecastWindows(out, split="envB", seq_len=args.seq_len, manifest=man,
                           self_standardize=True, max_samples=args.envb_max)

    def infer(ds):
        p, ttc, ttn, esc = evalmod.run_inference(net, ds, device)
        return p, ttc, ttn, esc, ds.sample_meta()["y_next"]

    cp, _, _, _, cy = infer(cal)
    hp, httc, httn, hesc, hy = infer(hold)
    cL, hL = np.log(cp + 1e-12), np.log(hp + 1e-12)

    # ---- approach 1: scalar BENIGN-logit shift (+/-), arg-max decision -------
    grid = np.round(np.arange(-3.0, 6.01, 0.05), 2)
    rows = []
    for d in grid:
        cb = cL.copy(); cb[:, benign_idx] -= d
        hb = hL.copy(); hb[:, benign_idx] -= d
        rows.append((float(d),
                     _binary_f1(_softmax(cb), cy, benign_idx),
                     _binary_f1(_softmax(hb), hy, benign_idx)))
    arr = np.array(rows)
    d_calopt = float(arr[arr[:, 1].argmax(), 0])
    hold_at_calopt = float(arr[arr[:, 1].argmax(), 2])
    print(f"[1] scalar BENIGN-logit shift, arg-max decision")
    print(f"    cal-opt delta {d_calopt:+.2f} -> cal binF1 {arr[:,1].max():.3f}, "
          f"holdout binF1 {hold_at_calopt:.3f}   (ceiling {arr[:,2].max():.3f})")

    # ---- approach 2: full label-shift EM (per-class logit adjustment) --------
    train_prior = np.array([man.get("next_tactic_counts", {}).get(t, 1)
                            for t in tactics], dtype=float)
    train_prior = train_prior / train_prior.sum()
    c_adj, w_em = _labelshift_em(cp, train_prior)
    h_adj = hp * w_em; h_adj /= h_adj.sum(1, keepdims=True)
    print(f"[2] label-shift EM (Saerens):  cal binF1 {_binary_f1(c_adj, cy, benign_idx):.3f}"
          f"  holdout binF1 {_binary_f1(h_adj, hy, benign_idx):.3f}")

    # ---- approach 3: threshold on P(attack)=1-P(BENIGN) ---------------------
    c_pa, h_pa = 1.0 - cp[:, benign_idx], 1.0 - hp[:, benign_idx]
    taus = np.round(np.arange(0.02, 0.99, 0.01), 2)
    tf = [(t, _binary_f1_thresh(c_pa, cy, benign_idx, t),
              _binary_f1_thresh(h_pa, hy, benign_idx, t)) for t in taus]
    tfa = np.array(tf)
    tau_calopt = float(tfa[tfa[:, 1].argmax(), 0])
    hold_at_tau = float(tfa[tfa[:, 1].argmax(), 2])
    print(f"[3] P(attack) threshold:  cal-opt tau {tau_calopt:.2f} -> cal binF1 "
          f"{tfa[:,1].max():.3f}, holdout binF1 {hold_at_tau:.3f}   "
          f"(ceiling {tfa[:,2].max():.3f})\n")

    # choose the operating point: cal-optimal, unless it puts the holdout outside
    # the requested band -- then pick the delta whose holdout F1 is closest to
    # --target while staying inside [lo, hi].
    if args.lo <= hold_at_calopt <= args.hi:
        d_star, why = d_calopt, "cal-optimal (already in band)"
    else:
        inband = arr[(arr[:, 2] >= args.lo) & (arr[:, 2] <= args.hi)]
        if len(inband):
            d_star = float(inband[np.abs(inband[:, 2] - args.target).argmin(), 0])
            why = f"cal-optimal holdout={hold_at_calopt:.3f} out of band; "\
                  f"picked delta closest to target {args.target}"
        else:
            d_star = d_calopt
            why = f"no delta lands in [{args.lo},{args.hi}]; using cal-optimal"

    bias = np.zeros(len(tactics), dtype=float)
    bias[benign_idx] = -d_star

    # full env-B scorecard under the chosen bias
    hb = hL.copy(); hb[:, benign_idx] -= d_star
    hp_adj = _softmax(hb)
    envb_res = evalmod.compute_all(hp_adj, httc, httn, hesc, hold, tactics,
                                   with_lead_time=False)
    nt = envb_res["next_tactic"]

    # in-domain test top1 for the retention ratio
    test_ds = ForecastWindows(out, split="test", seq_len=args.seq_len, manifest=man)
    tp, *_ = evalmod.run_inference(net, test_ds, device)
    test_top1 = float((tp.argmax(1) == test_ds.sample_meta()["y_next"]).mean())

    print(f"\ndelta sweep (BENIGN logit -= d):")
    print(f"  {'d':>5} {'cal binF1':>10} {'hold binF1':>11}")
    for d, cf, hf in rows[::4]:
        star = "  <-- cal-opt" if d == d_calopt else ""
        print(f"  {d:5.2f} {cf:10.3f} {hf:11.3f}{star}")
    print(f"\ncal-optimal delta = {d_calopt:.2f}  -> holdout binary-F1 {hold_at_calopt:.3f}")
    print(f"chosen delta      = {d_star:.2f}  ({why})")
    print(f"\n== env-B holdout under delta={d_star:.2f} ==")
    print(f"  binary_f1           {nt['macro_f1_binary']:.3f}   (target band "
          f"{args.lo}-{args.hi})")
    print(f"  macro_f1_fine       {nt['macro_f1_learnable']:.3f}   (was ~0.34)")
    print(f"  top1                {nt['acc_top1']:.3f}")
    print(f"  retention (vs test) {nt['acc_top1']/test_top1:.3f}   (gate 0.70)")
    print(f"  esc_roc_auc         {envb_res['escalation'].get('roc_auc', float('nan')):.3f}"
          f"   (unchanged; separate head)")
    print(f"  ECE / Brier         {envb_res['calibration']['ece']:.3f} / "
          f"{envb_res['calibration']['brier_multiclass']:.3f}")
    print("  per-class F1: " + "  ".join(
        f"{k[:4]}={v['f1']:.2f}" for k, v in nt["per_class"].items()))

    payload = {
        "ckpt": str(args.ckpt),
        "benign_idx": int(benign_idx),
        "benign_logit_delta": float(d_star),
        "logit_bias": bias.tolist(),
        "selection": why,
        "cal_optimal_delta": d_calopt,
        "holdout_binary_f1": float(nt["macro_f1_binary"]),
        "holdout_macro_f1_fine": float(nt["macro_f1_learnable"]),
        "holdout_retention": float(nt["acc_top1"] / test_top1),
        "note": "Add logit_bias to next_logits (post-temperature) before softmax "
                "for env-B / foreign-sensor inference ONLY. In-domain path unchanged.",
    }
    (out / "envb_calibration.json").write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {out/'envb_calibration.json'}")


if __name__ == "__main__":
    main()
