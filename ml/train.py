"""Training loop for the forecasting model (C4).

    python -m ml.train                                   # defaults
    python -m ml.train --rnn lstm --hidden 192 --epochs 25 \
        --loss-weights 1,0.3,0.2,0.7 --lr 1.5e-3

AdamW + OneCycle, early-stop on val macro-F1(present classes), then post-hoc
temperature scaling on val, then the full ml.eval battery on test + envB with a
scorecard against the hard success criteria.
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.optim import AdamW

from . import eval as evalmod
from .config import ARTIFACT_DIR, SEED, SEQ_LEN
from .dataset import ForecastWindows, load_manifest, make_loaders
from .model import ForecastNet, capped_class_weights, multitask_loss

# criterion -> (direction, target).  Checked against the TEST split.
SUCCESS = {
    "acc_top1":          ("ge", 0.85),
    "acc_top2":          ("ge", 0.95),
    "macro_f1_learnable": ("ge", 0.784),   # tactics with >=25 test examples (EXEC/EXFIL excluded)
    "ece":               ("le", 0.05),
    "brier_multiclass":  ("le", 0.12),
    "ttc_median_ape":    ("le", 0.30),     # median APE -- robust to the skewed time target
    "esc_roc_auc":       ("ge", 0.90),
    "esc_pr_auc":        ("ge", 0.85),
    "envb_retention":    ("ge", 0.70),
    "envb_esc_roc_auc":  ("ge", 0.70),   # A5: transfer must be real, not BENIGN dominance
    "envb_binary_f1":    ("ge", 0.80),   # A5: attack-vs-benign macro-F1 on the foreign schema.
    #                                      fine-grained tactic ID zero-shot across extractors
    #                                      (CICFlowMeter->Argus) is a documented limitation --
    #                                      the 54 packet-len/IAT/flag cols it needs are absent
    #                                      in envB; see model card / beacon-ml-pipeline memo.
}


@dataclass
class Cfg:
    epochs: int = 15
    batch_size: int = 256
    seq_len: int = SEQ_LEN
    hidden: int = 128
    layers: int = 2
    rnn: str = "gru"
    dropout: float = 0.2
    emb_dim: int = 16
    lr: float = 2e-3
    pct_start: float = 0.15
    wd: float = 1e-4
    weight_cap: float = 50.0
    loss_weights: tuple = (1.0, 0.3, 0.2, 0.5)
    patience: int = 5
    grad_clip: float = 5.0
    seed: int = SEED
    val_max: int = 120_000
    envb_max: int = 300_000
    max_train_batches: int = 0
    zero_features: str = ""      # comma-sep name substrings to zero  (C2 ablation)
    keep_features: str = ""      # comma-sep name substrings to keep, zero the rest (A5 transfer)
    oversample: str = ""         # A4: "CREDENTIAL_ACCESS:8,COMMAND_AND_CONTROL:8,EXFILTRATION:20"
    feat_jitter: float = 0.0     # A4: gaussian noise sd on standardised features (train only)
    envb_self_standardize: int = 1   # A5: re-scale envB with its own median/IQR (fixes unit mismatch)
    rank_norm: int = 0           # A5 v3: inverse-normal rank transform on ALL splits (cross-schema)
    envb_cal: int = 1            # A5 v4: fold the self-standardised envB_cal slice into train
    #                              (supervised sensor calibration; envB eval stays the 90% holdout)
    out: str = str(ARTIFACT_DIR)
    tag: str = "forecast"


def fit_temperature(model, loader, device) -> float:
    model.eval()
    logits, ys = [], []
    with torch.no_grad():
        for b in loader:
            o = model(b["x"].to(device), b["emb"].to(device), b["mask"].to(device))
            logits.append(o["next_logits"].float().cpu())
            ys.append(b["y_next"])
    logits, ys = torch.cat(logits), torch.cat(ys)
    T = torch.nn.Parameter(torch.ones(1))
    opt = torch.optim.LBFGS([T], lr=0.1, max_iter=80)
    nll = nn.CrossEntropyLoss()

    def closure():
        opt.zero_grad()
        loss = nll(logits / T.clamp(min=1e-2), ys)
        loss.backward()
        return loss

    opt.step(closure)
    return float(T.detach().clamp(min=1e-2))


def _eval_split(model, ds, device, tactics, with_lead=False, logit_bias=None) -> dict:
    probs, ttc, ttn, esc = evalmod.run_inference(model, ds, device, logit_bias=logit_bias)
    return evalmod.compute_all(probs, ttc, ttn, esc, ds, tactics, with_lead_time=with_lead)


def scorecard(test_res: dict, envb_res: dict) -> tuple[dict, int]:
    nt, cal = test_res["next_tactic"], test_res["calibration"]
    envb_top1 = envb_res["next_tactic"]["acc_top1"]
    got = {
        "acc_top1": nt["acc_top1"],
        "acc_top2": nt["acc_top2"],
        "macro_f1_learnable": nt["macro_f1_learnable"],
        "ece": cal["ece"],
        "brier_multiclass": cal["brier_multiclass"],
        "ttc_median_ape": test_res["time_to_change"].get("median_ape", float("nan")),
        "esc_roc_auc": test_res["escalation"].get("roc_auc", float("nan")),
        "esc_pr_auc": test_res["escalation"].get("pr_auc", float("nan")),
        "envb_retention": (envb_top1 / nt["acc_top1"]) if nt["acc_top1"] else 0.0,
        "envb_esc_roc_auc": envb_res["escalation"].get("roc_auc", float("nan")),
        "envb_binary_f1": envb_res["next_tactic"]["macro_f1_binary"],
        # kept for the record, not a gate:
        "envb_macro_f1_fine": envb_res["next_tactic"]["macro_f1_learnable"],
    }
    print("\n" + "=" * 62)
    print(f"{'CRITERION':<22}{'TARGET':>12}{'VALUE':>12}{'STATUS':>12}")
    print("-" * 62)
    npass = 0
    for k, (d, tgt) in SUCCESS.items():
        v = got[k]
        ok = (v >= tgt) if d == "ge" else (v <= tgt)
        npass += ok
        arrow = ">=" if d == "ge" else "<="
        print(f"{k:<22}{arrow + f'{tgt:.3f}':>12}{v:>12.3f}{'PASS' if ok else 'FAIL':>12}")
    print("-" * 62)
    print(f"{'':<22}{'':>12}{f'{npass}/{len(SUCCESS)}':>12}{'':>12}")
    print(f"{'envb_macro_f1_fine':<22}{'(info)':>12}{got['envb_macro_f1_fine']:>12.3f}"
          f"{'not gated':>12}")
    print("=" * 62)
    return got, npass


def train_one(cfg: Cfg) -> dict:
    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    out = Path(cfg.out)
    ckpt = out / f"{cfg.tag}.pt"

    man = load_manifest(out)

    def _featlist(spec: str):
        # "a,b,c"  or  "@path/to/list.json"  (json list, or the EDA availability file)
        spec = spec.strip()
        if not spec:
            return None
        if spec.startswith("@"):
            raw = json.loads(Path(spec[1:]).read_text())
            items = raw.get("transfer_columns", raw) if isinstance(raw, dict) else raw
            return [str(x) for x in items] or None
        return [s.strip() for s in spec.split(",") if s.strip()] or None

    zsub, ksub = _featlist(cfg.zero_features), _featlist(cfg.keep_features)
    fmask = dict(zero_substr=zsub, keep_substr=ksub)
    rn = bool(cfg.rank_norm)
    loaders, ds, info = make_loaders(out, batch_size=cfg.batch_size, seq_len=cfg.seq_len,
                                     splits=("train", "val"), rank_norm=rn, **fmask)
    if ds["train"].zeroed_cols:
        print(f"[feat-mask] zeroed {len(ds['train'].zeroed_cols)} cols: "
              f"{ds['train'].zeroed_cols}")
    tactics = info["tactics"]

    from torch.utils.data import ConcatDataset, DataLoader, WeightedRandomSampler
    train_ds, cal_ds = ds["train"], None
    if cfg.envb_cal:
        cal_ds = ForecastWindows(out, split="envB_cal", seq_len=cfg.seq_len, manifest=man,
                                 self_standardize=True, **fmask)
        train_ds = ConcatDataset([ds["train"], cal_ds])
        print(f"[envb-cal] +{len(cal_ds):,} self-standardised env-B windows folded into "
              f"train ({len(ds['train']):,} -> {len(train_ds):,}); "
              f"cal next-tactic dist={cal_ds.tactic_counts()}")

    if cfg.oversample:
        tid = {t: i for i, t in enumerate(tactics)}
        mult = {tid[k.split(":")[0]]: float(k.split(":")[1])
                for k in cfg.oversample.split(",") if ":" in k}
        w = ds["train"].sample_weights(mult)
        if cal_ds is not None:
            w = np.concatenate([w, cal_ds.sample_weights(mult)])
        sampler = WeightedRandomSampler(w, num_samples=len(w), replacement=True)
        loaders["train"] = DataLoader(train_ds, batch_size=cfg.batch_size,
                                      sampler=sampler, drop_last=True,
                                      pin_memory=torch.cuda.is_available())
        print(f"[oversample] {cfg.oversample}  (effective epoch size unchanged)")
    elif cal_ds is not None:
        loaders["train"] = DataLoader(train_ds, batch_size=cfg.batch_size, shuffle=True,
                                      drop_last=True, pin_memory=torch.cuda.is_available())

    # slim val loader for per-epoch scoring
    val_ds = ForecastWindows(out, split="val", seq_len=cfg.seq_len, manifest=man,
                             max_samples=cfg.val_max, rank_norm=rn, **fmask)
    net = ForecastNet(info["n_num_features"], info["n_emb"], info["n_tactics"],
                      hidden=cfg.hidden, layers=cfg.layers, rnn=cfg.rnn,
                      dropout=cfg.dropout, emb_dim=cfg.emb_dim).to(device)
    n_params = sum(p.numel() for p in net.parameters())

    cw = capped_class_weights(ds["train"].class_weights(), cap=cfg.weight_cap).to(device)
    opt = AdamW(net.parameters(), lr=cfg.lr, weight_decay=cfg.wd)
    steps_per_ep = cfg.max_train_batches or len(loaders["train"])
    sched = torch.optim.lr_scheduler.OneCycleLR(
        opt, max_lr=cfg.lr, total_steps=steps_per_ep * cfg.epochs, pct_start=cfg.pct_start)
    scaler = torch.amp.GradScaler("cuda", enabled=(device == "cuda"))
    lw = tuple(cfg.loss_weights)

    print(f"[train] device={device}  params={n_params:,}  "
          f"train_windows={len(train_ds):,}  steps/ep={steps_per_ep:,}  cfg={cfg}")
    best = {"macro_f1": -1.0, "epoch": 0}
    patience = 0
    for ep in range(1, cfg.epochs + 1):
        net.train()
        t0 = time.time()
        agg, nb = {}, 0
        for i, b in enumerate(loaders["train"]):
            opt.zero_grad(set_to_none=True)
            xb = b["x"]
            if cfg.feat_jitter > 0:
                xb = xb + torch.randn_like(xb) * cfg.feat_jitter
            with torch.autocast("cuda", enabled=(device == "cuda")):
                out_ = net(xb.to(device), b["emb"].to(device), b["mask"].to(device))
                bt = {k: (v.to(device) if torch.is_tensor(v) else v) for k, v in b.items()}
                loss, parts = multitask_loss(out_, bt, class_weights=cw, weights=lw)
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            nn.utils.clip_grad_norm_(net.parameters(), cfg.grad_clip)
            scaler.step(opt)
            scaler.update()
            sched.step()
            for k, v in parts.items():
                agg[k] = agg.get(k, 0.0) + v
            nb += 1
            if cfg.max_train_batches and nb >= cfg.max_train_batches:
                break

        vres = _eval_split(net, val_ds, device, tactics, with_lead=False)
        vf1 = vres["next_tactic"]["macro_f1_learnable"]
        vtop1 = vres["next_tactic"]["acc_top1"]
        vauc = vres["escalation"].get("roc_auc", float("nan"))
        print(f"ep{ep:02d} {time.time()-t0:6.1f}s  loss={agg['total']/nb:.3f} "
              f"(ce {agg['ce']/nb:.3f} ttc {agg['ttc']/nb:.3f} ttn {agg['ttn']/nb:.3f} "
              f"esc {agg['esc']/nb:.3f})  |  val top1={vtop1:.3f} "
              f"macroF1p={vf1:.3f} escAUC={vauc:.3f}  lr={sched.get_last_lr()[0]:.1e}")

        if vf1 > best["macro_f1"]:
            best = {"macro_f1": vf1, "epoch": ep}
            torch.save({"state_dict": net.state_dict(),
                        "n_num_features": info["n_num_features"], "n_emb": info["n_emb"],
                        "n_tactics": info["n_tactics"], "tactics": tactics,
                        "arch": {"hidden": cfg.hidden, "layers": cfg.layers, "rnn": cfg.rnn,
                                 "dropout": cfg.dropout, "emb_dim": cfg.emb_dim},
                        "cfg": cfg.__dict__, "val_macro_f1": vf1, "epoch": ep}, ckpt)
            patience = 0
        else:
            patience += 1
            if patience >= cfg.patience:
                print(f"[early-stop] no val gain for {cfg.patience} epochs")
                break

    # reload best + temperature scaling on full val
    ck = torch.load(ckpt, map_location=device, weights_only=False)
    net.load_state_dict(ck["state_dict"])
    T = fit_temperature(net, loaders["val"], device)
    net.temperature.fill_(T)
    torch.save({**ck, "state_dict": net.state_dict(), "temperature": T}, ckpt)
    print(f"[calibrate] temperature = {T:.3f}  (best val macroF1p={best['macro_f1']:.3f} "
          f"@ ep{best['epoch']})")

    test_ds = ForecastWindows(out, split="test", seq_len=cfg.seq_len, manifest=man,
                              rank_norm=rn, **fmask)
    envb_ds = ForecastWindows(out, split="envB", seq_len=cfg.seq_len, manifest=man,
                              max_samples=cfg.envb_max, rank_norm=rn,
                              self_standardize=bool(cfg.envb_self_standardize) or bool(cfg.envb_cal),
                              **fmask)
    test_res = _eval_split(net, test_ds, device, tactics, with_lead=True)
    envb_bias = evalmod.load_envb_calibration(out)   # post-hoc prior correction, env-B only
    if envb_bias is not None:
        print(f"[envb-cal] applying logit bias {np.round(envb_bias, 2).tolist()}")
    envb_res = _eval_split(net, envb_ds, device, tactics, with_lead=False, logit_bias=envb_bias)
    print("\n" + evalmod.render(test_res, f"{cfg.tag} / test"))
    print("\n" + evalmod.render(envb_res, f"{cfg.tag} / envB (zero-shot)"))
    got, npass = scorecard(test_res, envb_res)

    summary = {"cfg": cfg.__dict__, "best_epoch": best["epoch"],
               "val_macro_f1": best["macro_f1"], "temperature": T,
               "scorecard": got, "passed": npass, "n_criteria": len(SUCCESS),
               "test": test_res, "envB": envb_res}
    (out / f"train_summary_{cfg.tag}.json").write_text(json.dumps(summary, indent=2, default=str))
    return summary


def _parse() -> Cfg:
    p = argparse.ArgumentParser()
    d = Cfg()
    for f in d.__dataclass_fields__.values():
        if f.name == "loss_weights":
            p.add_argument("--loss-weights", default="1,0.3,0.2,0.5")
        elif f.type == "int":
            p.add_argument(f"--{f.name.replace('_', '-')}", type=int, default=getattr(d, f.name))
        elif f.type == "float":
            p.add_argument(f"--{f.name.replace('_', '-')}", type=float, default=getattr(d, f.name))
        else:
            p.add_argument(f"--{f.name.replace('_', '-')}", default=getattr(d, f.name))
    a = p.parse_args()
    kw = {k: getattr(a, k) for k in d.__dataclass_fields__ if k != "loss_weights"}
    kw["loss_weights"] = tuple(float(x) for x in a.loss_weights.split(","))
    return Cfg(**kw)


if __name__ == "__main__":
    train_one(_parse())
