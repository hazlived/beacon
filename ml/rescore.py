"""Re-run the ml.eval battery + scorecard on an existing checkpoint.

Rebuilds test + env-B exactly as ml.train does (reading the cfg baked into the
checkpoint), applies the env-B post-hoc calibration if ml/artifacts/
envb_calibration.json exists, and rewrites train_summary_<tag>.json.

    python -m ml.rescore --ckpt ml/artifacts/forecast.pt --tag forecast
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from . import eval as evalmod
from .config import ARTIFACT_DIR
from .dataset import ForecastWindows, load_manifest
from .model import ForecastNet
from .train import SUCCESS, scorecard


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", default=str(ARTIFACT_DIR / "forecast.pt"))
    ap.add_argument("--tag", default="forecast")
    ap.add_argument("--out", default=str(ARTIFACT_DIR))
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    out = Path(args.out)
    man = load_manifest(out)
    ck = torch.load(args.ckpt, map_location=device, weights_only=False)
    cfg = ck.get("cfg", {})
    seq_len = cfg.get("seq_len", 64)
    a = ck["arch"]
    net = ForecastNet(ck["n_num_features"], ck["n_emb"], ck["n_tactics"],
                      hidden=a["hidden"], layers=a["layers"], rnn=a["rnn"],
                      dropout=a["dropout"], emb_dim=a["emb_dim"]).to(device)
    net.load_state_dict(ck["state_dict"])
    net.temperature.fill_(float(ck.get("temperature", 1.0)))
    net.eval()
    tactics = ck["tactics"]

    self_std = bool(cfg.get("envb_self_standardize", 1)) or bool(cfg.get("envb_cal", 0))
    test_ds = ForecastWindows(out, split="test", seq_len=seq_len, manifest=man)
    envb_ds = ForecastWindows(out, split="envB", seq_len=seq_len, manifest=man,
                              max_samples=cfg.get("envb_max", 300_000),
                              self_standardize=self_std,
                              rank_norm=bool(cfg.get("rank_norm", 0)))

    envb_bias = evalmod.load_envb_calibration(out)
    if envb_bias is not None:
        print(f"[envb-cal] applying logit bias {[round(x, 2) for x in envb_bias.tolist()]}")

    test_res = evalmod.compute_all(*evalmod.run_inference(net, test_ds, device),
                                   test_ds, tactics, with_lead_time=True)
    envb_res = evalmod.compute_all(*evalmod.run_inference(net, envb_ds, device,
                                                          logit_bias=envb_bias),
                                   envb_ds, tactics, with_lead_time=False)
    print("\n" + evalmod.render(test_res, f"{args.tag} / test"))
    print("\n" + evalmod.render(envb_res, f"{args.tag} / envB"))
    got, npass = scorecard(test_res, envb_res)

    summ_path = out / f"train_summary_{args.tag}.json"
    summary = json.loads(summ_path.read_text()) if summ_path.exists() else {}
    summary.update({"cfg": cfg, "temperature": float(ck.get("temperature", 1.0)),
                    "scorecard": got, "passed": npass, "n_criteria": len(SUCCESS),
                    "envb_calibration": (None if envb_bias is None
                                         else json.loads((out / "envb_calibration.json").read_text())),
                    "test": test_res, "envB": envb_res, "rescored": True})
    summ_path.write_text(json.dumps(summary, indent=2, default=str))
    print(f"\nwrote {summ_path}")


if __name__ == "__main__":
    main()
