"""Exploratory analysis of the built artifact.

    python -m ml.eda

Writes ml/artifacts/eda/report.md + PNGs and prints a summary. Covers:
class balance (events & episodes), episode length, kill-chain depth,
tactic-transition matrix, inter-stage timing, escalation rate, per-dataset
contribution, and the env-B feature-availability surface (transfer readiness).
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from .config import ARTIFACT_DIR
from .data.schema import ID_TO_TACTIC, TACTICS

OUT = Path(ARTIFACT_DIR) / "eda"


def _fig():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    man = json.loads((Path(ARTIFACT_DIR) / "feature_manifest.json").read_text())
    ev = pd.read_parquet(Path(ARTIFACT_DIR) / "events.parquet",
                         columns=["episode_id", "seq_idx", "ts", "dataset", "domain",
                                  "split", "tactic", "tactic_id", "next_tactic_id",
                                  "time_to_next_change", "dt_prev"])
    ep = pd.read_parquet(Path(ARTIFACT_DIR) / "episodes.parquet")
    plt = _fig()
    md: list[str] = ["# BEACON forecasting - EDA", "",
                     f"- events: **{len(ev):,}**   episodes: **{len(ep):,}**",
                     f"- datasets: {sorted(ev['dataset'].unique())}",
                     f"- feature columns (model): {len(man['feature_columns'])}", ""]

    # --- class balance --------------------------------------------------- --
    ev_bal = ev["tactic"].value_counts().reindex(TACTICS, fill_value=0)
    nxt_bal = (ev.loc[ev.next_tactic_id >= 0, "next_tactic_id"]
               .map(ID_TO_TACTIC).value_counts().reindex(TACTICS, fill_value=0))
    split_tab = (ev.loc[ev.next_tactic_id >= 0]
                 .assign(t=lambda d: d.next_tactic_id.map(ID_TO_TACTIC))
                 .pivot_table(index="t", columns="split", values="tactic_id",
                              aggfunc="size", fill_value=0)
                 .reindex(TACTICS, fill_value=0))
    md += ["## Class balance (next-tactic target, by split)", "",
           split_tab.to_markdown(), "",
           f"- escalation-positive events: {(ev['tactic'].isin(['IMPACT','EXFILTRATION'])).mean():.3f}",
           f"- episodes reaching escalation: {ep['reached_impact'].mean():.3f}", ""]

    fig, ax = plt.subplots(figsize=(8, 4))
    x = np.arange(len(TACTICS))
    ax.bar(x - 0.2, ev_bal.values, 0.4, label="events (current)")
    ax.bar(x + 0.2, nxt_bal.values, 0.4, label="events (as next-target)")
    ax.set_yscale("log"); ax.set_xticks(x)
    ax.set_xticklabels([t[:6] for t in TACTICS], rotation=90)
    ax.legend(); ax.set_title("tactic frequency (log)")
    fig.tight_layout(); fig.savefig(OUT / "class_balance.png", dpi=120); plt.close(fig)

    # --- episode length + kill-chain depth ----------------------------- --
    ep_len = ev.groupby("episode_id").size()
    depth = ev.groupby("episode_id")["tactic"].nunique()
    md += ["## Episode structure", "",
           f"- length  p50={ep_len.median():.0f}  p90={ep_len.quantile(.9):.0f}  "
           f"max={ep_len.max():.0f}",
           f"- distinct tactics/episode  p50={depth.median():.0f}  "
           f"p90={depth.quantile(.9):.0f}  max={depth.max():.0f}",
           f"- multi-stage episodes (>=3 tactics): {(depth >= 3).mean():.3f}", ""]
    fig, ax = plt.subplots(1, 2, figsize=(10, 3.5))
    ax[0].hist(np.clip(ep_len, 0, 400), bins=50); ax[0].set_title("episode length (clip 400)")
    ax[1].hist(depth, bins=range(1, len(TACTICS) + 2)); ax[1].set_title("distinct tactics / episode")
    fig.tight_layout(); fig.savefig(OUT / "episode_structure.png", dpi=120); plt.close(fig)

    # --- transition matrix ------------------------------------------------ --
    e2 = ev.sort_values(["episode_id", "seq_idx"])
    cur = e2["tactic_id"].to_numpy()
    nxt = e2["next_tactic_id"].to_numpy()
    ok = nxt >= 0
    T = np.zeros((len(TACTICS), len(TACTICS)))
    np.add.at(T, (cur[ok], nxt[ok]), 1.0)
    Tn = T / T.sum(1, keepdims=True).clip(min=1)
    pd.DataFrame(Tn.round(4), index=TACTICS, columns=TACTICS).to_csv(OUT / "transition_matrix.csv")
    md += ["## Tactic transition matrix  P(next | current)", "",
           "Saved `transition_matrix.csv`. Diagonal mass (tactic persists):",
           "", "| tactic | P(stay) | top off-diagonal |", "|---|---|---|"]
    for i, t in enumerate(TACTICS):
        off = [(TACTICS[j], Tn[i, j]) for j in range(len(TACTICS)) if j != i]
        off.sort(key=lambda z: -z[1])
        md.append(f"| {t} | {Tn[i, i]:.3f} | {off[0][0]} {off[0][1]:.3f} |")
    md.append("")
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    im = ax.imshow(Tn, cmap="viridis", vmin=0, vmax=1)
    ax.set_xticks(range(len(TACTICS))); ax.set_yticks(range(len(TACTICS)))
    ax.set_xticklabels([t[:5] for t in TACTICS], rotation=90)
    ax.set_yticklabels([t[:5] for t in TACTICS])
    ax.set_xlabel("next"); ax.set_ylabel("current"); fig.colorbar(im)
    ax.set_title("P(next | current)")
    fig.tight_layout(); fig.savefig(OUT / "transition_matrix.png", dpi=120); plt.close(fig)

    # --- inter-stage timing -------------------------------------------- --
    ttc = ev.loc[ev["time_to_next_change"].notna(), "time_to_next_change"]
    dt = ev.loc[ev["dt_prev"] > 0, "dt_prev"]
    md += ["## Timing", "",
           f"- inter-flow gap dt_prev (s): p50={dt.median():.3f}  p90={dt.quantile(.9):.2f}  "
           f"p99={dt.quantile(.99):.1f}",
           f"- time-to-stage-change (s): p50={ttc.median():.2f}  p90={ttc.quantile(.9):.1f}  "
           f"p99={ttc.quantile(.99):.0f}  (non-null {ev['time_to_next_change'].notna().mean():.2f})",
           f"- transitions with >=60 s lead available: {(ttc >= 60).mean():.3f}", ""]
    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.hist(np.log10(ttc.clip(lower=1e-3)), bins=60)
    ax.set_xlabel("log10 seconds to stage change"); ax.set_title("inter-stage timing")
    fig.tight_layout(); fig.savefig(OUT / "interstage_timing.png", dpi=120); plt.close(fig)

    # --- per-dataset contribution ------------------------------------- --
    contrib = (ev.assign(t=ev["tactic"])
               .pivot_table(index="t", columns="dataset", values="tactic_id",
                            aggfunc="size", fill_value=0).reindex(TACTICS, fill_value=0))
    md += ["## Per-dataset contribution (events per tactic)", "", contrib.to_markdown(), ""]

    # --- env-B feature availability ---------------------------------- --
    fc = man["feature_columns"]
    prim = pd.read_parquet(Path(ARTIFACT_DIR) / "events.parquet", columns=fc,
                           filters=[("domain", "==", "primary")])
    envb = pd.read_parquet(Path(ARTIFACT_DIR) / "events.parquet", columns=fc,
                           filters=[("domain", "==", "envB")])
    nan_env = envb.isna().mean()
    transfer_cols = nan_env[nan_env < 0.05].index.tolist()
    md += ["## Env-B (UNSW) transfer surface", "",
           f"- feature columns usable zero-shot (<5% NaN in env-B): "
           f"**{len(transfer_cols)} / {len(fc)}**",
           f"- columns lost (Argus schema lacks CICFlowMeter packet/IAT/flag stats): "
           f"{len(fc) - len(transfer_cols)}",
           "- engineered temporal / entity-graph / history features all transfer; "
           "raw CICFlowMeter distributional stats do not.", ""]
    json.dump({"transfer_columns": transfer_cols,
               "envB_nan_rate": nan_env.round(4).to_dict()},
              open(OUT / "envb_feature_availability.json", "w"), indent=2)

    (OUT / "report.md").write_text("\n".join(md))
    print("\n".join(md[:40]))
    print(f"\n[eda] wrote {OUT}/report.md + 5 PNGs + 3 data files")


if __name__ == "__main__":
    main()
