"""Central paths and constants for the BEACON ML pipeline."""
from __future__ import annotations

import os
from pathlib import Path

# --- Roots -------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
# Datasets live outside the repo (5-120 GB). Override with BEACON_DATA_ROOT.
DATA_ROOT = Path(os.environ.get("BEACON_DATA_ROOT", r"D:\Coding\datasets\beacon"))
ARTIFACT_DIR = Path(os.environ.get("BEACON_ARTIFACT_DIR", REPO_ROOT / "ml" / "artifacts"))
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

# --- Per-dataset locations -------------------------------------------------- -
PATHS = {
    "dapt2020":   DATA_ROOT / "dapt2020" / "csv",
    "cicids2017": DATA_ROOT / "cic-ids2017-improved",
    "cicids2018": DATA_ROOT / "cic-cse-ids2018-improved",
    "unsw_nb15":  DATA_ROOT / "unsw-nb15" / "full" / "CSV Files",
}

# --- Sessionisation defaults ----------------------------------------------- --
GAP_SECONDS = 300      # new episode when inter-flow gap exceeds this
MIN_EVENTS = 3         # drop episodes shorter than this
MAX_EVENTS = 512       # hard-split very long episodes
BENIGN_EPISODE_KEEP = 0.15   # fraction of pure-benign episodes retained as negatives
IMPACT_HORIZON_EVENTS = 20    # "reached impact within H events"

# --- Split ---------------------------------------------------------------- ---
SPLIT_FRACS = (0.70, 0.15, 0.15)   # train / val / test  (primary domain only)
SEED = 1337

# --- Model sequence window ---------------------------------------------------
SEQ_LEN = 64
