"""Per-dataset readers -> a normalised long-format frame.

Every reader yields DataFrames with these columns:
    ts (float, unix seconds), src_ip, dst_ip, src_port, dst_port, protocol (int),
    <ml.data.schema.CANON_FLOW_FEATURES...>, tactic (str), raw_label (str),
    dataset (str), day (str), domain (str: 'primary' | 'envB')
Readers stream in chunks so a 4 GB CSV never lands in memory whole.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

from .. import config
from . import schema

_CHUNK = 400_000


# --- helpers --------------------------------------------------------------- --
_EPOCH = pd.Timestamp("1970-01-01")


def _to_epoch(s: pd.Series, fmt: str | None) -> pd.Series:
    if fmt:
        dt = pd.to_datetime(s, format=fmt, errors="coerce")
    else:
        dt = pd.to_datetime(s, errors="coerce")
    if dt.isna().mean() > 0.5:                       # fallback: dayfirst free parse
        dt = pd.to_datetime(s, errors="coerce", dayfirst=True)
    # unit-agnostic (pandas may yield datetime64[s|us|ns]); keeps sub-second precision
    return (dt - _EPOCH).dt.total_seconds()


def _blank_canon(n: int) -> dict:
    return {c: np.full(n, np.nan, dtype="float32") for c in schema.CANON_FLOW_FEATURES}


def _finalise(df: pd.DataFrame, dataset: str, day: str, domain: str) -> pd.DataFrame:
    for c in schema.CANON_FLOW_FEATURES:
        if c not in df:
            df[c] = np.nan
    df = df.replace([np.inf, -np.inf], np.nan)
    keep = (["ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
            + schema.CANON_FLOW_FEATURES + schema.UNSW_CT_FEATURES
            + ["tactic", "raw_label"])
    for c in schema.UNSW_CT_FEATURES:
        if c not in df:
            df[c] = np.nan
    df = df[keep].copy()
    df["dataset"] = dataset
    df["day"] = day
    df["domain"] = domain
    df = df.dropna(subset=["ts"])
    df = df[df["tactic"] != schema.UNLABELED]
    for c in ("src_port", "dst_port", "protocol"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int32")
    for c in df.columns:
        # ts MUST stay float64 -- absolute epoch seconds (~1.5e9) lose ~128s to float32
        if c != "ts" and df[c].dtype == "float64":
            df[c] = df[c].astype("float32")
    df["ts"] = df["ts"].astype("float64")
    return df


# --- CICFlowMeter-family (DAPT2020 / CIC-IDS2017 / CIC-IDS2018) ------------- --
def _read_cicflowmeter(path: Path, dataset: str, domain: str,
                       nrows: int | None = None) -> Iterator[pd.DataFrame]:
    day = path.stem.lower()
    first = pd.read_csv(path, nrows=0)
    has_header = "Src IP" in first.columns or "Flow ID" in first.columns
    names = None if has_header else schema.CICFLOWMETER_V4_COLUMNS
    header = 0 if has_header else None

    ts_fmt = "%d/%m/%Y %I:%M:%S %p" if dataset == "dapt2020" else None
    label_col = "Stage" if dataset == "dapt2020" else "Label"

    reader = pd.read_csv(path, names=names, header=header, chunksize=_CHUNK,
                         nrows=nrows, low_memory=False, dtype_backend="numpy_nullable")
    for chunk in reader:
        chunk.columns = [str(c).strip() for c in chunk.columns]
        n = len(chunk)
        out = pd.DataFrame(index=range(n))
        out["ts"] = _to_epoch(chunk["Timestamp"].reset_index(drop=True), ts_fmt).values
        for src, dst in schema.CIC_META.items():
            if dst == "ts_raw":
                continue
            out[dst] = chunk[src].reset_index(drop=True).values if src in chunk else np.nan
        for src, dst in schema.CIC_TO_CANON.items():
            if src in chunk:
                out[dst] = pd.to_numeric(chunk[src].reset_index(drop=True), errors="coerce").values
        raw = chunk[label_col].astype(str).reset_index(drop=True) if label_col in chunk \
            else pd.Series(["BENIGN"] * n)
        attempted = None
        if "Attempted Category" in chunk:
            attempted = (pd.to_numeric(chunk["Attempted Category"], errors="coerce")
                         .fillna(-1).reset_index(drop=True) != -1)
        out["raw_label"] = raw.values
        out["tactic"] = [
            schema.label_to_tactic(dataset, r, bool(attempted.iloc[i]) if attempted is not None else False)
            for i, r in enumerate(raw)
        ]
        yield _finalise(out, dataset, day, domain)


# --- UNSW-NB15 full (4 headerless parts) ----------------------------------- --
def _read_unsw(path: Path, nrows: int | None = None) -> Iterator[pd.DataFrame]:
    day = path.stem.lower()
    reader = pd.read_csv(path, names=schema.UNSW_COLUMNS, header=None, chunksize=_CHUNK,
                         nrows=nrows, low_memory=False)
    for chunk in reader:
        n = len(chunk)
        out = pd.DataFrame(index=range(n))
        out["ts"] = pd.to_numeric(chunk["stime"].reset_index(drop=True), errors="coerce").values
        out["src_ip"] = chunk["srcip"].reset_index(drop=True).values
        out["dst_ip"] = chunk["dstip"].reset_index(drop=True).values
        out["src_port"] = pd.to_numeric(chunk["sport"].reset_index(drop=True), errors="coerce").values
        out["dst_port"] = pd.to_numeric(chunk["dsport"].reset_index(drop=True), errors="coerce").values
        out["protocol"] = (chunk["proto"].astype(str).str.lower().str.strip()
                           .map(schema.PROTO_NAME_TO_NUM).fillna(0).reset_index(drop=True).values)
        for src, dst in schema.UNSW_TO_CANON.items():
            out[dst] = pd.to_numeric(chunk[src].reset_index(drop=True), errors="coerce").values
        for c in schema.UNSW_CT_FEATURES:
            out[c] = pd.to_numeric(chunk[c].reset_index(drop=True), errors="coerce").values
        # In the raw 4-part files, benign flows have an EMPTY attack_cat; the
        # binary `label` column (0=normal) disambiguates.
        raw = chunk["attack_cat"].astype(str).str.strip().reset_index(drop=True)
        lab = pd.to_numeric(chunk["label"], errors="coerce").fillna(0).reset_index(drop=True)
        blank = raw.isin(["", "nan", "NaN", "None", "-"])
        raw = raw.where(~blank, "Normal").mask(lab == 0, "Normal")
        out["raw_label"] = raw.values
        out["tactic"] = [schema.label_to_tactic("unsw_nb15", r) for r in raw]
        yield _finalise(out, "unsw_nb15", day, "envB")


# --- public API ----------------------------------------------------------- ---
_CIC_DOMAIN = {"dapt2020": "primary", "cicids2017": "primary", "cicids2018": "primary"}


def iter_source(dataset: str, nrows: int | None = None,
                day_limit: int | None = None) -> Iterator[pd.DataFrame]:
    root = config.PATHS[dataset]
    if dataset == "unsw_nb15":
        parts = sorted(root.glob("UNSW-NB15_[1-4].csv"))
        for p in parts[:day_limit] if day_limit else parts:
            yield from _read_unsw(p, nrows=nrows)
    else:
        files = sorted(root.glob("*.csv"))
        for p in (files[:day_limit] if day_limit else files):
            yield from _read_cicflowmeter(p, dataset, _CIC_DOMAIN[dataset], nrows=nrows)


def load_source(dataset: str, nrows: int | None = None,
                day_limit: int | None = None) -> pd.DataFrame:
    frames = list(iter_source(dataset, nrows=nrows, day_limit=day_limit))
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
