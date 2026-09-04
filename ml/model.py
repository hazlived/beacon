"""Forecasting model: causal RNN encoder + multi-head prediction.

Heads (all read the encoder state at the current event = last window position):
    next_logits  -- next ATT&CK tactic            (10-way softmax)
    ttc          -- log1p seconds until the tactic changes   (regression)
    ttn          -- log1p seconds to the next flow           (regression)
    esc_logit    -- escalation to IMPACT/EXFIL within H events(binary)

The RNN is unidirectional -- forecasting must not see the future.
`temperature` is a post-hoc calibration buffer (set by ml/train.py after fit).
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class ForecastNet(nn.Module):
    def __init__(self, n_num_features: int, n_emb: int, n_tactics: int,
                 hidden: int = 128, layers: int = 2, rnn: str = "gru",
                 dropout: float = 0.2, emb_dim: int = 16):
        super().__init__()
        self.n_tactics = n_tactics
        self.embs = nn.ModuleList(
            [nn.Embedding(n_tactics, emb_dim) for _ in range(n_emb)])
        in_dim = n_num_features + n_emb * emb_dim
        rnn_cls = {"gru": nn.GRU, "lstm": nn.LSTM}[rnn]
        self.rnn = rnn_cls(in_dim, hidden, num_layers=layers, batch_first=True,
                           dropout=dropout if layers > 1 else 0.0)
        self.norm = nn.LayerNorm(hidden)
        self.drop = nn.Dropout(dropout)
        self.head_next = nn.Linear(hidden, n_tactics)
        self.head_ttc = nn.Linear(hidden, 1)
        self.head_ttn = nn.Linear(hidden, 1)
        self.head_esc = nn.Linear(hidden, 1)
        self.register_buffer("temperature", torch.ones(1))

    def encode(self, x, emb, mask):
        parts = [x] + [self.embs[i](emb[..., i]) for i in range(len(self.embs))]
        h, _ = self.rnn(torch.cat(parts, dim=-1))       # [B, T, H]
        # windows are right-aligned: the current event is always the last position
        return self.drop(self.norm(h[:, -1, :]))

    def forward(self, x, emb, mask, calibrated: bool = False, return_state: bool = False):
        z = self.encode(x, emb, mask)
        logits = self.head_next(z)
        if calibrated:
            logits = logits / self.temperature.clamp(min=1e-2)
        out = {
            "next_logits": logits,
            "ttc": self.head_ttc(z).squeeze(-1),
            "ttn": self.head_ttn(z).squeeze(-1),
            "esc_logit": self.head_esc(z).squeeze(-1),
        }
        if return_state:
            out["state"] = z
        return out


def capped_class_weights(w: torch.Tensor, cap: float = 50.0) -> torch.Tensor:
    """Inverse-freq weights blow up for 0/near-0 support classes -- clamp them."""
    return w.clone().clamp_(max=cap)


def multitask_loss(out: dict, batch: dict, class_weights: torch.Tensor | None = None,
                   weights=(1.0, 0.3, 0.2, 0.5)) -> tuple[torch.Tensor, dict]:
    wn, wc, wt, we = weights
    ce = F.cross_entropy(out["next_logits"], batch["y_next"], weight=class_weights)

    def masked_reg(pred, tgt, valid):
        v = valid.bool()
        return F.smooth_l1_loss(pred[v], tgt[v]) if v.any() else pred.sum() * 0.0

    lc = masked_reg(out["ttc"], batch["y_ttc"], batch["y_ttc_valid"])
    lt = masked_reg(out["ttn"], batch["y_ttn"], batch["y_ttn_valid"])
    le = F.binary_cross_entropy_with_logits(out["esc_logit"], batch["y_esc"])
    total = wn * ce + wc * lc + wt * lt + we * le
    return total, {"total": float(total), "ce": float(ce), "ttc": float(lc),
                   "ttn": float(lt), "esc": float(le)}


if __name__ == "__main__":                       # smoke test
    torch.manual_seed(0)
    B, T, Fn, E, C = 8, 64, 142, 2, 10
    net = ForecastNet(Fn, E, C, hidden=64, layers=2)
    batch = {
        "x": torch.randn(B, T, Fn), "emb": torch.randint(0, C, (B, T, E)),
        "mask": torch.ones(B, T),
        "y_next": torch.randint(0, C, (B,)),
        "y_ttc": torch.rand(B) * 5, "y_ttc_valid": (torch.rand(B) > 0.3).float(),
        "y_ttn": torch.rand(B) * 3, "y_ttn_valid": torch.ones(B),
        "y_esc": (torch.rand(B) > 0.5).float(),
    }
    out = net(batch["x"], batch["emb"], batch["mask"])
    loss, parts = multitask_loss(out, batch)
    loss.backward()
    n_params = sum(p.numel() for p in net.parameters())
    print("output shapes:", {k: tuple(v.shape) for k, v in out.items()})
    print("loss parts:", {k: round(v, 4) for k, v in parts.items()})
    print(f"params: {n_params:,}  | grad ok: "
          f"{all(p.grad is not None for p in net.parameters() if p.requires_grad)}")
