import os
import json
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import Dict, List, Any, Tuple

MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
FORECAST_MODEL_PATH = os.path.join(MODEL_DIR, "forecast_lstm.pt")
STAGES = ["BENIGN", "RECON", "INITIAL_ACCESS", "CREDENTIAL_ACCESS", "LATERAL_MOVEMENT", "IMPACT"]
STAGE_TO_IDX = {s: i for i, s in enumerate(STAGES)}
IDX_TO_STAGE = {i: s for i, s in enumerate(STAGES)}

class ForecastModel(nn.Module):
    def __init__(self, input_dim: int = 12, hidden_dim: int = 64, num_stages: int = len(STAGES)):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.fc_stage = nn.Linear(hidden_dim, num_stages)
        self.fc_risk = nn.Linear(hidden_dim, 1)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        out, _ = self.lstm(x)
        last = out[:, -1, :]
        stage_logits = self.fc_stage(last)
        risk = torch.sigmoid(self.fc_risk(last))
        return stage_logits, risk

class AttackForecastingEngine:
    def __init__(self):
        self.input_dim = 12
        self.hidden_dim = 64
        self.model = ForecastModel(self.input_dim, self.hidden_dim, len(STAGES))
        self._load_if_exists()

    def _load_if_exists(self):
        if os.path.exists(FORECAST_MODEL_PATH):
            try:
                self.model.load_state_dict(torch.load(FORECAST_MODEL_PATH, map_location=torch.device("cpu"), weights_only=True))
                self.model.eval()
            except Exception as e:
                print(f"Warning loading Forecast model: {e}")

    def extract_sequence_features(self, flows: list, seq_len: int = 5) -> Tuple[np.ndarray, int, float]:
        """Converts flow list into feature tensor sequences (seq_len, input_dim)."""
        feats_seq = []
        last_stage_idx = 0
        for f in flows[-seq_len:]:
            duration = float(f.get("duration", 0.0)) / 100.0
            fwd_pkts = float(f.get("total_fwd_packets", 0)) / 1000.0
            bwd_pkts = float(f.get("total_bwd_packets", 0)) / 1000.0
            fwd_bytes = float(f.get("total_length_fwd_packets", 0)) / 10000.0
            bwd_bytes = float(f.get("total_length_bwd_packets", 0)) / 10000.0
            flow_bytes = float(f.get("flow_bytes_s", 0)) / 100000.0
            syn_flag = float(f.get("syn_flag_count", 0))
            rst_flag = float(f.get("rst_flag_count", 0))
            waf_risk = float(f.get("waf_risk", 0.0))
            behavior_risk = float(f.get("behavior_risk", 0.0))
            compliance = float(f.get("compliance_score", 1.0))
            
            stage_str = f.get("attack_stage", "BENIGN")
            stage_idx = STAGE_TO_IDX.get(stage_str, 0)
            last_stage_idx = stage_idx

            vec = [
                duration, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes,
                flow_bytes, syn_flag, rst_flag, waf_risk, behavior_risk, compliance, float(stage_idx)
            ]
            feats_seq.append(vec)

        # Pad if short
        while len(feats_seq) < seq_len:
            feats_seq.insert(0, [0.0] * self.input_dim)

        # Calculate target escalation risk
        target_risk = 0.9 if last_stage_idx in [3, 4, 5] else (0.5 if last_stage_idx in [1, 2] else 0.05)

        return np.array(feats_seq, dtype=np.float32), last_stage_idx, target_risk

    def train(self, flow_records: list, epochs: int = 15) -> Dict[str, Any]:
        """Trains PyTorch LSTM dual-head forecasting model on entity flow sequences."""
        if len(flow_records) < 10:
            return {"status": "insufficient_data"}

        # Group flows by entity (src_ip)
        entity_groups = {}
        for f in flow_records:
            entity = f["src_ip"]
            if entity not in entity_groups:
                entity_groups[entity] = []
            entity_groups[entity].append(f)

        X_list, y_stage_list, y_risk_list = [], [], []

        for entity, flows in entity_groups.items():
            for i in range(2, len(flows)):
                seq = flows[:i]
                target_flow = flows[i]
                x_vec, _, _ = self.extract_sequence_features(seq)
                next_stage_str = target_flow.get("attack_stage", "BENIGN")
                next_stage_idx = STAGE_TO_IDX.get(next_stage_str, 0)
                risk_val = 0.95 if next_stage_idx in [3, 4, 5] else (0.6 if next_stage_idx in [1, 2] else 0.05)

                X_list.append(x_vec)
                y_stage_list.append(next_stage_idx)
                y_risk_list.append(risk_val)

        if not X_list:
            return {"status": "no_sequences_generated"}

        X_tensor = torch.tensor(np.array(X_list), dtype=torch.float32)
        y_stage_tensor = torch.tensor(np.array(y_stage_list), dtype=torch.long)
        y_risk_tensor = torch.tensor(np.array(y_risk_list), dtype=torch.float32).unsqueeze(1)

        self.model.train()
        optimizer = optim.Adam(self.model.parameters(), lr=0.005)
        criterion_stage = nn.CrossEntropyLoss()
        criterion_risk = nn.MSELoss()

        for epoch in range(epochs):
            optimizer.zero_grad()
            stage_logits, risk_preds = self.model(X_tensor)
            loss_stage = criterion_stage(stage_logits, y_stage_tensor)
            loss_risk = criterion_risk(risk_preds, y_risk_tensor)
            total_loss = loss_stage + loss_risk
            total_loss.backward()
            optimizer.step()

        self.model.eval()
        os.makedirs(MODEL_DIR, exist_ok=True)
        torch.save(self.model.state_dict(), FORECAST_MODEL_PATH)

        return {
            "sequences_trained": len(X_list),
            "epochs": epochs,
            "final_loss": round(float(total_loss.item()), 4),
            "status": "trained"
        }

    def forecast_session(self, flows: list) -> Dict[str, Any]:
        """Performs live sequence inference predicting next attack stage and escalation risk."""
        self.model.eval()
        x_vec, last_stage_idx, heuristic_risk = self.extract_sequence_features(flows)
        x_tensor = torch.tensor(np.array([x_vec]), dtype=torch.float32)

        with torch.no_grad():
            stage_logits, risk_tensor = self.model(x_tensor)
            probs = torch.softmax(stage_logits, dim=-1)[0]
            pred_stage_idx = int(torch.argmax(probs).item())
            confidence = float(probs[pred_stage_idx].item())
            escalation_risk = float(risk_tensor[0][0].item())

        current_stage = IDX_TO_STAGE.get(last_stage_idx, "BENIGN")
        likely_next_stage = IDX_TO_STAGE.get(pred_stage_idx, "BENIGN")

        # Map to ATT&CK stage details
        stage_descriptions = {
            "BENIGN": "Normal operational behavior",
            "RECON": "Scanning & Probing (T1046 - Network Service Discovery)",
            "INITIAL_ACCESS": "Exploits & Web Attacks (T1190 - Exploit Public-Facing Application)",
            "CREDENTIAL_ACCESS": "Brute Force & Theft (T1110 - Brute Force)",
            "LATERAL_MOVEMENT": "Remote Services & Pivoting (T1021 - Remote Services)",
            "IMPACT": "Denial of Service / Exfiltration (T1499 - Endpoint Denial of Service)"
        }

        return {
            "current_stage": current_stage,
            "likely_next_stage": likely_next_stage,
            "escalation_risk": round(escalation_risk, 4),
            "confidence": round(confidence, 4),
            "att_ck_mapping": stage_descriptions.get(likely_next_stage, ""),
            "probs": {STAGES[i]: round(float(probs[i]), 4) for i in range(len(STAGES))}
        }

forecasting_engine = AttackForecastingEngine()
