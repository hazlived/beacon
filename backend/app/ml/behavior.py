import os
import networkx as nx
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from typing import Dict, List, Any
from backend.app.db.database import SessionLocal
from backend.app.db.models import AuthLog

MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
BEHAVIOR_MODEL_PATH = os.path.join(MODEL_DIR, "behavior_isoforest.joblib")

class InsiderThreatEngine:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.model = None
        self._load_if_exists()

    def _load_if_exists(self):
        if os.path.exists(BEHAVIOR_MODEL_PATH):
            try:
                self.model = joblib.load(BEHAVIOR_MODEL_PATH)
            except Exception:
                pass

    def build_graph_from_logs(self, auth_logs: list):
        """Constructs heterogeneous behavioral graph from authentication & access logs."""
        self.graph.clear()
        for log in auth_logs:
            user = f"user:{log['user_id']}"
            device = f"device:{log['device_id']}"
            ip = f"ip:{log['ip']}"
            resource = f"resource:{log['resource']}"

            self.graph.add_node(user, node_type="User", user_id=log["user_id"])
            self.graph.add_node(device, node_type="Device")
            self.graph.add_node(ip, node_type="IP")
            self.graph.add_node(resource, node_type="Resource", sensitive=log.get("sensitive_access", 0))

            # Edges
            self.graph.add_edge(user, device, relation="User->Device", success=log.get("success", 1))
            self.graph.add_edge(user, ip, relation="User->IP")
            self.graph.add_edge(user, resource, relation="User->Resource", sensitive=log.get("sensitive_access", 0))
            if "SRV_" in log["device_id"]:
                self.graph.add_edge(device, resource, relation="Device->Resource")

    def extract_user_features(self, user_id: str, user_logs: list) -> List[float]:
        total_logins = len(user_logs)
        failed_logins = sum(1 for l in user_logs if l.get("success") == 0)
        sensitive_accesses = sum(1 for l in user_logs if l.get("sensitive_access") == 1)
        unique_devices = len(set(l["device_id"] for l in user_logs))
        unique_ips = len(set(l["ip"] for l in user_logs))

        # Temporal features
        login_hours = []
        for l in user_logs:
            t = l["login_time"]
            hour = t.hour if hasattr(t, "hour") else int(str(t).split()[1].split(":")[0]) if " " in str(t) else 12
            login_hours.append(hour)

        mean_hour = np.mean(login_hours) if login_hours else 12.0
        off_hours_count = sum(1 for h in login_hours if h < 7 or h > 19)

        return [
            float(total_logins),
            float(failed_logins),
            float(sensitive_accesses),
            float(unique_devices),
            float(unique_ips),
            float(mean_hour),
            float(off_hours_count)
        ]

    def train(self, auth_logs: list) -> Dict[str, Any]:
        self.build_graph_from_logs(auth_logs)

        # Group logs by user
        user_logs_map = {}
        for l in auth_logs:
            uid = l["user_id"]
            if uid not in user_logs_map:
                user_logs_map[uid] = []
            user_logs_map[uid].append(l)

        X = [self.extract_user_features(uid, ulogs) for uid, ulogs in user_logs_map.items()]

        if len(X) < 3:
            return {"status": "insufficient_data"}

        self.model = IsolationForest(contamination=0.15, random_state=42)
        self.model.fit(X)

        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, BEHAVIOR_MODEL_PATH)

        return {"users_modeled": len(X), "nodes": self.graph.number_of_nodes(), "edges": self.graph.number_of_edges(), "status": "trained"}

    def compute_behavior_risk(self, user_id: str, user_logs: list) -> Dict[str, Any]:
        feats = self.extract_user_features(user_id, user_logs)
        
        indicators = []
        if feats[1] > 2: # failed logins
            indicators.append("multiple_failed_logins")
        if feats[2] > 1: # sensitive access
            indicators.append("high_sensitive_access")
        if feats[3] > 3: # new/multiple devices
            indicators.append("new_device_sprawl")
        if feats[6] > 1: # off hours
            indicators.append("unusual_time_activity")

        if self.model is not None:
            score_raw = self.model.decision_function([feats])[0]
            # Convert decision score (-0.5 to 0.5) to risk probability (0.0 to 1.0)
            risk = float(np.clip(1.0 - (score_raw + 0.5), 0.0, 1.0))
        else:
            # Rule fallback
            risk = min(1.0, 0.1 * feats[1] + 0.25 * feats[2] + 0.2 * feats[3] + 0.15 * feats[6])

        return {
            "user_id": user_id,
            "behavior_risk": round(risk, 4),
            "anomaly_indicators": indicators,
            "features": {
                "total_logins": feats[0],
                "failed_logins": feats[1],
                "sensitive_accesses": feats[2],
                "unique_devices": feats[3],
                "unique_ips": feats[4],
                "off_hours_count": feats[6]
            }
        }

    def get_graph_data(self) -> Dict[str, Any]:
        nodes = [{"id": n, "label": n.split(":")[-1], "type": self.graph.nodes[n].get("node_type", "Unknown")} for n in self.graph.nodes()]
        links = [{"source": u, "target": v, "relation": self.graph.edges[u, v].get("relation", "")} for u, v in self.graph.edges()]
        return {"nodes": nodes, "links": links}

insider_engine = InsiderThreatEngine()
