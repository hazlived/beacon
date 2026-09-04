import json
import os
import urllib.parse
from typing import Dict, Any, Tuple, List
import torch
import torch.nn as nn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
import joblib

MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
WAF_MODEL_PATH = os.path.join(MODEL_DIR, "waf_classifier.joblib")
WAF_VEC_PATH = os.path.join(MODEL_DIR, "waf_vectorizer.joblib")
WAF_METRICS_PATH = os.path.join(MODEL_DIR, "waf_metrics.json")

def request_to_text(method: str, path: str, query: str = "", headers: str = "", body: str = "") -> str:
    try:
        header_dict = json.loads(headers) if headers and headers.startswith("{") else headers
        header_str = json.dumps(header_dict) if isinstance(header_dict, dict) else str(headers or "")
    except Exception:
        header_str = str(headers or "")

    parts = [method.upper(), path, query, header_str, (body or "")[:1024]]
    return " || ".join(str(p) for p in parts if p)

class SmartWAF:
    def __init__(self):
        self.vectorizer = None
        self.model = None
        self.metrics = None
        self._load_if_exists()

    def _load_if_exists(self):
        if os.path.exists(WAF_MODEL_PATH) and os.path.exists(WAF_VEC_PATH):
            try:
                self.model = joblib.load(WAF_MODEL_PATH)
                self.vectorizer = joblib.load(WAF_VEC_PATH)
            except Exception:
                pass
        if os.path.exists(WAF_METRICS_PATH):
            try:
                with open(WAF_METRICS_PATH, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
            except Exception:
                pass

    def train(self, payloads: list) -> Dict[str, Any]:
        texts = [
            request_to_text(p["method"], p["path"], p.get("query", ""), p.get("headers", ""), p.get("body", ""))
            for p in payloads
        ]
        labels = [int(p["label"]) for p in payloads]

        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )

        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=5000, analyzer="char_wb")
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_test_vec = self.vectorizer.transform(X_test)

        self.model = LogisticRegression(C=1.0, max_iter=500)
        self.model.fit(X_train_vec, y_train)

        y_pred = self.model.predict(X_test_vec)

        acc = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()

        self.metrics = {
            "accuracy": round(acc, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "confusion_matrix": cm,
            "test_samples": len(y_test),
        }

        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, WAF_MODEL_PATH)
        joblib.dump(self.vectorizer, WAF_VEC_PATH)
        with open(WAF_METRICS_PATH, "w", encoding="utf-8") as f:
            json.dump(self.metrics, f, indent=2)

        return {
            "samples": len(payloads),
            "train_samples": len(y_train),
            "test_samples": len(y_test),
            "accuracy": self.metrics["accuracy"],
            "precision": self.metrics["precision"],
            "recall": self.metrics["recall"],
            "f1": self.metrics["f1"],
            "status": "trained",
        }

    def evaluate_request(self, method: str, path: str, query: str = "", headers: str = "", body: str = "") -> Dict[str, Any]:
        text = request_to_text(method, path, query, headers, body)
        if self.model is None or self.vectorizer is None:
            lowered = text.lower()
            suspicious_keywords = ["union select", "drop table", "<script>", "onerror=", "../..", "/etc/passwd", "cat /etc", "hydra", "or '1'='1"]
            is_malicious = any(kw in lowered for kw in suspicious_keywords)
            score = 0.92 if is_malicious else 0.05
            attack_type = "SQL Injection/XSS" if is_malicious else "BENIGN"
            return {
                "text": text,
                "malicious_score": score,
                "label": 1 if is_malicious else 0,
                "attack_type": attack_type,
                "model_status": "heuristic_fallback",
            }

        X = self.vectorizer.transform([text])
        probs = self.model.predict_proba(X)[0]
        malicious_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        label = 1 if malicious_prob >= 0.5 else 0

        attack_type = "BENIGN"
        if label == 1:
            lowered = text.lower()
            if "select" in lowered or "union" in lowered or "drop" in lowered or "'" in lowered:
                attack_type = "SQL Injection"
            elif "<script>" in lowered or "onerror" in lowered:
                attack_type = "XSS"
            elif ".." in lowered or "passwd" in lowered:
                attack_type = "Path Traversal"
            elif "cat " in lowered or "ping" in lowered or ";" in lowered:
                attack_type = "Command Injection"
            else:
                attack_type = "Web Attack"

        return {
            "text": text,
            "malicious_score": round(malicious_prob, 4),
            "label": label,
            "attack_type": attack_type,
            "model_status": "tfidf_logreg_trained",
        }

    def get_metrics(self) -> Dict[str, Any]:
        return self.metrics or {"status": "no_metrics_available"}

waf_engine = SmartWAF()
