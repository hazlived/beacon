import os
import sys
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.db.database import SessionLocal, Base, engine
from backend.app.db.models import NetworkFlow, AuthLog, WafLog, ComplianceFinding, SessionTrust, AttackSequence
from backend.app.ml.waf import waf_engine
from backend.app.ml.behavior import insider_engine
from backend.app.ml.forecast import forecasting_engine
from backend.app.ml.trust import compute_trust_score
from backend.app.ml.compliance import compliance_engine

# Initialize database schemas
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SIH26153 AI-Based Network Attack Forecasting Mini-SOC Backend API",
    description="Backend services for Smart WAF, Agentless Compliance, Insider Threat Engine, Attack Forecasting, and Continuous Trust Engine.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper DB session manager obeying expunge_all rule
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.expunge_all()
        db.close()

# Pydantic Request Models
class WafEvaluationRequest(BaseModel):
    method: str
    path: str
    query: Optional[str] = ""
    headers: Optional[str] = ""
    body: Optional[str] = ""

class TrustEvaluationRequest(BaseModel):
    session_id: str
    user_id: str
    identity_trust: float = 1.0
    waf_risk: float = 0.0
    behavior_risk: float = 0.0
    forecast_risk: float = 0.0
    compliance_score: float = 1.0

# 1. Overview Stats Endpoint
@app.get("/api/overview/stats")
def get_overview_stats(db=Depends(get_db)):
    total_flows = db.query(NetworkFlow).count()
    attacks_detected = db.query(NetworkFlow).filter(NetworkFlow.attack_stage != "BENIGN").count()
    open_compliance = db.query(ComplianceFinding).filter(ComplianceFinding.status == "OPEN").count()
    total_auth_logs = db.query(AuthLog).count()

    # Active sessions trust breakdown
    trust_scores = [0.95, 0.88, 0.72, 0.65, 0.42, 0.91, 0.84, 0.38]
    high_trust = sum(1 for t in trust_scores if t >= 0.8)
    medium_trust = sum(1 for t in trust_scores if 0.5 <= t < 0.8)
    low_trust = sum(1 for t in trust_scores if t < 0.5)

    recent_flows = db.query(NetworkFlow).order_by(NetworkFlow.timestamp.desc()).limit(6).all()
    feed = [
        {
            "id": f.id,
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "stage": f.attack_stage,
            "label": f.label,
            "timestamp": str(f.timestamp)
        }
        for f in recent_flows
    ]

    return {
        "metrics": {
            "total_flows": total_flows,
            "attacks_detected": attacks_detected,
            "open_compliance_findings": open_compliance,
            "auth_logs_ingested": total_auth_logs,
            "high_trust_sessions": high_trust,
            "medium_trust_sessions": medium_trust,
            "low_trust_sessions": low_trust
        },
        "recent_live_feed": feed
    }

# 2. Network Flow Endpoints
@app.get("/api/network/flows")
def get_network_flows(limit: int = 50, stage: Optional[str] = None, db=Depends(get_db)):
    query = db.query(NetworkFlow)
    if stage:
        query = query.filter(NetworkFlow.attack_stage == stage)
    flows = query.order_by(NetworkFlow.timestamp.desc()).limit(limit).all()
    
    stage_counts = {
        "BENIGN": db.query(NetworkFlow).filter(NetworkFlow.attack_stage == "BENIGN").count(),
        "RECON": db.query(NetworkFlow).filter(NetworkFlow.attack_stage == "RECON").count(),
        "INITIAL_ACCESS": db.query(NetworkFlow).filter(NetworkFlow.attack_stage == "INITIAL_ACCESS").count(),
        "CREDENTIAL_ACCESS": db.query(NetworkFlow).filter(NetworkFlow.attack_stage == "CREDENTIAL_ACCESS").count(),
        "LATERAL_MOVEMENT": db.query(NetworkFlow).filter(NetworkFlow.attack_stage == "LATERAL_MOVEMENT").count(),
        "IMPACT": db.query(NetworkFlow).filter(NetworkFlow.attack_stage == "IMPACT").count(),
    }

    return {
        "stage_distribution": stage_counts,
        "flows": [
            {
                "id": f.id,
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "timestamp": str(f.timestamp),
                "duration": f.duration,
                "flow_bytes_s": f.flow_bytes_s,
                "flow_packets_s": f.flow_packets_s,
                "attack_stage": f.attack_stage,
                "label": f.label
            }
            for f in flows
        ]
    }

# 3. Smart WAF Endpoints
@app.post("/api/waf/evaluate")
def evaluate_waf_request(req: WafEvaluationRequest, db=Depends(get_db)):
    result = waf_engine.evaluate_request(req.method, req.path, req.query, req.headers, req.body)
    
    # Save log to DB
    waf_log = WafLog(
        method=req.method,
        path=req.path,
        query=req.query,
        headers=req.headers,
        body=req.body,
        malicious_score=result["malicious_score"],
        label=result["label"],
        attack_type=result["attack_type"]
    )
    db.add(waf_log)
    db.commit()

    return result

@app.get("/api/waf/logs")
def get_waf_logs(limit: int = 30, db=Depends(get_db)):
    logs = db.query(WafLog).order_by(WafLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "method": l.method,
            "path": l.path,
            "query": l.query,
            "malicious_score": l.malicious_score,
            "label": l.label,
            "attack_type": l.attack_type,
            "created_at": str(l.created_at)
        }
        for l in logs
    ]

# 4. Insider Threat Behavior Endpoints
@app.get("/api/behavior/graph")
def get_behavior_graph(db=Depends(get_db)):
    logs = db.query(AuthLog).all()
    log_dicts = [
        {
            "user_id": l.user_id,
            "device_id": l.device_id,
            "ip": l.ip,
            "resource": l.resource,
            "login_time": l.login_time,
            "success": l.success,
            "sensitive_access": l.sensitive_access
        }
        for l in logs
    ]
    insider_engine.build_graph_from_logs(log_dicts)
    return insider_engine.get_graph_data()

@app.get("/api/behavior/users")
def get_user_risk_ranking(db=Depends(get_db)):
    logs = db.query(AuthLog).all()
    user_logs_map = {}
    for l in logs:
        uid = l.user_id
        if uid not in user_logs_map:
            user_logs_map[uid] = []
        user_logs_map[uid].append({
            "user_id": l.user_id,
            "device_id": l.device_id,
            "ip": l.ip,
            "resource": l.resource,
            "login_time": l.login_time,
            "success": l.success,
            "sensitive_access": l.sensitive_access
        })

    rankings = []
    for uid, ulogs in user_logs_map.items():
        prof = insider_engine.compute_behavior_risk(uid, ulogs)
        rankings.append(prof)

    rankings.sort(key=lambda x: x["behavior_risk"], reverse=True)
    return rankings

# 5. Attack Forecasting Endpoints
@app.get("/api/forecast/evaluate")
def get_forecast_evaluation(session_id: str = "SESS101", db=Depends(get_db)):
    flows = db.query(NetworkFlow).limit(10).all()
    flow_dicts = [
        {
            "src_ip": f.src_ip,
            "duration": f.duration,
            "total_fwd_packets": f.total_fwd_packets,
            "total_bwd_packets": f.total_bwd_packets,
            "total_length_fwd_packets": f.total_length_fwd_packets,
            "total_length_bwd_packets": f.total_length_bwd_packets,
            "flow_bytes_s": f.flow_bytes_s,
            "syn_flag_count": f.syn_flag_count,
            "rst_flag_count": f.rst_flag_count,
            "waf_risk": f.waf_risk,
            "behavior_risk": f.behavior_risk,
            "compliance_score": f.compliance_score,
            "attack_stage": f.attack_stage
        }
        for f in flows
    ]
    res = forecasting_engine.forecast_session(flow_dicts)
    res["session_id"] = session_id
    return res

# 6. Compliance Endpoints
@app.get("/api/compliance/findings")
def get_compliance_findings(source: Optional[str] = None, db=Depends(get_db)):
    query = db.query(ComplianceFinding)
    if source:
        query = query.filter(ComplianceFinding.source == source)
    findings = query.all()

    if not findings:
        # Run scan if empty
        aws_findings = compliance_engine.run_scan("aws")
        k8s_findings = compliance_engine.run_scan("k8s")
        for f in aws_findings + k8s_findings:
            item = ComplianceFinding(
                source=f["source"],
                control_id=f["control_id"],
                title=f["title"],
                severity=f["severity"],
                resource=f["resource"],
                description=f["description"],
                remediation=f["remediation"],
                status=f["status"],
                nciipc_guideline=f["nciipc_guideline"],
                plain_english_explanation=f["plain_english_explanation"]
            )
            db.add(item)
        db.commit()
        findings = db.query(ComplianceFinding).all()

    return [
        {
            "id": f.id,
            "source": f.source,
            "control_id": f.control_id,
            "title": f.title,
            "severity": f.severity,
            "resource": f.resource,
            "description": f.description,
            "remediation": f.remediation,
            "status": f.status,
            "nciipc_guideline": f.nciipc_guideline,
            "plain_english_explanation": f.plain_english_explanation
        }
        for f in findings
    ]

# 7. Continuous Trust Status Endpoint
@app.post("/api/trust/score")
def evaluate_trust_score(req: TrustEvaluationRequest):
    return compute_trust_score(
        identity_trust=req.identity_trust,
        waf_risk=req.waf_risk,
        behavior_risk=req.behavior_risk,
        forecast_risk=req.forecast_risk,
        compliance_score=req.compliance_score
    )

# 8. System Ingest & Train Trigger Endpoints
@app.post("/api/system/ingest")
def trigger_system_ingest():
    from backend.app.ingest import ingest_cicids2017_csv, ingest_lanl_auth_csv, ingest_compliance_json
    c1 = ingest_cicids2017_csv("data/cicids2017_sample.csv", force=True)
    c2 = ingest_lanl_auth_csv("data/lanl_auth_sample.csv", force=True)
    c3 = ingest_compliance_json("data/compliance_benchmarks.json", force=True)
    return {
        "status": "success",
        "flows_ingested": c1,
        "auth_logs_ingested": c2,
        "compliance_findings_ingested": c3
    }

@app.post("/api/system/train")
def trigger_system_train(db=Depends(get_db)):
    import csv
    # Train WAF
    payloads = []
    if os.path.exists("data/http_waf_payloads.csv"):
        with open("data/http_waf_payloads.csv", "r", encoding="utf-8") as f:
            payloads = list(csv.DictReader(f))
    waf_res = waf_engine.train(payloads) if payloads else {"status": "no_payloads"}

    # Train Behavior
    logs = db.query(AuthLog).all()
    log_dicts = [{"user_id": l.user_id, "device_id": l.device_id, "ip": l.ip, "resource": l.resource, "login_time": l.login_time, "success": l.success, "sensitive_access": l.sensitive_access} for l in logs]
    beh_res = insider_engine.train(log_dicts) if log_dicts else {"status": "no_logs"}

    # Train Forecast
    flows = db.query(NetworkFlow).all()
    flow_dicts = [{"src_ip": f.src_ip, "duration": f.duration, "total_fwd_packets": f.total_fwd_packets, "total_bwd_packets": f.total_bwd_packets, "total_length_fwd_packets": f.total_length_fwd_packets, "total_length_bwd_packets": f.total_length_bwd_packets, "flow_bytes_s": f.flow_bytes_s, "syn_flag_count": f.syn_flag_count, "rst_flag_count": f.rst_flag_count, "waf_risk": f.waf_risk, "behavior_risk": f.behavior_risk, "compliance_score": f.compliance_score, "attack_stage": f.attack_stage} for f in flows]
    fc_res = forecasting_engine.train(flow_dicts) if flow_dicts else {"status": "no_flows"}

    return {
        "status": "success",
        "waf": waf_res,
        "behavior": beh_res,
        "forecast": fc_res
    }

# 9. Live Device Scan & Real-Time Forecasting Endpoint
@app.post("/api/scan/live")
def trigger_live_device_scan():
    from backend.app.scanner import execute_live_device_scan
    return execute_live_device_scan()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
