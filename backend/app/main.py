import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, Depends, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import json

load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.identity import compute_identity_trust
from backend.app.identity.keys import generate_challenge, generate_demo_user_keypair, sign_challenge, _load_user_keys
from backend.app.db.database import SessionLocal, Base, engine
from backend.app.db.models import (
    NetworkFlow, AuthLog, WafLog, ComplianceFinding,
    SessionTrust, AttackSequence, Incident, IncidentEvent, AuditEvent
)
from backend.app.ml.waf import waf_engine
from backend.app.ml.behavior import insider_engine
from backend.app.ml.forecast import forecasting_engine
from backend.app.ml.trust import compute_trust_score
from backend.app.ml.compliance import compliance_engine
from backend.app.ml.correlation import correlate_risks
from backend.app.incidents import create_incident

ADMIN_API_KEY = os.getenv("BEACON_API_KEY", "")
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(BASE_DIR, "soc_beacon.db")

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SIH26153 AI-Based Network Attack Forecasting Mini-SOC Backend API",
    description=(
        "Backend services for Smart WAF, Agentless Compliance, Insider Threat "
        "Engine, Attack Forecasting, and Continuous Trust Engine."
    ),
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.expunge_all()
        db.close()


def verify_admin_key(x_api_key: str = Header(None, alias="X-API-Key")):
    if not ADMIN_API_KEY:
        return
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return x_api_key


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
    network_risk: float = 0.0


# ---------------- Overview & Network ----------------

@app.get("/api/overview/stats")
def get_overview_stats(db=Depends(get_db)):
    total_flows = db.query(NetworkFlow).count()
    attacks_detected = db.query(NetworkFlow).filter(NetworkFlow.attack_stage != "BENIGN").count()
    open_compliance = db.query(ComplianceFinding).filter(ComplianceFinding.status == "OPEN").count()
    total_auth_logs = db.query(AuthLog).count()

    trust_rows = db.query(SessionTrust).all()
    trust_values = [t.trust_score for t in trust_rows] if trust_rows else [1.0]

    high_trust = sum(1 for t in trust_values if t >= 0.8)
    medium_trust = sum(1 for t in trust_values if 0.5 <= t < 0.8)
    low_trust = sum(1 for t in trust_values if t < 0.5)

    recent_flows = db.query(NetworkFlow).order_by(NetworkFlow.timestamp.desc()).limit(6).all()
    feed = [
        {
            "id": f.id,
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "stage": f.attack_stage,
            "label": f.label,
            "timestamp": str(f.timestamp),
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
            "low_trust_sessions": low_trust,
        },
        "recent_live_feed": feed,
    }


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
                "session_id": f.session_id,
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
                "label": f.label,
            }
            for f in flows
        ],
    }


# ---------------- WAF ----------------

@app.post("/api/waf/evaluate")
def evaluate_waf_request(req: WafEvaluationRequest, db=Depends(get_db)):
    result = waf_engine.evaluate_request(req.method, req.path, req.query, req.headers, req.body)

    waf_log = WafLog(
        method=req.method,
        path=req.path,
        query=req.query,
        headers=req.headers,
        body=req.body,
        malicious_score=result["malicious_score"],
        label=result["label"],
        attack_type=result["attack_type"],
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
            "created_at": str(l.created_at),
        }
        for l in logs
    ]


# ---------------- Behavior ----------------

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
            "sensitive_access": l.sensitive_access,
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
            "sensitive_access": l.sensitive_access,
        })

    rankings = []
    for uid, ulogs in user_logs_map.items():
        prof = insider_engine.compute_behavior_risk(uid, ulogs)
        rankings.append(prof)

    rankings.sort(key=lambda x: x["behavior_risk"], reverse=True)
    return rankings


# ---------------- Forecast ----------------

@app.get("/api/forecast/evaluate")
def get_forecast_evaluation(session_id: str = "SESS_001", db=Depends(get_db)):
    flows = (
        db.query(NetworkFlow)
        .filter(NetworkFlow.session_id == session_id)
        .order_by(NetworkFlow.timestamp.asc())
        .limit(20)
        .all()
    )

    if not flows:
        flows = (
            db.query(NetworkFlow)
            .order_by(NetworkFlow.timestamp.desc())
            .limit(20)
            .all()
        )

    if not flows:
        return {
            "current_stage": "BENIGN",
            "likely_next_stage": "RECON",
            "escalation_risk": 0.05,
            "confidence": 0.85,
            "att_ck_mapping": "Normal operational behavior",
            "probs": {"BENIGN": 0.85, "RECON": 0.10, "INITIAL_ACCESS": 0.03, "CREDENTIAL_ACCESS": 0.01, "LATERAL_MOVEMENT": 0.005, "IMPACT": 0.005},
            "session_id": session_id,
        }

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
            "attack_stage": f.attack_stage,
        }
        for f in flows
    ]

    res = forecasting_engine.forecast_session(flow_dicts)
    res["session_id"] = session_id
    return res


# ---------------- Compliance ----------------

@app.get("/api/compliance/findings")
def get_compliance_findings(source: Optional[str] = None, db=Depends(get_db)):
    query = db.query(ComplianceFinding)
    if source:
        query = query.filter(ComplianceFinding.source == source)
    findings = query.all()

    if not findings:
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
                plain_english_explanation=f["plain_english_explanation"],
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
            "plain_english_explanation": f.plain_english_explanation,
        }
        for f in findings
    ]


# ---------------- Trust ----------------

@app.post("/api/trust/score")
def evaluate_trust_score(req: TrustEvaluationRequest, db=Depends(get_db)):
    result = compute_trust_score(
        identity_trust=req.identity_trust,
        waf_risk=req.waf_risk,
        behavior_risk=req.behavior_risk,
        forecast_risk=req.forecast_risk,
        compliance_score=req.compliance_score,
        network_risk=req.network_risk,
    )

    audit = AuditEvent(
        actor="api",
        action="trust_decision",
        details=json.dumps({
            "session_id": req.session_id,
            "user_id": req.user_id,
            "trust_score": result["trust_score"],
            "policy_action": result["policy_action"],
            "overall_risk": result["overall_risk"],
        }),
    )
    db.add(audit)
    db.commit()

    return result


# ---------------- System ingest & train ----------------

@app.post("/api/system/ingest")
def trigger_system_ingest(_: str = Depends(verify_admin_key)):
    from backend.app.ingest import ingest_cicids2017_csv, ingest_lanl_auth_csv, ingest_compliance_json
    c1 = ingest_cicids2017_csv("data/cicids2017_sample.csv", force=True)
    c2 = ingest_lanl_auth_csv("data/lanl_auth_sample.csv", force=True)
    c3 = ingest_compliance_json("data/compliance_benchmarks.json", force=True)
    return {
        "status": "success",
        "flows_ingested": c1,
        "auth_logs_ingested": c2,
        "compliance_findings_ingested": c3,
    }


@app.post("/api/system/train")
def trigger_system_train(db=Depends(get_db), _: str = Depends(verify_admin_key)):
    import csv
    payloads = []
    if os.path.exists("data/http_waf_payloads.csv"):
        with open("data/http_waf_payloads.csv", "r", encoding="utf-8") as f:
            payloads = list(csv.DictReader(f))
    waf_res = waf_engine.train(payloads) if payloads else {"status": "no_payloads"}

    logs = db.query(AuthLog).all()
    log_dicts = [
        {
            "user_id": l.user_id,
            "device_id": l.device_id,
            "ip": l.ip,
            "resource": l.resource,
            "login_time": l.login_time,
            "success": l.success,
            "sensitive_access": l.sensitive_access,
        }
        for l in logs
    ]
    beh_res = insider_engine.train(log_dicts) if log_dicts else {"status": "no_logs"}

    flows = db.query(NetworkFlow).all()
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
            "attack_stage": f.attack_stage,
        }
        for f in flows
    ]
    fc_res = forecasting_engine.train(flow_dicts) if flow_dicts else {"status": "no_flows"}

    return {
        "status": "success",
        "waf": waf_res,
        "behavior": beh_res,
        "forecast": fc_res,
    }


# ---------------- Live scan ----------------

@app.post("/api/scan/live")
def trigger_live_device_scan(_: str = Depends(verify_admin_key)):
    from backend.app.scanner import execute_live_device_scan
    return execute_live_device_scan()


# ---------------- Demo scenario ----------------

@app.post("/api/scenarios/execute")
def execute_demo_scenario(db=Depends(get_db), _: str = Depends(verify_admin_key)):
    """
    Executes a realistic attack scenario by:
      - generating auth events → behavior_risk
      - sending a malicious HTTP request → waf_risk
      - creating network flows → network_risk
      - running forecast on the session → forecast_risk
      - computing identity_trust via identity module
      - correlating all signals → overall_risk, severity, action
      - computing trust → policy
      - creating an incident with a real event timeline
    """

    demo_user = "USER_DEMO_104"
    demo_device = "DEV_WORKSTATION_DEMO"
    demo_ip = "10.0.4.99"
    demo_session = "DEMO-SESSION-001"

    # 1. Behavior risk from synthetic auth logs
    demo_auth_logs = [
        {
            "user_id": demo_user,
            "device_id": demo_device,
            "ip": demo_ip,
            "resource": "/api/v1/auth",
            "login_time": datetime.utcnow(),
            "success": 0,
            "sensitive_access": 0,
        },
        {
            "user_id": demo_user,
            "device_id": demo_device,
            "ip": demo_ip,
            "resource": "/api/v1/auth",
            "login_time": datetime.utcnow(),
            "success": 0,
            "sensitive_access": 0,
        },
        {
            "user_id": demo_user,
            "device_id": demo_device,
            "ip": demo_ip,
            "resource": "/admin/db_backup",
            "login_time": datetime.utcnow(),
            "success": 1,
            "sensitive_access": 1,
        },
    ]

    behavior_prof = insider_engine.compute_behavior_risk(demo_user, demo_auth_logs)
    behavior_risk = behavior_prof["behavior_risk"]

    # 2. WAF risk from a malicious HTTP request
    waf_res = waf_engine.evaluate_request(
        method="POST",
        path="/api/login",
        query="",
        headers="",
        body="username=admin' OR '1'='1&password=x",
    )
    waf_risk = waf_res["malicious_score"]

    # 3. Create network flows for this session
    demo_flows_data = [
        {
            "session_id": demo_session,
            "src_ip": demo_ip,
            "dst_ip": "172.16.0.20",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": 6,
            "duration": 1.2,
            "total_fwd_packets": 45,
            "total_bwd_packets": 30,
            "total_length_fwd_packets": 5400.0,
            "total_length_bwd_packets": 3600.0,
            "flow_bytes_s": 5400.0,
            "flow_packets_s": 50.0,
            "flow_iat_mean": 0.02,
            "flow_iat_std": 0.01,
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "attack_stage": "INITIAL_ACCESS",
            "label": "Web Attack - SQL Injection",
        },
        {
            "session_id": demo_session,
            "src_ip": demo_ip,
            "dst_ip": "172.16.0.20",
            "src_port": 54322,
            "dst_port": 22,
            "protocol": 6,
            "duration": 3.5,
            "total_fwd_packets": 120,
            "total_bwd_packets": 80,
            "total_length_fwd_packets": 12000.0,
            "total_length_bwd_packets": 8000.0,
            "flow_bytes_s": 8000.0,
            "flow_packets_s": 80.0,
            "flow_iat_mean": 0.04,
            "flow_iat_std": 0.02,
            "syn_flag_count": 2,
            "rst_flag_count": 0,
            "attack_stage": "CREDENTIAL_ACCESS",
            "label": "SSH-Patator",
        },
    ]

    flows_for_session: List[NetworkFlow] = []
    for fd in demo_flows_data:
        flow = NetworkFlow(
            session_id=fd["session_id"],
            src_ip=fd["src_ip"],
            dst_ip=fd["dst_ip"],
            src_port=fd["src_port"],
            dst_port=fd["dst_port"],
            protocol=fd["protocol"],
            timestamp=datetime.utcnow(),
            duration=fd["duration"],
            total_fwd_packets=fd["total_fwd_packets"],
            total_bwd_packets=fd["total_bwd_packets"],
            total_length_fwd_packets=fd["total_length_fwd_packets"],
            total_length_bwd_packets=fd["total_length_bwd_packets"],
            flow_bytes_s=fd["flow_bytes_s"],
            flow_packets_s=fd["flow_packets_s"],
            flow_iat_mean=fd["flow_iat_mean"],
            flow_iat_std=fd["flow_iat_std"],
            syn_flag_count=fd["syn_flag_count"],
            rst_flag_count=fd["rst_flag_count"],
            waf_risk=waf_risk,
            behavior_risk=behavior_risk,
            compliance_score=0.85,
            attack_stage=fd["attack_stage"],
            label=fd["label"],
        )
        db.add(flow)
        flows_for_session.append(flow)

    db.commit()

    # 4. Compute network_risk from flows (simple heuristic)
    syn_count = sum(f.syn_flag_count for f in flows_for_session)
    bytes_s = sum(f.flow_bytes_s for f in flows_for_session) / max(len(flows_for_session), 1)
    has_attack = any(f.attack_stage != "BENIGN" for f in flows_for_session)

    network_risk = min(
        1.0,
        (0.4 * (syn_count / max(len(flows_for_session), 1)))
        + (0.3 * (bytes_s / 10000.0))
        + (0.3 * (1.0 if has_attack else 0.0))
    )

    # 5. Forecast risk from the same session
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
            "attack_stage": f.attack_stage,
        }
        for f in flows_for_session
    ]

    forecast_res = forecasting_engine.forecast_session(flow_dicts)
    forecast_risk = forecast_res["escalation_risk"]

    # 6. Identity trust via Ed25519 (demo: generate keypair and sign challenge)
    if demo_user not in _load_user_keys():
        generate_demo_user_keypair(demo_user)

    challenge = generate_challenge()
    signature_b64 = sign_challenge(demo_user, challenge)

    identity_info = compute_identity_trust(
        user_id=demo_user,
        challenge=challenge,
        signature_b64=signature_b64,
        use_ed25519=True,
    )
    identity_trust = identity_info["identity_trust"]

    # 7. Compliance (demo value; can be enriched later)
    compliance_score = 0.70

    # 8. Correlation
    correlation = correlate_risks(
        identity_trust=identity_trust,
        waf_risk=waf_risk,
        behavior_risk=behavior_risk,
        network_risk=network_risk,
        forecast_risk=forecast_risk,
        compliance_score=compliance_score,
    )

    # 9. Trust
    trust_result = compute_trust_score(
        identity_trust=identity_trust,
        waf_risk=waf_risk,
        behavior_risk=behavior_risk,
        forecast_risk=forecast_risk,
        compliance_score=compliance_score,
        network_risk=network_risk,
    )

    # 10. Build a real event timeline
    events = [
        {
            "event_type": "AUTH",
            "description": (
                f"Multiple failed logins for {demo_user}, "
                "followed by sensitive access attempt."
            ),
            "severity": correlation["severity"],
        },
        {
            "event_type": "WAF",
            "description": (
                f"Malicious HTTP request detected: {waf_res['attack_type']} "
                f"(score {waf_res['malicious_score']})."
            ),
            "severity": correlation["severity"],
        },
        {
            "event_type": "NETWORK",
            "description": (
                f"Risky network activity in session {demo_session} "
                f"(SYN count {syn_count}, avg bytes/s {bytes_s:.1f})."
            ),
            "severity": correlation["severity"],
        },
        {
            "event_type": "FORECAST",
            "description": (
                f"Predicted next stage: {forecast_res['likely_next_stage']} "
                f"(escalation risk {forecast_res['escalation_risk']}, "
                f"model confidence {forecast_res['confidence']})."
            ),
            "severity": correlation["severity"],
        },
        {
            "event_type": "IDENTITY",
            "description": (
                f"Identity verification: device_known={identity_info['device_known']}, "
                f"mfa_used={identity_info['mfa_used']}, "
                f"identity_trust={identity_info['identity_trust']}."
            ),
            "severity": correlation["severity"],
        },
        {
            "event_type": "CORRELATION",
            "description": (
                f"Overall risk {correlation['overall_risk']}, "
                f"signal agreement {correlation['signal_agreement']}, "
                f"severity {correlation['severity']}."
            ),
            "severity": correlation["severity"],
        },
        {
            "event_type": "TRUST_DECISION",
            "description": (
                f"Trust score {trust_result['trust_score']}, "
                f"policy action {trust_result['policy_action']}."
            ),
            "severity": correlation["severity"],
        },
    ]

    incident = create_incident(
        user_id=demo_user,
        session_id=demo_session,
        severity=correlation["severity"],
        attack_stage="CREDENTIAL_ACCESS",
        trust_score=trust_result["trust_score"],
        policy_action=trust_result["policy_action"],
        correlation=correlation,
        events=events,
    )

    return {
        "mode": "DEMO",
        "incident": incident,
        "trust": trust_result,
        "correlation": correlation,
        "forecast": forecast_res,
        "behavior_risk": behavior_risk,
        "waf_risk": waf_risk,
        "network_risk": network_risk,
        "forecast_risk": forecast_risk,
        "identity": identity_info,
    }


# ---------------- Incidents ----------------

@app.get("/api/incidents")
def list_incidents(db=Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(20).all()
    return [
        {
            "incident_id": f"INC-{i.id}",
            "user_id": i.user_id,
            "session_id": i.session_id,
            "severity": i.severity,
            "attack_stage": i.attack_stage,
            "trust_score": i.trust_score,
            "policy_action": i.policy_action,
            "overall_risk": i.overall_risk,
            "confidence": i.confidence,
            "status": i.status,
            "created_at": str(i.created_at),
        }
        for i in incidents
    ]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int, db=Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "incident_id": f"INC-{incident.id}",
        "user_id": incident.user_id,
        "session_id": incident.session_id,
        "severity": incident.severity,
        "attack_stage": incident.attack_stage,
        "trust_score": incident.trust_score,
        "policy_action": incident.policy_action,
        "overall_risk": incident.overall_risk,
        "confidence": incident.confidence,
        "status": incident.status,
        "created_at": str(incident.created_at),
    }


@app.get("/api/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: int, db=Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    events = (
        db.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.timestamp.asc())
        .all()
    )

    timeline = [
        {
            "event_type": e.event_type,
            "description": e.description,
            "severity": e.severity,
            "timestamp": str(e.timestamp),
        }
        for e in events
    ]

    return {
        "incident_id": f"INC-{incident.id}",
        "timeline": timeline,
    }


# ---------------- ML metrics ----------------

@app.get("/api/ml/metrics")
def get_ml_metrics():
    return {
        "waf": waf_engine.get_metrics(),
        "forecast": forecasting_engine.get_metrics(),
        "behavior": insider_engine.eval_metrics or {"status": "no_evaluation_yet"},
    }

@app.post("/api/identity/challenge")
def identity_challenge():
    from backend.app.identity.keys import generate_challenge
    challenge = generate_challenge()
    # For demo, just return challenge. In production, bind to user + expiry.
    return {"challenge": challenge}


@app.post("/api/identity/verify")
def identity_verify(
    user_id: str,
    challenge: str,
    signature_b64: str,
):
    from backend.app.identity.keys import compute_identity_trust
    result = compute_identity_trust(
        user_id=user_id,
        challenge=challenge,
        signature_b64=signature_b64,
        use_ed25519=True,
    )
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
