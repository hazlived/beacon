import csv
import json
import os
from datetime import datetime
from typing import Dict, Tuple, List, Optional
from backend.app.db.database import SessionLocal
from backend.app.db.models import NetworkFlow, AuthLog, WafLog, ComplianceFinding, SessionTrust

_file_seen_signature: Dict[str, Tuple[float, int]] = {}

def parse_datetime_utc_naive(dt_str: str) -> datetime:
    """Parses datetime strings and guarantees UTC-naive datetime object per user rules."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(dt_str.strip(), fmt)
            if dt.tzinfo is not None:
                dt = datetime(*dt.utctimetuple()[:6])
            return dt
        except ValueError:
            pass
    dt = datetime.utcnow()
    return datetime(*dt.utctimetuple()[:6])

def should_skip_file(file_path: str) -> bool:
    """Tracks (st_mtime, st_size) signature to prevent duplicate file re-reads."""
    if not os.path.exists(file_path):
        return True
    stat = os.stat(file_path)
    current_sig = (stat.st_mtime, stat.st_size)
    if _file_seen_signature.get(file_path) == current_sig:
        return True
    _file_seen_signature[file_path] = current_sig
    return False

def ingest_cicids2017_csv(file_path: str, force: bool = False) -> int:
    if not force and should_skip_file(file_path):
        print(f"Skipping duplicate re-read of {file_path} (signature unchanged)")
        return 0

    session = SessionLocal()
    count = 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                dt = parse_datetime_utc_naive(row["timestamp"])
                flow = NetworkFlow(
                    src_ip=row["src_ip"],
                    dst_ip=row["dst_ip"],
                    src_port=int(row["src_port"]),
                    dst_port=int(row["dst_port"]),
                    protocol=int(row["protocol"]),
                    timestamp=dt,
                    duration=float(row["duration"]),
                    total_fwd_packets=int(row["total_fwd_packets"]),
                    total_bwd_packets=int(row["total_bwd_packets"]),
                    total_length_fwd_packets=float(row["total_length_fwd_packets"]),
                    total_length_bwd_packets=float(row["total_length_bwd_packets"]),
                    flow_bytes_s=float(row["flow_bytes_s"]),
                    flow_packets_s=float(row["flow_packets_s"]),
                    flow_iat_mean=float(row.get("flow_iat_mean", 0.0)),
                    flow_iat_std=float(row.get("flow_iat_std", 0.0)),
                    syn_flag_count=int(row.get("syn_flag_count", 0)),
                    ack_flag_count=int(row.get("ack_flag_count", 0)),
                    fin_flag_count=int(row.get("fin_flag_count", 0)),
                    rst_flag_count=int(row.get("rst_flag_count", 0)),
                    waf_risk=float(row.get("waf_risk", 0.0)),
                    behavior_risk=float(row.get("behavior_risk", 0.0)),
                    compliance_score=float(row.get("compliance_score", 1.0)),
                    attack_stage=row.get("attack_stage", "BENIGN"),
                    label=row.get("label", "BENIGN")
                )
                session.add(flow)
                count += 1
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.expunge_all()
        session.close()
    return count

def ingest_lanl_auth_csv(file_path: str, force: bool = False) -> int:
    if not force and should_skip_file(file_path):
        return 0

    session = SessionLocal()
    count = 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                login_dt = parse_datetime_utc_naive(row["login_time"])
                logout_dt = parse_datetime_utc_naive(row["logout_time"]) if row.get("logout_time") else None
                log = AuthLog(
                    user_id=row["user_id"],
                    device_id=row["device_id"],
                    ip=row["ip"],
                    resource=row.get("resource", "/"),
                    login_time=login_dt,
                    logout_time=logout_dt,
                    success=int(row["success"]),
                    auth_method=row.get("auth_method", "Password"),
                    sensitive_access=int(row.get("sensitive_access", 0))
                )
                session.add(log)
                count += 1
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.expunge_all()
        session.close()
    return count

def ingest_compliance_json(file_path: str, force: bool = False) -> int:
    if not force and should_skip_file(file_path):
        return 0

    session = SessionLocal()
    count = 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        all_findings = []
        if isinstance(data, dict):
            for k, item_list in data.items():
                if isinstance(item_list, list):
                    all_findings.extend(item_list)
        elif isinstance(data, list):
            all_findings = data

        for item in all_findings:
            finding = ComplianceFinding(
                source=item.get("source", "prowler"),
                control_id=item.get("control_id", "CIS-0.0"),
                title=item.get("title", "Compliance Warning"),
                severity=item.get("severity", "MEDIUM"),
                resource=item.get("resource", "unknown"),
                description=item.get("description", ""),
                remediation=item.get("remediation", ""),
                status=item.get("status", "OPEN"),
                nciipc_guideline=item.get("nciipc_guideline", "NCIIPC Guidelines"),
                plain_english_explanation=f"Control {item.get('control_id')}: {item.get('title')}. Risk: {item.get('description')} Fix: {item.get('remediation')}"
            )
            session.add(finding)
            count += 1
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.expunge_all()
        session.close()
    return count
