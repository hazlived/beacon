from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.db.database import Base

class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(Integer)
    timestamp = Column(DateTime, index=True)
    duration = Column(Float)
    total_fwd_packets = Column(Integer)
    total_bwd_packets = Column(Integer)
    total_length_fwd_packets = Column(Float)
    total_length_bwd_packets = Column(Float)
    flow_bytes_s = Column(Float)
    flow_packets_s = Column(Float)
    flow_iat_mean = Column(Float)
    flow_iat_std = Column(Float)
    syn_flag_count = Column(Integer)
    ack_flag_count = Column(Integer)
    fin_flag_count = Column(Integer)
    rst_flag_count = Column(Integer)
    waf_risk = Column(Float, default=0.0)
    behavior_risk = Column(Float, default=0.0)
    compliance_score = Column(Float, default=1.0)
    attack_stage = Column(String(50), default="BENIGN", index=True)
    label = Column(String(100), default="BENIGN")

class AuthLog(Base):
    __tablename__ = "auth_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), index=True)
    device_id = Column(String(100), index=True)
    ip = Column(String(45), index=True)
    resource = Column(String(255))
    login_time = Column(DateTime, index=True)
    logout_time = Column(DateTime, nullable=True)
    success = Column(Integer, default=1)
    auth_method = Column(String(50))
    sensitive_access = Column(Integer, default=0)

class WafLog(Base):
    __tablename__ = "waf_logs"

    id = Column(Integer, primary_key=True, index=True)
    method = Column(String(10))
    path = Column(String(255))
    query = Column(Text, nullable=True)
    headers = Column(Text, nullable=True)
    body = Column(Text, nullable=True)
    malicious_score = Column(Float)
    label = Column(Integer)
    attack_type = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class ComplianceFinding(Base):
    __tablename__ = "compliance_findings"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(50), index=True)
    control_id = Column(String(50), index=True)
    title = Column(String(255))
    severity = Column(String(20), index=True)
    resource = Column(String(255))
    description = Column(Text)
    remediation = Column(Text)
    status = Column(String(20), default="OPEN", index=True)
    nciipc_guideline = Column(String(255))
    plain_english_explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SessionTrust(Base):
    __tablename__ = "session_trusts"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), unique=True, index=True)
    user_id = Column(String(100), index=True)
    identity_trust = Column(Float, default=1.0)
    waf_risk = Column(Float, default=0.0)
    behavior_risk = Column(Float, default=0.0)
    forecast_risk = Column(Float, default=0.0)
    compliance_score = Column(Float, default=1.0)
    trust_score = Column(Float, default=1.0)
    policy_action = Column(String(50), default="FULL_ACCESS")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AttackSequence(Base):
    __tablename__ = "attack_sequences"

    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(String(100), index=True)
    session_id = Column(String(100), index=True)
    flow_sequence_json = Column(Text)
    current_stage = Column(String(50))
    predicted_next_stage = Column(String(50))
    escalation_risk = Column(Float)
    confidence = Column(Float)
    updated_at = Column(DateTime, default=datetime.utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), index=True)
    session_id = Column(String(100), index=True)
    severity = Column(String(20), index=True)
    attack_stage = Column(String(50))
    trust_score = Column(Float)
    policy_action = Column(String(50))
    overall_risk = Column(Float)
    confidence = Column(Float)
    status = Column(String(20), default="OPEN")
    created_at = Column(DateTime, default=datetime.utcnow)


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    event_type = Column(String(50))
    description = Column(Text)
    severity = Column(String(20))
    timestamp = Column(DateTime, default=datetime.utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String(100), default="system")
    action = Column(String(100), index=True)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Tamper-evident audit chain fields (optional but recommended)
    event_hash = Column(String(255), nullable=True)
    previous_hash = Column(String(255), nullable=True)
