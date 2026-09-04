from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.app.db.database import SessionLocal
from backend.app.db.models import Incident, IncidentEvent


def create_incident(
    user_id: str,
    session_id: str,
    severity: str,
    attack_stage: str,
    trust_score: float,
    policy_action: str,
    correlation: Dict[str, Any],
    events: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        incident = Incident(
            user_id=user_id,
            session_id=session_id,
            severity=severity,
            attack_stage=attack_stage,
            trust_score=trust_score,
            policy_action=policy_action,
            overall_risk=correlation["overall_risk"],
            confidence=correlation["signal_agreement"],
            status="OPEN",
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        # Default events if none provided
        if events is None:
            events = [
                {
                    "event_type": "CORRELATION",
                    "description": (
                        f"Overall risk {incident.overall_risk}, "
                        f"confidence {incident.confidence}, severity {incident.severity}"
                    ),
                    "severity": severity,
                },
                {
                    "event_type": "TRUST_DECISION",
                    "description": (
                        f"Trust score {incident.trust_score}, "
                        f"policy action {incident.policy_action}"
                    ),
                    "severity": severity,
                },
            ]

        for ev in events:
            event = IncidentEvent(
                incident_id=incident.id,
                event_type=ev["event_type"],
                description=ev["description"],
                severity=ev["severity"],
            )
            db.add(event)

        db.commit()

        return {
            "incident_id": f"INC-{incident.id}",
            "severity": severity,
            "attack_stage": attack_stage,
            "trust_score": trust_score,
            "policy_action": policy_action,
            "correlation": correlation,
        }
    finally:
        db.expunge_all()
        db.close()
