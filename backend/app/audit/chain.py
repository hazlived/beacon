import hashlib
from typing import List, Dict, Any
from backend.app.db.database import SessionLocal
from backend.app.db.models import AuditEvent


def _hash_payload(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_audit_chain() -> Dict[str, Any]:
    """
    Verifies the tamper-evident audit chain:
    previous_hash of event N == event_hash of event N-1.
    Returns verification result and details.
    """
    db = SessionLocal()
    try:
        events = db.query(AuditEvent).order_by(AuditEvent.timestamp).all()
        if len(events) == 0:
            return {"valid": True, "message": "No audit events to verify."}

        prev_hash = None
        broken_at = None

        for e in events:
            if e.previous_hash != prev_hash:
                broken_at = e.id
                break
            # Recompute event_hash from details + timestamp as simple payload
            payload = f"{e.actor}|{e.action}|{e.details}|{e.timestamp}"
            expected_hash = _hash_payload(payload)
            if e.event_hash is not None and e.event_hash != expected_hash:
                broken_at = e.id
                break
            prev_hash = expected_hash

        if broken_at is None:
            return {"valid": True, "message": "Audit chain is intact."}
        else:
            return {
                "valid": False,
                "message": f"Audit chain broken at event id {broken_at}.",
                "broken_at": broken_at,
            }
    finally:
        db.expunge_all()
        db.close()
