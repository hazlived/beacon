from typing import Dict, Any

def compute_trust_score(
    identity_trust: float = 1.0,
    waf_risk: float = 0.0,
    behavior_risk: float = 0.0,
    forecast_risk: float = 0.0,
    compliance_score: float = 1.0
) -> Dict[str, Any]:
    """
    Continuous Trust Engine formula fusing identity, WAF, behavior, forecast, and compliance scores.
    """
    raw_trust = (
        0.25 * identity_trust +
        0.25 * (1.0 - waf_risk) +
        0.25 * (1.0 - behavior_risk) +
        0.25 * (1.0 - forecast_risk)
    )
    
    # Cap trust if critical compliance issues exist
    if compliance_score < 0.6:
        raw_trust = min(raw_trust, 0.70)
        
    final_trust = max(0.0, min(1.0, raw_trust))

    if final_trust >= 0.80:
        action = "FULL_ACCESS"
        description = "Unrestricted access granted. Standard telemetry monitoring."
    elif final_trust >= 0.50:
        action = "RESTRICTED_ACCESS"
        description = "Restricted access: Step-up MFA required, write operations blocked on sensitive resources."
    else:
        action = "CONTAINMENT"
        description = "Session terminated & host isolated: High escalation threat. Escalated to SOC analysts."

    return {
        "identity_trust": round(identity_trust, 4),
        "waf_risk": round(waf_risk, 4),
        "behavior_risk": round(behavior_risk, 4),
        "forecast_risk": round(forecast_risk, 4),
        "compliance_score": round(compliance_score, 4),
        "trust_score": round(final_trust, 4),
        "policy_action": action,
        "policy_description": description
    }
