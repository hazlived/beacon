from typing import Dict, Any
from backend.app.ml.correlation import correlate_risks


def compute_trust_score(
    identity_trust: float = 1.0,
    waf_risk: float = 0.0,
    behavior_risk: float = 0.0,
    forecast_risk: float = 0.0,
    compliance_score: float = 1.0,
    network_risk: float = 0.0,
) -> Dict[str, Any]:
    correlation = correlate_risks(
        identity_trust=identity_trust,
        waf_risk=waf_risk,
        behavior_risk=behavior_risk,
        network_risk=network_risk,
        forecast_risk=forecast_risk,
        compliance_score=compliance_score,
    )

    final_trust = max(0.0, min(1.0, 1.0 - correlation["overall_risk"]))

    action = correlation["action"]
    if action == "CONTAINMENT":
        description = (
            "Session terminated & host isolated: High escalation threat. "
            "Escalated to SOC analysts."
        )
    elif action == "RESTRICTED_ACCESS":
        description = (
            "Restricted access: Step-up MFA required, write operations blocked "
            "on sensitive resources."
        )
    else:
        description = (
            "Unrestricted access granted. Standard telemetry monitoring."
        )

    return {
        "identity_trust": round(identity_trust, 4),
        "waf_risk": round(waf_risk, 4),
        "behavior_risk": round(behavior_risk, 4),
        "forecast_risk": round(forecast_risk, 4),
        "compliance_score": round(compliance_score, 4),
        "network_risk": round(network_risk, 4),
        "trust_score": round(final_trust, 4),
        "policy_action": action,
        "policy_description": description,
        "overall_risk": correlation["overall_risk"],
        "signal_agreement": correlation["signal_agreement"],
        "severity": correlation["severity"],
        "reasons": correlation["reasons"],
        "signal_breakdown": correlation["signal_breakdown"],
    }
