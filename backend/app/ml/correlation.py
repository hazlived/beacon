from typing import Dict, Any, List


def correlate_risks(
    identity_trust: float,
    waf_risk: float,
    behavior_risk: float,
    network_risk: float,
    forecast_risk: float,
    compliance_score: float,
) -> Dict[str, Any]:
    identity_risk = 1.0 - identity_trust
    compliance_risk = 1.0 - compliance_score

    weights = {
        "waf": 0.20,
        "behavior": 0.20,
        "network": 0.20,
        "forecast": 0.20,
        "identity": 0.15,
        "compliance": 0.05,
    }

    overall_risk = (
        weights["waf"] * waf_risk
        + weights["behavior"] * behavior_risk
        + weights["network"] * network_risk
        + weights["forecast"] * forecast_risk
        + weights["identity"] * identity_risk
        + weights["compliance"] * compliance_risk
    )

    signals = [waf_risk, behavior_risk, network_risk, forecast_risk]
    mean_signal = sum(signals) / len(signals)
    variance = sum((s - mean_signal) ** 2 for s in signals) / len(signals)
    signal_agreement = max(0.0, min(1.0, 1.0 - variance))

    if overall_risk >= 0.75:
        severity = "CRITICAL"
        action = "CONTAINMENT"
    elif overall_risk >= 0.50:
        severity = "HIGH"
        action = "RESTRICTED_ACCESS"
    else:
        severity = "MEDIUM"
        action = "FULL_ACCESS"

    reasons: List[str] = []
    if waf_risk >= 0.7:
        reasons.append("High WAF risk")
    if behavior_risk >= 0.7:
        reasons.append("Abnormal user behavior")
    if network_risk >= 0.7:
        reasons.append("Risky network activity")
    if forecast_risk >= 0.7:
        reasons.append("Attack escalation predicted")
    if identity_risk >= 0.6:
        reasons.append("Unverified or risky identity")
    if compliance_risk >= 0.6:
        reasons.append("Significant compliance weaknesses")

    return {
        "overall_risk": round(overall_risk, 2),
        "signal_agreement": round(signal_agreement, 2),
        "severity": severity,
        "action": action,
        "reasons": reasons,
        "signal_breakdown": {
            "waf": round(waf_risk, 4),
            "behavior": round(behavior_risk, 4),
            "network": round(network_risk, 4),
            "forecast": round(forecast_risk, 4),
            "identity": round(identity_risk, 4),
            "compliance": round(compliance_risk, 4),
        },
    }
