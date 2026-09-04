import json
import os
from typing import Dict, List, Any

NCIIPC_MAPPINGS = {
    "AWS-CIS-1.1": {
        "guideline": "NCIIPC-SEC-01: Identity & Access Management",
        "explanation": (
            "Root account has unrestricted privileges. Using root for daily "
            "activities increases vulnerability to credential theft and complete "
            "cloud compromise."
        ),
    },
    "AWS-CIS-2.1.1": {
        "guideline": "NCIIPC-DATA-04: Critical Data Protection & Encryption",
        "explanation": (
            "S3 bucket is publicly accessible over the Internet. Anyone can read "
            "or overwrite sensitive organization files."
        ),
    },
    "AWS-CIS-3.1": {
        "guideline": "NCIIPC-LOG-02: Centralized Logging & Audit Trails",
        "explanation": (
            "CloudTrail logging is disabled in specific regions. Attacks in "
            "unmonitored regions will go undetected."
        ),
    },
    "K8S-CIS-1.2.1": {
        "guideline": "NCIIPC-K8S-01: Perimeter Security & API Protection",
        "explanation": (
            "Kubernetes API server allows unauthenticated requests. External "
            "attackers can query or modify cluster workloads without password "
            "or token."
        ),
    },
    "K8S-CIS-4.2.1": {
        "guideline": "NCIIPC-CONT-03: Container Isolation & Hardening",
        "explanation": (
            "Pod container is running in privileged mode. If compromised, "
            "attackers gain root access to the underlying host node."
        ),
    },
}


class AutoComplianceEngine:
    def run_scan(self, target: str = "aws") -> List[Dict[str, Any]]:
        results = []
        if target.lower() in ["aws", "cloud", "prowler"]:
            results = [
                {
                    "source": "prowler",
                    "control_id": "AWS-CIS-1.1",
                    "title": "Avoid the use of root account",
                    "severity": "CRITICAL",
                    "resource": "arn:aws:iam::123456789012:root",
                    "description": (
                        "Root account credentials used recently without MFA requirement."
                    ),
                    "remediation": (
                        "Delete root access keys, require hardware MFA, and enforce IAM roles."
                    ),
                    "status": "OPEN",
                    "evidence": [
                        "Root login detected in last 7 days",
                        "No hardware MFA configured for root",
                    ],
                    "security_impact": (
                        "Full account compromise possible if root credentials are stolen."
                    ),
                    "framework": "CIS AWS Foundations Benchmark",
                    "reference": "https://docs.aws.amazon.com/security/",
                },
                {
                    "source": "prowler",
                    "control_id": "AWS-CIS-2.1.1",
                    "title": "Ensure S3 bucket policies restrict public access",
                    "severity": "HIGH",
                    "resource": "s3://corp-db-backups-bucket",
                    "description": (
                        "Bucket policy grants s3:GetObject to all Anonymous principals."
                    ),
                    "remediation": (
                        "Apply S3 Block Public Access and restrict bucket policy to VPC endpoints."
                    ),
                    "status": "OPEN",
                    "evidence": [
                        "Bucket policy allows Principal: '*'",
                        "Block Public Access disabled at bucket level",
                    ],
                    "security_impact": (
                        "Sensitive backups exposed to the public internet."
                    ),
                    "framework": "CIS AWS Foundations Benchmark",
                    "reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/",
                },
                {
                    "source": "prowler",
                    "control_id": "AWS-CIS-3.1",
                    "title": "Ensure CloudTrail is enabled across all active regions",
                    "severity": "MEDIUM",
                    "resource": "CloudTrail: ap-south-1",
                    "description": (
                        "Audit trail logging disabled in ap-south-1 (Mumbai region)."
                    ),
                    "remediation": (
                        "Enable multi-region trail logging in CloudTrail configuration."
                    ),
                    "status": "RESOLVED",
                    "evidence": [
                        "CloudTrail trail exists but is not multi-region",
                        "No logging configuration for ap-south-1",
                    ],
                    "security_impact": (
                        "Attacks in unmonitored regions may go undetected."
                    ),
                    "framework": "CIS AWS Foundations Benchmark",
                    "reference": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/",
                },
            ]
        elif target.lower() in ["k8s", "kubernetes", "kube-bench"]:
            results = [
                {
                    "source": "kube-bench",
                    "control_id": "K8S-CIS-1.2.1",
                    "title": "Ensure anonymous requests to API server are disabled",
                    "severity": "CRITICAL",
                    "resource": "kube-apiserver",
                    "description": (
                        "API server started with --anonymous-auth=true."
                    ),
                    "remediation": (
                        "Set --anonymous-auth=false in /etc/kubernetes/manifests/kube-apiserver.yaml."
                    ),
                    "status": "OPEN",
                    "evidence": [
                        "kube-apiserver --anonymous-auth=true observed",
                    ],
                    "security_impact": (
                        "Unauthenticated users can query or modify cluster resources."
                    ),
                    "framework": "CIS Kubernetes Benchmark",
                    "reference": "https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/",
                },
                {
                    "source": "kube-bench",
                    "control_id": "K8S-CIS-4.2.1",
                    "title": "Minimize privileged container deployments",
                    "severity": "HIGH",
                    "resource": "pod/monitoring-agent-priv",
                    "description": (
                        "Pod securityContext allows securityContext.privileged=true."
                    ),
                    "remediation": (
                        "Set securityContext.privileged=false and specify required capabilities explicitly."
                    ),
                    "status": "OPEN",
                    "evidence": [
                        "Pod spec contains securityContext.privileged: true",
                    ],
                    "security_impact": (
                        "Compromised container may escape to the host node."
                    ),
                    "framework": "CIS Kubernetes Benchmark",
                    "reference": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                },
            ]

        enriched = []
        for r in results:
            cid = r["control_id"]
            nciipc_info = NCIIPC_MAPPINGS.get(cid, {
                "guideline": "NCIIPC Guidelines - Security Best Practices",
                "explanation": (
                    f"Security finding for control {cid}. Remediation required to comply with NCII directives."
                ),
            })
            r["nciipc_guideline"] = nciipc_info["guideline"]
            r["plain_english_explanation"] = (
                f"[{r['severity']}] {nciipc_info['explanation']} Fix: {r['remediation']}"
            )
            enriched.append(r)

        return enriched


compliance_engine = AutoComplianceEngine()
