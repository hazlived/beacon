# BEACON SOC — AI Network Attack Forecasting & Behavioral Security Platform

[![Python](https://img.shields.io/badge/Python-3.11+-E6D5B8?style=flat-square&logo=python&logoColor=0A0908)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-D4C5A9?style=flat-square&logo=fastapi&logoColor=0A0908)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-D4B982?style=flat-square&logo=pytorch&logoColor=0A0908)](https://pytorch.org)
[![React](https://img.shields.io/badge/React-18+-F8F5EE?style=flat-square&logo=react&logoColor=0A0908)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-A8A092?style=flat-square)](LICENSE)

BEACON SOC is an enterprise-grade AI-driven Security Operations Center (SOC) designed for real-time network attack forecasting, insider threat behavioral modeling, smart WAF payload classification, agentless compliance auditing, Ed25519 cryptographic identity verification, tamper-evident audit logging, and continuous Zero Trust policy evaluation.

---

## Executive Overview

BEACON SOC combines machine learning sequence modeling, heterogeneous graph analysis, natural language processing, asymmetric cryptography, and multi-signal risk correlation into a unified threat prevention platform.

### Core Architecture & Analytics Layer

1. **AI Network Attack Forecasting Engine (`backend/app/ml/forecast.py`)**
   - **Architecture**: PyTorch Dual-Head LSTM Temporal Sequence Model.
   - **Sequence Ingestion**: Processes temporal sequences of flow records (~80 features aligned with CIC-IDS2017/UNSW-NB15/DAPT2020).
   - **Output Heads**:
     - `fc_stage`: Predicts current and next MITRE ATT&CK attack stage (`RECON`, `INITIAL_ACCESS`, `CREDENTIAL_ACCESS`, `LATERAL_MOVEMENT`, `IMPACT`, `BENIGN`).
     - `fc_risk`: Regression head estimating escalation risk probability in `[0, 1]`.

2. **Smart WAF Engine (`backend/app/ml/waf.py`)**
   - **Architecture**: Character sub-word TF-IDF vectorizer + Logistic Regression text classification pipeline with heuristic fallback.
   - **Input Serialization**: Serializes HTTP snapshots (`method || path || query || headers || body`).
   - **Classifications**: Classifies payloads into SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, Command Injection, Brute Force, and BENIGN traffic.

3. **Insider Threat & Graph Behavioral Engine (`backend/app/ml/behavior.py`)**
   - **Architecture**: NetworkX Heterogeneous Relational Graph + Isolation Forest Anomaly Detector.
   - **Graph Entities**: Nodes (`Users`, `Devices`, `Resources`, `IPs`) and Edges (`User -> Device`, `User -> Resource`, `Device -> Device`).
   - **Anomaly Indicators**: Detects multi-device sprawl, off-hours activity, failed login spikes, and sensitive resource access. Model performance is validated via `eval_behavior.py`.

4. **Multi-Signal Risk Correlation & Continuous Trust Engine (`backend/app/ml/correlation.py` & `trust.py`)**
   - **Weighted Risk Correlation Formula**:
     ```
     Overall_Risk = 0.20 * WAF + 0.20 * Behavior + 0.20 * Network + 0.20 * Forecast + 0.15 * Identity_Risk + 0.05 * Compliance_Risk
     ```
   - **Dynamic Enforcement Actions**:
     - **Trust >= 0.8**: `FULL_ACCESS` (Unrestricted access)
     - **0.5 <= Trust < 0.8**: `RESTRICTED_ACCESS` (Step-up MFA required, write operations blocked)
     - **Trust < 0.5**: `CONTAINMENT` (Session termination & host isolation)

5. **Ed25519 Asymmetric Cryptographic Identity (`backend/app/identity/keys.py`)**
   - Implements challenge-response authentication using Ed25519 public-key signature verification for passwordless identity trust computation.

6. **Tamper-Evident SHA-256 Audit Chain (`backend/app/audit/chain.py`)**
   - Maintains a cryptographic hash chain (`previous_hash` & `event_hash`) across security audit events to guarantee audit trail non-repudiation.

7. **Agentless Compliance Engine (`backend/app/ml/compliance.py`)**
   - Parses AWS Prowler cloud audits and Kubernetes kube-bench CIS benchmarks. Generates plain-English security remediation guidance mapped to NCIIPC protection directives.

8. **Live Device Security Scanner (`backend/app/scanner.py`)**
   - Performs real-time host inspection (sockets, listening ports, process metrics) and runs live PyTorch attack sequence forecasting on active local connections.

9. **Attack Analysis Pipeline & Heatmap UI (`frontend/src/components/`)**
   - Interactive 7-step analysis pipeline visualization (`AttackAnalysisPipeline.jsx`) and MITRE ATT&CK prediction matrix heatmap (`AttackHeatmap.jsx`).

---

## Technical Prerequisites

Before setting up BEACON SOC, ensure the following software is installed on your environment:

- **Python**: Version 3.11 or higher
- **Node.js**: Version 18.0 or higher
- **npm**: Version 9.0 or higher
- **Git**: Version 2.30 or higher
- **Docker & Docker Compose** (Optional, for containerized deployment)

---

## Installation & Environment Setup

Follow these step-by-step instructions to install and configure BEACON SOC:

### Step 1: Clone Repository

```bash
git clone https://github.com/hazlived/beacon.git
cd beacon
```

### Step 2: Set Up Python Backend Environment

#### Linux / macOS
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Step 3: Set Up React Frontend Environment

```bash
cd frontend
npm install
cd ..
```

### Step 4: Generate Datasets & Initialize ML Models

Initialize the SQLite database, generate sample datasets with synthetic session IDs, and train all machine learning models:

```bash
# Generate synthetic dataset files
python scripts/generate_sample_data.py

# Initialize database schemas
python -m backend.app.cli.soc init-env

# Ingest datasets into database
python -m backend.app.cli.soc ingest --name CICIDS2017 --path data/cicids2017_sample.csv
python -m backend.app.cli.soc ingest --name LANL --path data/lanl_auth_sample.csv
python -m backend.app.cli.soc ingest --name COMPLIANCE --path data/compliance_benchmarks.json

# Train analytics models
python -m backend.app.cli.soc train-waf
python -m backend.app.cli.soc train-behavior
python -m backend.app.cli.soc train-forecast
```

---

## How to Run BEACON SOC

Choose one of the following execution methods to launch the system:

### Option A: Single-Command Automated Runner (Recommended)

Run the unified Python runner script which launches both the FastAPI REST backend (`port 8000`) and the Vite React frontend (`port 5173`):

```bash
python run.py
```

- **Web Dashboard**: http://localhost:5173
- **FastAPI Documentation (Swagger UI)**: http://localhost:8000/docs
- **API Redoc**: http://localhost:8000/redoc

### Option B: Manual Two-Terminal Execution

#### Terminal 1: Launch FastAPI Backend
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Terminal 2: Launch Vite React Dashboard
```bash
cd frontend
npm run dev
```

### Option C: Containerized Deployment via Docker Compose

To deploy the stack inside isolated Docker containers:

```bash
docker-compose up --build
```

---

## Command-Line Interface Guide (`soc`)

BEACON SOC provides a Typer-based CLI for automation and administrative operations:

```bash
python -m backend.app.cli.soc [COMMAND] [OPTIONS]
```

### CLI Command Summary

| Command | Arguments / Options | Purpose |
| :--- | :--- | :--- |
| `init-env` | None | Initializes database tables (`soc_beacon.db`) and workspace directories |
| `ingest` | `--name <NAME> --path <PATH>` | Ingests CSV/JSON datasets (`CICIDS2017`, `LANL`, `COMPLIANCE`) |
| `train-waf` | `--path <PATH>` | Trains Smart WAF text classification model on HTTP payloads |
| `train-behavior` | None | Constructs relational graph & trains Isolation Forest anomaly model |
| `train-forecast` | None | Trains PyTorch Dual-Head LSTM Attack Forecasting Engine |
| `compliance-scan` | `--target <aws\|k8s>` | Executes agentless compliance audit scan |
| `behavior-anomalies` | `--user <USER_ID>` | Displays behavioral risk score & anomaly indicators for a user |
| `forecast-session` | `--session <SESSION_ID>` | Evaluates sequence flow prediction & escalation risk for a session |
| `trust-status` | `--session <SESSION_ID>` | Computes continuous trust score and policy enforcement action |
| `live-scan` | None | Scans host device sockets & runs real-time PyTorch attack forecast |

---

## REST API Endpoint Reference

All backend API endpoints communicate via JSON over HTTP:

| Method | Endpoint Path | Description |
| :---: | :--- | :--- |
| `GET` | `/api/overview/stats` | System telemetry metrics, live feed, and trust heatmap counters |
| `GET` | `/api/network/flows` | Network flow records and ATT&CK stage distribution |
| `POST` | `/api/waf/evaluate` | Classifies HTTP request snapshot in real time |
| `GET` | `/api/waf/logs` | Retrieves recent WAF inspection logs |
| `GET` | `/api/behavior/graph` | Returns heterogeneous entity graph nodes and relational links |
| `GET` | `/api/behavior/users` | Returns user behavioral risk rankings table |
| `GET` | `/api/forecast/evaluate` | Evaluates PyTorch LSTM sequence attack forecasting |
| `GET` | `/api/compliance/findings` | Returns CIS audit findings mapped to NCIIPC guidelines |
| `POST` | `/api/trust/score` | Computes zero-trust score and recommended policy enforcement |
| `POST` | `/api/scan/live` | Executes real-time host device security scan and attack forecast |
| `POST` | `/api/scenarios/execute` | Triggers realistic attack scenario execution & incident creation |
| `GET` | `/api/incidents` | Lists active security incidents |
| `GET` | `/api/incidents/{id}/timeline` | Returns event timeline for a specific incident |
| `POST` | `/api/identity/challenge` | Generates Ed25519 cryptographic authentication challenge |
| `POST` | `/api/identity/verify` | Verifies Ed25519 challenge signature & returns identity trust |
| `GET` | `/api/ml/metrics` | Fetches metrics for WAF, Behavior, and Forecast models |
| `POST` | `/api/system/ingest` | Triggers background dataset ingestion |
| `POST` | `/api/system/train` | Triggers background ML model retraining |

---

## Dataset Format Specifications

### 1. Network Traffic Flows (`data/cicids2017_sample.csv`)

| Column Name | Type | Description |
| :--- | :--- | :--- |
| `session_id` | String | Session identifier (`SESS_001` .. `SESS_005`) |
| `src_ip` | String | Source IP address |
| `dst_ip` | String | Destination IP address |
| `src_port` | Integer | Source port number |
| `dst_port` | Integer | Destination port number |
| `protocol` | Integer | Protocol ID (6 = TCP, 17 = UDP) |
| `timestamp` | String | Timestamp (UTC-naive: `YYYY-MM-DD HH:MM:SS`) |
| `duration` | Float | Flow duration in seconds |
| `total_fwd_packets` | Integer | Total packets in forward direction |
| `total_bwd_packets` | Integer | Total packets in backward direction |
| `flow_bytes_s` | Float | Flow throughput in bytes/sec |
| `syn_flag_count` | Integer | SYN flag count |
| `rst_flag_count` | Integer | RST flag count |
| `attack_stage` | String | ATT&CK Stage (`RECON`, `INITIAL_ACCESS`, etc.) |
| `label` | String | Specific attack label (`PortScan`, `SQL Injection`, etc.) |

### 2. Authentication Logs (`data/lanl_auth_sample.csv`)

| Column Name | Type | Description |
| :--- | :--- | :--- |
| `user_id` | String | User identifier |
| `device_id` | String | Host device identifier |
| `ip` | String | Source IP address |
| `resource` | String | Accessed target resource |
| `login_time` | String | Login timestamp (`YYYY-MM-DD HH:MM:SS`) |
| `logout_time` | String | Logout timestamp |
| `success` | Integer | Authentication result (1 = Success, 0 = Failed) |
| `auth_method` | String | Authentication method (Password, MFA, SSH-Key) |
| `sensitive_access` | Integer | Sensitive resource flag (1 = Sensitive, 0 = Normal) |

---

## Repository Structure

```
beacon/
├── backend/
│   └── app/
│       ├── audit/
│       │   ├── __init__.py        # Export verify_audit_chain
│       │   └── chain.py           # Tamper-evident SHA-256 audit chain verification
│       ├── cli/
│       │   └── soc.py             # Typer CLI command application
│       ├── db/
│       │   ├── database.py        # SQLAlchemy setup & session manager with expunge_all
│       │   └── models.py          # ORM models (Flows, Logs, Incidents, AuditEvents)
│       ├── identity/
│       │   ├── __init__.py        # Export compute_identity_trust
│       │   └── keys.py            # Ed25519 keypair & signature verification
│       ├── ml/
│       │   ├── behavior.py        # Insider threat graph & Isolation Forest engine
│       │   ├── compliance.py      # Prowler & kube-bench compliance parser
│       │   ├── correlation.py     # Multi-signal risk correlation engine
│       │   ├── forecast.py        # PyTorch Dual-Head LSTM forecasting engine
│       │   ├── trust.py           # Continuous Trust Engine calculation
│       │   ├── waf.py             # Smart WAF text classifier
│       │   └── saved_models/      # Saved ML model checkpoints (.pt, .joblib)
│       ├── incidents.py           # Incident creation and timeline helper
│       ├── ingest.py              # Dataset ingestion & UTC-naive normalization
│       ├── main.py                # FastAPI REST server application
│       └── scanner.py             # Live host device scanner module
├── data/                          # Datasets (CIC-IDS2017, LANL, WAF, Compliance)
├── frontend/                      # React + Vite web dashboard
│   ├── src/
│   │   ├── components/
│   │   │   ├── AttackAnalysisPipeline.jsx # 7-stage attack analysis pipeline visualizer
│   │   │   ├── AttackHeatmap.jsx          # MITRE ATT&CK confidence heatmap matrix
│   │   │   ├── BeaconLogo.jsx             # Vector SVG logo icon component
│   │   │   └── LiveScanner.jsx            # Live Device Scan modal component
│   │   ├── pages/                 # Overview, Network, WAF, Behavior, Forecast, Compliance
│   │   ├── App.jsx                # Main React App shell & navigation
│   │   └── index.css              # Beige & Black CSS design system
├── ml/                            # Research & benchmarking pipeline (PyTorch + DAPT2020)
├── scripts/
│   └── generate_sample_data.py    # Synthetic dataset generator with session modeling
├── eval_behavior.py               # Behavior model evaluation script
├── docker-compose.yml             # Docker compose deployment script
├── requirements.txt               # Python dependencies file
├── run.py                         # Single-command application runner
└── README.md                      # Platform documentation
```

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.
