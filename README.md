# 🛡️ BEACON SOC — AI Network Attack Forecasting & Behavioral Security Platform

[![Python](https://img.shields.io/badge/Python-3.11+-E6D5B8?style=flat-square&logo=python&logoColor=0A0908)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-D4C5A9?style=flat-square&logo=fastapi&logoColor=0A0908)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-D4B982?style=flat-square&logo=pytorch&logoColor=0A0908)](https://pytorch.org)
[![React](https://img.shields.io/badge/React-18+-F8F5EE?style=flat-square&logo=react&logoColor=0A0908)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-A8A092?style=flat-square)](LICENSE)

**BEACON SOC** is an end-to-end, lightweight AI-driven Security Operations Center (SOC) focused on **real-time network attack forecasting**, **insider threat behavioral modeling**, **smart WAF request classification**, **agentless compliance auditing**, and **continuous zero-trust evaluation**.

---

## 🌟 Key Architecture & Analytics Engines

BEACON SOC integrates five core AI/ML engines into a unified threat detection and forecasting stack:

### 1. 🔮 Core AI Network Attack Forecasting Engine (`backend/app/ml/forecast.py`)
- **PyTorch Dual-Head LSTM Temporal Sequence Model**: Processes temporal sequences of network flow records (~80 features aligned with CIC-IDS2017/UNSW-NB15).
- **Dual Prediction Heads**:
  - `fc_stage`: Classifies the next likely MITRE ATT&CK attack stage (`RECON` $\rightarrow$ `INITIAL_ACCESS` $\rightarrow$ `CREDENTIAL_ACCESS` $\rightarrow$ `LATERAL_MOVEMENT` $\rightarrow$ `IMPACT`).
  - `fc_risk`: Predicts numerical escalation risk probability $\in [0, 1]$.

### 2. 🛡️ Smart WAF Engine (`backend/app/ml/waf.py`)
- **Transformer / NLP Sequence Classifier**: Evaluates serialized HTTP request snapshots (`method || path || query || headers || body`).
- **Attack Classification**: Classifies payloads into SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, Command Injection, Brute Force, or BENIGN traffic.

### 3. 🕸️ Insider Threat & Graph Behavioral Engine (`backend/app/ml/behavior.py`)
- **Heterogeneous Relational Graph**: Constructs NetworkX graph nodes (`Users`, `Devices`, `Resources`, `IPs`) and directed relationship edges (`User -> Device`, `User -> Resource`, `Device -> Device`).
- **Isolation Forest Anomaly Model**: Extracts user feature vectors (failed logins, off-hours activity, sensitive resource access, device sprawl) to compute `behavior_risk` scores.

### 4. 🔒 Continuous Trust Engine (`backend/app/ml/trust.py`)
- **Zero-Trust Score Fusion**: Dynamically calculates continuous session trust:
  $$\text{Trust} = 0.25 \times \text{Identity} + 0.25 \times (1 - \text{WAF}) + 0.25 \times (1 - \text{Behavior}) + 0.25 \times (1 - \text{Forecast})$$
- **Dynamic Policy Enforcement**:
  - **Trust $\ge$ 0.8**: `FULL_ACCESS` (Unrestricted)
  - **0.5 $\le$ Trust < 0.8**: `RESTRICTED_ACCESS` (Step-up MFA required, write operations blocked)
  - **Trust < 0.5**: `CONTAINMENT` (Session termination, IP block & host isolation)

### 5. 📑 Agentless Compliance Engine (`backend/app/ml/compliance.py`)
- Integrates remote **AWS Prowler** cloud security posture and **Kubernetes kube-bench** CIS benchmarks with plain-English security explanations and NCIIPC protection guideline mappings.

### 6. ⚡ Live Device Security Scanner (`backend/app/scanner.py`)
- Audits active host listening ports, network sockets, Smart WAF payloads, and PyTorch LSTM attack sequence forecasts in real time via Web GUI or CLI.

---

## 🎨 Web GUI Dashboard (Beige & Black Theme)

BEACON SOC includes a modern React web interface featuring:
- **Beige & Black Aesthetic**: Obsidian Black background (`#090908`) paired with Warm Luxe Beige (`#E6D5B8`), Sand Beige (`#D4C5A9`), and Champagne Gold (`#D4B982`).
- **Typography**: Google Fonts *Plus Jakarta Sans* (UI), *Space Grotesk* (Headings), and *JetBrains Mono* (Telemetry/Code).
- **Vector Logo**: Custom lighthouse beacon & cyber shield vector graphic icon.
- **Zero Emojis**: Clean, responsive **Lucide React Icons** exclusively.

---

## ⚡ Quickstart & Installation

### Prerequisites
- Python 3.11+
- Node.js v18+ & npm
- Git

### 1. Clone & Setup Repository
```bash
git clone https://github.com/your-username/beacon-soc.git
cd beacon-soc
```

### 2. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Frontend dependencies
cd frontend
npm install
cd ..
```

### 3. Launch Platform (Single Command)
Run the built-in runner script to start both the FastAPI backend (`http://localhost:8000`) and React frontend (`http://localhost:5173`):

```bash
python run.py
```

- **Web Dashboard**: [http://localhost:5173](http://localhost:5173)
- **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🐳 Docker Deployment

To launch containerized services using Docker Compose:

```bash
docker-compose up --build
```

---

## 💻 CLI Command Suite (`soc`)

You can execute all pipeline operations from the command line using `python -m backend.app.cli.soc`:

| Command | Description |
| :--- | :--- |
| `soc init-env` | Initialize SQLite database tables and directory structure |
| `soc ingest --name <NAME> --path <PATH>` | Ingest dataset (`CICIDS2017`, `LANL`, `COMPLIANCE`) with UTC-naive normalization |
| `soc train-waf` | Train Smart WAF model on HTTP payloads |
| `soc train-behavior` | Build behavioral graph and train Isolation Forest anomaly model |
| `soc train-forecast` | Train PyTorch Dual-Head LSTM attack forecasting engine |
| `soc compliance-scan --target <aws\|k8s>` | Execute agentless cloud/K8s compliance audit scan |
| `soc behavior-anomalies --user <USER_ID>` | Inspect user behavioral risk profile and anomaly flags |
| `soc forecast-session --session <SESS_ID>` | Show next attack stage prediction and escalation risk |
| `soc trust-status --session <SESS_ID>` | Compute continuous trust score and policy enforcement action |
| `soc live-scan` | Run live local host device scan and PyTorch attack sequence forecast |

---

## 📡 REST API Endpoint Reference

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `GET` | `/api/overview/stats` | System telemetry metrics, live feed, and trust heatmap counters |
| `GET` | `/api/network/flows` | Network flow records and ATT&CK stage distribution |
| `POST` | `/api/waf/evaluate` | Live HTTP request snapshot classification sandbox |
| `GET` | `/api/waf/logs` | Recent WAF inspection logs |
| `GET` | `/api/behavior/graph` | Entity-relational node-edge graph data |
| `GET` | `/api/behavior/users` | User behavioral risk rankings table |
| `GET` | `/api/forecast/evaluate` | PyTorch LSTM sequence attack forecasting analysis |
| `GET` | `/api/compliance/findings` | CIS benchmark audit findings with NCIIPC mappings |
| `POST` | `/api/trust/score` | Continuous trust score computation |
| `POST` | `/api/scan/live` | Real-time host device security scan & attack forecast |
| `POST` | `/api/system/ingest` | 1-click dataset ingestion trigger |
| `POST` | `/api/system/train` | 1-click ML model retraining trigger |

---

## 📁 Repository Directory Structure

```
beacon-soc/
├── backend/
│   └── app/
│       ├── cli/
│       │   └── soc.py             # Typer CLI application suite
│       ├── db/
│       │   ├── database.py        # SQLAlchemy setup & expunge_all enforcement
│       │   └── models.py          # Database ORM models
│       ├── ml/
│       │   ├── behavior.py        # Graph & Isolation Forest insider threat engine
│       │   ├── compliance.py      # Prowler & kube-bench compliance parser
│       │   ├── forecast.py        # PyTorch dual-head LSTM attack forecasting engine
│       │   ├── trust.py           # Continuous Trust Engine calculation
│       │   └── waf.py             # Smart WAF DistilBERT/TF-IDF classifier
│       ├── ingest.py              # Ingestion logic & UTC-naive datetime normalization
│       ├── main.py                # FastAPI REST server application
│       └── scanner.py             # Live host device scanner module
├── data/                          # Sample datasets (CIC-IDS2017, LANL, WAF, Compliance)
├── frontend/                      # React + Vite web dashboard (Beige & Black theme)
│   ├── public/
│   │   └── favicon.svg            # Custom vector favicon
│   ├── src/
│   │   ├── components/
│   │   │   ├── BeaconLogo.jsx     # Vector SVG logo icon
│   │   │   └── LiveScanner.jsx    # Live Device Scan modal component
│   │   ├── pages/                 # Overview, Network, WAF, Behavior, Forecast, Compliance
│   │   ├── App.jsx                # Main App shell & navigation
│   │   └── index.css              # Beige & Black CSS design system
├── docker-compose.yml             # Docker compose configuration
├── requirements.txt               # Python package dependencies
├── run.py                         # Single-command application runner
└── README.md                      # GitHub Repository Documentation
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
