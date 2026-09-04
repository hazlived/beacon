# Changelog

All notable changes to the **BEACON SOC** platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-09-04

### Added
- **Asymmetric Ed25519 Cryptographic Identity Module (`backend/app/identity/`)**:
  - Implemented Ed25519 keypair generation (`generate_demo_user_keypair`).
  - Added challenge-response signature generation (`sign_challenge`) and cryptographic signature verification (`verify_ed25519_signature`).
  - Exposed `/api/identity/challenge` and `/api/identity/verify` FastAPI endpoints.

- **Multi-Signal Risk Correlation Engine (`backend/app/ml/correlation.py`)**:
  - Implemented weighted risk fusion combining WAF risk (20%), behavior risk (20%), network risk (20%), PyTorch forecast risk (20%), identity risk (15%), and compliance risk (5%).
  - Added variance-based signal agreement metric for severity assignment (`CRITICAL`, `HIGH`, `MEDIUM`).

- **Incident & Event Timeline Management (`backend/app/incidents.py`)**:
  - Added `Incident` and `IncidentEvent` database models.
  - Implemented `create_incident` helper recording multi-event threat timelines.
  - Exposed `/api/incidents`, `/api/incidents/{id}`, `/api/incidents/{id}/timeline`, and `/api/scenarios/execute` endpoints.

- **Tamper-Evident SHA-256 Audit Chain (`backend/app/audit/`)**:
  - Implemented audit log chain verification (`verify_audit_chain`) checking cryptographic link integrity across `AuditEvent` records (`previous_hash` and `event_hash`).

- **Attack Analysis Pipeline & ATT&CK Heatmap Components**:
  - Created `frontend/src/components/AttackAnalysisPipeline.jsx` visualizing the 7-step analysis path (`01/INGEST` through `07/ASSESS`).
  - Created `frontend/src/components/AttackHeatmap.jsx` displaying a MITRE ATT&CK confidence matrix.
  - Updated `frontend/src/pages/Forecast.jsx` and added CSS animations in `frontend/src/index.css`.

- **Behavior Model Evaluation Script (`eval_behavior.py`)**:
  - Added evaluation utility for measuring Detection Rate (TPR) and False Positive Rate (FPR) on synthetic user profiles.

### Changed
- **Sample Data Generator (`scripts/generate_sample_data.py`)**:
  - Added synthetic session modeling (`SESS_001` .. `SESS_005`) and session-based attack stage progression.
- **FastAPI Backend (`backend/app/main.py`)**:
  - Added fallback in `/api/forecast/evaluate` to fetch recent flows from active sessions when specific session flow queries are empty, preventing UI `NaN` states.
  - Integrated admin API key verification middleware (`verify_admin_key`).
- **Database Session Safety (`backend/app/db/database.py` & `ingest.py`)**:
  - Enforced `session.expunge_all()` prior to `session.close()` across read methods.
  - Enforced UTC-naive datetime parsing (`parse_datetime_utc_naive`) for SQLite compatibility.
  - Added `(st_mtime, st_size)` file signature tracking in `ingest.py` to prevent duplicate re-reads.
- **Dependencies (`requirements.txt`)**:
  - Added `cryptography>=41.0.0` for Ed25519 signature operations.

---

## [1.0.0] - 2026-09-01

### Added
- Initial release of BEACON SOC Platform.
- PyTorch Dual-Head LSTM temporal sequence forecasting engine (`backend/app/ml/forecast.py`).
- DistilBERT / TF-IDF Smart WAF text classifier (`backend/app/ml/waf.py`).
- NetworkX Heterogeneous Entity Graph & Isolation Forest Insider Threat engine (`backend/app/ml/behavior.py`).
- Agentless CIS compliance auditor (`backend/app/ml/compliance.py`).
- Live Device Security Scanner (`backend/app/scanner.py`).
- React 18 + Vite Beige & Black design system dashboard (`frontend/`).
- Typer CLI utility (`backend/app/cli/soc.py`).
