# CyberTwin 🛡️
> **Simulate. Detect. Defend. Improve.**
> An Intelligent Cybersecurity Digital Twin & Controlled Attack Simulation Platform.

CyberTwin is a 100% software-based cybersecurity digital twin application designed for security operations centers (SOC), academic research, and collegiate cybersecurity demonstrations. It creates a virtual digital replica of an enterprise/campus network to safely model threats, run deterministic simulated cyberattacks, monitor intrusion alerts, execute incident response workflows, apply defensive controls, and generate executive PDF security audits.

# Working Website
https://cybertwin-ei42.onrender.com

---

## 🏛️ Architectural Overview

CyberTwin is engineered across six core cybersecurity domains:
1. **Security Foundations**: Asset criticality modeling, CIA triad risk profiling, custom risk scoring.
2. **Network Security**: Virtual topology modeling, gateway routing, firewall ACL enforcement (`deny-overrides-allow`, default-deny boundaries).
3. **Attack Simulation**: Safe, deterministic attack scenarios (Reconnaissance Port Scans, Credential Brute-Force, Lateral Movement, Firewall Misconfigurations, SQL Injection, Denial of Service).
4. **Threat Detection**: Rule-based Intrusion Detection Engine (IDS) identifying port sweeps, repeated login failures, wildcard access rules, and unencrypted legacy protocols.
5. **Incident Response**: Complete triage lifecycle with real-time virtual asset containment (network isolation) and recovery.
6. **Defensive Hardening & Testing**: Automated before-and-after comparison following ACL microsegmentation, auth strengthening, and vector PDF audit report generation via ReportLab.

```
cybertwin/
├── backend/
│   ├── app/
│   │   ├── api/             # REST Routers (auth, networks, assessments, simulations, threats, incidents, controls, reports)
│   │   ├── core/            # Config & system settings
│   │   ├── models/          # SQLite / PostgreSQL compatible SQLAlchemy entities
│   │   ├── schemas/         # Pydantic schemas validating network topology & telemetry
│   │   ├── services/        # Business logic, sample network seeders, auth
│   │   ├── graph_engine/    # NetworkX reachability & path analysis
│   │   ├── simulation/      # Deterministic 6-scenario attack simulation engine
│   │   ├── detection/       # Rule-based IDS & threat telemetry engine
│   │   ├── security/        # CIA Triad & quantitative risk calculator
│   │   └── reporting/       # ReportLab PDF executive assessment generator
│   ├── tests/               # Pytest automated test suite (8 passing test suites)
│   └── venv/                # Isolated Python virtual environment
├── frontend/
│   ├── src/
│   │   ├── components/      # UI component library (Cards, StatCards, Badges, Navigation)
│   │   ├── pages/           # 9 Dedicated digital twin modules
│   │   ├── services/        # Axios API client
│   │   ├── App.jsx          # Root application shell & demo coordinator
│   │   └── main.jsx         # React DOM entrypoint
│   └── vite.config.js       # Vite dev proxy configuration
├── docs/                    # Architecture documentation & demo scripts
├── start-all.bat            # One-click Windows launch script
└── cybertwin.db             # Local SQLite database pre-seeded with sample university network
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Python 3.12+**
- **Node.js 18+ & npm**

### 2. Automatic Launch (Windows)
Double-click `start-all.bat` or run:
```powershell
.\start-all.bat
```

### 3. Manual Execution

**Backend API:**
```powershell
# From the project root:
backend\venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Docs (Swagger): [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Check: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

**Frontend Application:**
```powershell
cd frontend
npm run dev
```
- App UI: [http://localhost:5173](http://localhost:5173)

---

## 🧪 Running Automated Tests

Run backend integration and unit tests:
```powershell
backend\venv\Scripts\python.exe -m pytest backend/tests -v
```

All 8 foundational tests pass:
- `test_health_check`
- `test_sample_network_seeded`
- `test_security_assessment_and_cia`
- `test_threat_detection_rules`
- `test_threat_alerts_evaluated`
- `test_incident_response_isolation`
- `test_defensive_control_before_after`
- `test_pdf_report_download`

---

## 🎨 UI Color Palette Specification
- **Primary Background**: `#F5F7F6` (Calm off-white)
- **Card Surfaces**: `#FFFFFF` (Clean white with subtle borders)
- **Primary Text**: `#253443` (Deep slate)
- **Secondary Text**: `#718096` (Muted gray)
- **Primary Teal Accent**: `#397C78` (Main brand accent)
- **Secondary Sage Accent**: `#80AAA1` (Subtle highlights)
- **Success / Good**: `#5B9678` (Soft green)
- **Warning / Moderate**: `#D5A45C` (Warm amber)
- **Danger / Critical**: `#CE7373` (Restrained coral red)
- **Navigation Sidebar**: `#202E39` (Deep charcoal navy)

