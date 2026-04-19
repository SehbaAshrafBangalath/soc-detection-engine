# SOC Detection Engine (Mini SIEM Simulation)

A Python-based Security Operations Center (SOC) simulation engine that detects common attack patterns using log analysis and rule-based detection.

---

## Overview

This project simulates a lightweight SIEM system by:

- Ingesting logs from multiple sources
- Applying detection rules
- Identifying suspicious behavior
- Generating structured alerts
- Storing results for analysis

---

##  Detection Capabilities

###  Brute Force Detection
- Monitors repeated failed login attempts
- Flags suspicious authentication patterns

###  Abnormal Input Detection
- Detects:
  - Long/malicious inputs
  - XSS patterns (`<script>`)
  - SQL Injection (`OR 1=1`, `--`)

###  Rapid Action Detection
- Identifies high-frequency requests
- Detects bot/flood-like behavior

---

## Architecture

</> Markdown
## 📁 Project Structure
soc_project/
│
├── engine/              # SOC processing engine
│   └── siem_engine.py
│
├── logs/                # Simulated attack logs
│   ├── auth_logs.txt
│   ├── abnormal_input.log
│   └── rapid_action.log
│
├── rules/               # Detection rules (SIEM logic)
│   ├── brute_force_rules.py
│   ├── anomaly_rules.py
│   └── rapid_action_rules.py
│
├── outputs/             # Generated alerts
│   └── alerts.txt
│
├── report/              # SOC summary report
│   └── SOC_Report.md
│
└── screenshots/         # Evidence of execution


▶️ How to Run
PYTHONPATH=. python3 engine/siem_engine.py


📊 Sample Output
===== SOC ENGINE STARTED =====

===== SOC ALERTS =====
2026-04-18 16:41:52 | HIGH | Suspicious Login Activity | FAIL_COUNT=5
2026-04-18 16:41:52 | MEDIUM | Abnormal input size detected
2026-04-18 16:41:52 | INFO | Normal activity


📸 Screenshots
🔹 Engine Execution
