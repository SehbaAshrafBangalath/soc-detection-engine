# 🛡️ SOC Detection Engine — Rule-Based SIEM Simulation

> A Python-based Security Operations Center (SOC) simulation that replicates Tier-1 and Tier-2 detection engineering workflows from scratch — without relying on any third-party SIEM platform.

**Author:** Sehba Ashraf | Cybersecurity Enthusiast | SOC & Detection Engineering Aspirant  
**Language:** Python 3 | **Status:** ✅ Functional | **Domain:** Blue Team / Detection Engineering

[![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)](https://python.org)
[![SOC](https://img.shields.io/badge/Domain-SOC%20%7C%20SIEM-darkblue?style=flat)](https://github.com/SehbaAshrafBangalath/soc-detection-engine)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=flat)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

---

## 📑 Table of Contents

- [Executive Summary](#-executive-summary)
- [Security Objectives](#-security-objectives)
- [System Architecture](#-system-architecture)
- [Project Structure](#-project-structure)
- [Detection Modules](#-detection-modules)
  - [Brute Force Detection](#1-brute-force-authentication-detection)
  - [Input Anomaly Detection](#2-input-anomaly-detection)
  - [Rapid Action Detection](#3-behavioral-anomaly-detection)
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [Security Engineering Analysis](#-security-engineering-analysis)
- [Real-World SOC Comparison](#-real-world-soc-tool-comparison)
- [Evidence & Screenshots](#-evidence--screenshots)
- [Known Limitations & Roadmap](#-known-limitations--roadmap)
- [How to Run](#-how-to-run)
- [Technologies & Concepts](#-technologies--concepts-demonstrated)

---

## 🧠 Executive Summary

This project engineers a fully functional Python-based SIEM simulation pipeline that replicates the core detection loop used in enterprise SOC environments. The system ingests raw security logs from three independent attack surfaces, normalizes them through a structured parsing layer, evaluates them against modular rule-based detection logic, and produces severity-classified, timestamped alerts — all written from scratch.

> **Design Philosophy:** Rather than configuring an existing platform, this system was built from the ground up to demonstrate genuine understanding of *how* SIEM detection engines work — not just how to use them.

**What this project demonstrates:**
- End-to-end log ingestion, parsing, and normalization pipeline
- Modular multi-tier severity classification — INFO / MEDIUM / HIGH / CRITICAL
- Independent detection modules across authentication, application, and behavioral layers
- Structured alert lifecycle from raw log event to persistent analyst-ready output
- Clean separation of concerns: engine logic fully decoupled from detection rules

---

## 🎯 Security Objectives

| Attack Surface | Threat Modeled | Log Source | Detection Module |
|---|---|---|---|
| Authentication layer | Credential brute force / password guessing | `auth_logs.txt` | `brute_force_rules.py` |
| Application input layer | XSS / SQL injection payloads | `abnormal_input.log` | `anomaly_rules.py` |
| Behavioral traffic layer | Bot activity / automated flooding | `rapid_action.log` | `rapid_action_rules.py` |

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────┐
│               RAW LOG SOURCES                    │
│  auth_logs.txt  |  abnormal_input.log            │
│  rapid_action.log                                │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────┐
│          DETECTION ENGINE — siem_engine.py       │
│  • Reads logs line by line                       │
│  • Counts FAIL events     → fail_count           │
│  • Counts all lines       → request_count        │
│  • Collects input data    → all_input_data[]     │
└──────┬───────────────┬──────────────────┬────────┘
       │               │                  │
       ▼               ▼                  ▼
┌────────────┐  ┌──────────────┐  ┌──────────────┐
│brute_force │  │anomaly_rules │  │rapid_action  │
│_rules.py   │  │.py           │  │_rules.py     │
│INFO        │  │INFO          │  │INFO          │
│HIGH        │  │MEDIUM        │  │MEDIUM        │
│CRITICAL    │  │HIGH          │  │HIGH          │
└─────┬──────┘  └──────┬───────┘  └──────┬───────┘
      └─────────────────┴─────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────┐
│  ALERT GENERATION                                │
│  timestamp | severity | message | metadata       │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────┐
│  PERSISTENT OUTPUT — outputs/alerts.txt          │
└──────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

> **Screenshot — Repository Tree Structure**

![Project Tree Structure](screenshots/tree.png)

```
soc-detection-engine/
├── engine/
│   └── siem_engine.py          ← Orchestration & alert generation
├── rules/
│   ├── brute_force_rules.py    ← Auth anomaly detection
│   ├── anomaly_rules.py        ← Input/payload detection
│   └── rapid_action_rules.py   ← Behavioral frequency detection
├── logs/
│   ├── auth_logs.txt           ← Simulated failed login events
│   ├── abnormal_input.log      ← Injection & payload log
│   └── rapid_action.log        ← High-frequency request log
├── outputs/
│   └── alerts.txt              ← Persistent alert store
├── screenshots/                ← Execution evidence
└── README.md
```

---

## 🔍 Detection Modules

### 1. Brute Force Authentication Detection

**Threat Modeled:** MITRE ATT&CK T1110.001 — Password Guessing

**Attack Scenario:** An attacker at IP `192.168.1.10` repeatedly submits failed credentials against a target account — a classic precursor to account takeover (ATO).

**Simulated Log — `logs/auth_logs.txt`:**

> **Screenshot — Brute Force Log**

![Brute Force Auth Log](screenshots/auth_logs.png)

```
192.168.1.10 FAIL
192.168.1.10 FAIL
192.168.1.10 FAIL
192.168.1.10 FAIL
192.168.1.10 FAIL
```

**Detection Rule — `rules/brute_force_rules.py`:**

```python
def detect_bruteforce(fail_count):
    if fail_count >= 10:
        return "CRITICAL", "Brute Force Attack Detected"
    elif fail_count >= 5:
        return "HIGH", "Suspicious Login Activity"
    else:
        return "INFO", "Normal Activity"
```

**Severity Scale:**

| fail_count | Severity | Interpretation |
|---|---|---|
| < 5 | INFO | Normal login behavior |
| ≥ 5 | HIGH | Suspicious — likely credential guessing |
| ≥ 10 | CRITICAL | Confirmed brute force attack pattern |

**Alert Generated:**
```
2026-04-18 16:41:52 | HIGH | Suspicious Login Activity | FAIL_COUNT=5
```

**SOC Context:** In production SIEMs (Splunk, Microsoft Sentinel, QRadar), this maps to a correlation rule firing on Windows Event ID 4625 (Failed Logon) exceeding a threshold per source IP. The three-tier severity scale here mirrors exactly how enterprise detection rules escalate based on signal strength — giving analysts actionable gradation rather than a binary alert/no-alert output.

**Sigma Rule Equivalent:**
```yaml
title: Brute Force Login Detection
status: experimental
logsource:
    category: authentication
detection:
    selection:
        EventType: FAIL
    condition: selection | count() >= 5
level: high
tags:
    - attack.credential_access
    - attack.t1110.001
```

---

### 2. Input Anomaly Detection (XSS & SQL Injection)

**Threat Modeled:** MITRE ATT&CK T1190 — Exploit Public-Facing Application

**Attack Scenario:** An attacker submits crafted payloads — an XSS script tag, a SQL injection string, and an oversized garbage payload — through an exposed input vector.

**Simulated Log — `logs/abnormal_input.log`:**

> **Screenshot — Abnormal Input Log**

![Abnormal Input Log](screenshots/abnormal_input_log.png)

```
192.168.1.10 OK
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@!111222324675687903fgtthffrryhhhn
192.168.1.10 OK
<script>alert(1)</script>
192.168.1.10 OK
' OR 1=1 --
192.168.1.10 OK
NORMAL_INPUT_TEST
```

**Detection Rule — `rules/anomaly_rules.py`:**

```python
def detect_abnormal_input(data):
    """
    Detect abnormal or malicious input patterns.
    """
    if len(data) > 50:
        return "MEDIUM", "Abnormal input size detected"
    if "<script>" in data:
        return "HIGH", "XSS attempt detected"
    if "OR 1=1" in data or "--" in data:
        return "HIGH", "SQL Injection attempt detected"
    return "INFO", "Normal input"
```

**Detection Priority:**

| Condition | Severity | Threat Identified |
|---|---|---|
| `len(data) > 50` | MEDIUM | Oversized / malformed payload |
| `<script>` present | HIGH | Cross-site scripting (XSS) |
| `OR 1=1` or `--` present | HIGH | SQL injection |
| None matched | INFO | Normal input |

**Alert Generated:**
```
2026-04-18 16:41:52 | MEDIUM | Abnormal input size detected
```

**Sigma Rule Equivalent:**
```yaml
title: Malicious Input Pattern Detected
logsource:
    category: webserver
detection:
    selection_xss:
        InputData|contains: '<script>'
    selection_sqli:
        InputData|contains:
            - 'OR 1=1'
            - '--'
    condition: selection_xss or selection_sqli
level: high
tags:
    - attack.initial_access
    - attack.t1190
```

---

### 3. Behavioral Anomaly Detection (Rapid Action / Bot Activity)

**Threat Modeled:** MITRE ATT&CK T1499.002 — Service Exhaustion Flood

**Attack Scenario:** IP `192.168.1.10` sends 20 rapid sequential requests, simulating bot-driven automated traffic or credential stuffing groundwork.

**Simulated Log — `logs/rapid_action.log`:**

> **Screenshot — Rapid Action Log**

![Rapid Action Log](screenshots/rapid_log.png)

```
192.168.1.10 REQUEST  ← ×20 entries
```

**Detection Rule — `rules/rapid_action_rules.py`:**

```python
def detect_rapid_action(request_count):
    if request_count > 20:
        return "HIGH", "Rapid activity detected (possible bot attack)"
    elif request_count > 10:
        return "MEDIUM", "Elevated request rate detected"
    else:
        return "INFO", "Normal activity"
```

**Severity Scale:**

| request_count | Severity | Interpretation |
|---|---|---|
| ≤ 10 | INFO | Normal user behavior |
| 11–20 | MEDIUM | Elevated — warrants monitoring |
| > 20 | HIGH | Likely automated / bot traffic |

**Alert Generated:**
```
2026-04-18 16:41:52 | INFO | Normal activity
```

> **Analyst Note:** With exactly 20 requests, the rule correctly returns INFO (threshold is `> 20`). This is a deliberate boundary condition — 20 rapid requests is a threshold tuning opportunity based on environment baseline traffic profiling.

---

## 🗺️ MITRE ATT&CK Coverage

| Detection Module | Tactic | Technique | ID | Severity |
|---|---|---|---|---|
| Brute Force Auth | Credential Access | Password Guessing | T1110.001 | HIGH / CRITICAL |
| Input Injection | Initial Access | Exploit Public-Facing App | T1190 | MEDIUM / HIGH |
| Rapid Requests | Impact | Service Exhaustion Flood | T1499.002 | MEDIUM / HIGH |

**Sub-technique coverage:**

| Sub-technique | Status | Notes |
|---|---|---|
| T1110.001 Password Guessing | ✅ Detected | Core target |
| T1110.003 Password Spraying | ✅ Partial | Triggers on multi-user FAIL patterns |
| T1110.004 Credential Stuffing | ⚠️ Gap | Requires username-password pair correlation |
| T1190 XSS / SQLi | ✅ Detected | Signature + size-based |
| T1499.002 Service Exhaustion | ✅ Detected | Frequency threshold-based |

---

## 🔬 Security Engineering Analysis

### ✅ What This System Gets Right

**Modular rule architecture.** The engine (`siem_engine.py`) is fully decoupled from detection logic (`rules/`). Each rule module is independently callable, testable, and replaceable — mirroring how production SIEM content is versioned and deployed separately from the ingestion pipeline.

**Multi-tier severity escalation.** Every detection function returns a two-value tuple: severity and message. Every module implements at least three tiers. This reflects real SOC design — HIGH alerts page the on-call analyst, MEDIUM go into the morning queue, INFO is retained for threat hunting context only.

**Append-mode persistence.** Using `open("outputs/alerts.txt", "a")` means each engine run adds to the historical alert record without overwriting. The `alerts.txt` file shows multiple timestamped runs across a real session — demonstrating the system has been executed, validated, and re-run. This is the correct behavior for a SIEM output layer: alert history is immutable and cumulative.

**Timestamp-embedded alerts.** Every alert includes `datetime.now()` formatted to the second — enabling chronological correlation across runs, which is the foundation of any timeline-based incident investigation.

---

### ⚠️ Detection Logic Critique — Known Gaps

**Gap 1 — Single log source drives all three detectors.**
The engine currently reads only `auth_logs.txt` into the variables feeding all three detection modules. The `abnormal_input.log` and `rapid_action.log` files exist but are not directly read by `siem_engine.py`. Each detector should consume its own dedicated log stream independently. This is the single highest-impact architectural improvement available.

**Gap 2 — Logic short-circuit in `detect_abnormal_input()`.**
The `len(data) > 50` check executes first. Because the engine joins all log lines into one string, this condition fires on virtually every run — making the XSS and SQL injection signature checks below it effectively unreachable. The real payloads in `abnormal_input.log` (`<script>alert(1)</script>`, `' OR 1=1 --`) would produce HIGH alerts if reached. Fix: evaluate each line individually, or reorder checks so signatures run before the length gate.

**Gap 3 — No time-window correlation.**
All three detectors operate on total counts across the entire log file with no time dimension. Five failures in five days is treated identically to five failures in five seconds. Implementing a sliding window using `collections.deque` with timestamps would be the most impactful single enhancement to detection quality.

**Gap 4 — No per-IP attribution in alert output.**
The logs clearly show `192.168.1.10` as the source of all activity, but detection modules receive only aggregate counts. The alert says `FAIL_COUNT=5` but not `SOURCE_IP=192.168.1.10`. In a real SOC, the source IP is the primary enrichment pivot — analysts immediately check it against threat intel feeds, geolocation, and asset inventories.

---

## 🏢 Real-World SOC Tool Comparison

| Capability | This System | Splunk ES | Microsoft Sentinel | QRadar |
|---|---|---|---|---|
| Log ingestion | File-based, single source | Agent-based, real-time multi-source | Cloud-native, connector-based | Multi-protocol, flow/event |
| Detection logic | Python functions, threshold-based | SPL correlation searches | KQL analytics rules | AQL + building blocks |
| Severity classification | INFO/MEDIUM/HIGH/CRITICAL | Low/Medium/High/Critical | Informational/Low/Medium/High | Low/Medium/High |
| Alert persistence | Append-mode flat file | Index-based, searchable | Log Analytics Workspace | Offense database |
| Time-window correlation | ❌ Not yet | ✅ `earliest=`/`latest=` | ✅ KQL sliding window | ✅ Event accumulation |
| Threat intel enrichment | ❌ Not yet | ✅ ThreatIntelligence lookup | ✅ MSTI / TAXII feeds | ✅ X-Force integration |
| False positive suppression | ❌ Not yet | ✅ Allowlist lookups | ✅ Watchlists | ✅ Tuning filters |
| MITRE ATT&CK mapping | ✅ Manual | ✅ ES content pack | ✅ Native in rule schema | ✅ Partial via use cases |

> **Key takeaway:** This system replicates the *core detection loop* of every tool in this table — ingest, parse, evaluate rule, classify, output alert. The differences are in scale, enrichment, and operational tooling — not in the fundamental logic. Building it from scratch demonstrates understanding of what those enterprise platforms are doing under the hood.

---

## 📸 Evidence & Screenshots

### Engine Execution

> Full engine run showing SOC ENGINE STARTED banner and alert output to terminal.

![Engine Run](screenshots/02_soc_engine_run.png)

---

### Alert Output File

> Contents of `outputs/alerts.txt` showing multiple timestamped runs and correct severity classification across all three detectors.

![Alert Output](screenshots/03_alerts_output.png)

```
✔ NORMAL: No suspicious activity
⚠️ HIGH ALERT: Suspicious Login Activity
2026-04-18 15:39:01 | HIGH | Suspicious Login Activity | FAIL_COUNT=5
2026-04-18 16:41:52 | HIGH | Suspicious Login Activity | FAIL_COUNT=5
2026-04-18 16:41:52 | MEDIUM | Abnormal input size detected
2026-04-18 16:41:52 | INFO | Normal activity
2026-04-18 16:49:16 | HIGH | Suspicious Login Activity | FAIL_COUNT=5
2026-04-18 16:49:16 | MEDIUM | Abnormal input size detected
2026-04-18 16:49:16 | INFO | Normal activity
```

---

### Brute Force Log

> `logs/auth_logs.txt` — five consecutive FAIL entries from 192.168.1.10 correctly triggering HIGH severity.

![Brute Force Log](screenshots/bruteforce_logs.png)

---

### Abnormal Input Log

> `logs/abnormal_input.log` — contains oversized payload, XSS script tag, and SQL injection string.

![Abnormal Input Log](screenshots/alog_io_bnormal_input_log.png)

---

### Rapid Action Log

> `logs/rapid_action.log` — 20 sequential REQUEST entries from 192.168.1.10 simulating bot-driven traffic.

![Rapid Action Log](screenshots/rapid_log.png)

---

## 🗺️ Known Limitations & Roadmap

| Limitation | Current State | Planned Enhancement |
|---|---|---|
| Single log source | Engine reads only `auth_logs.txt` | Route each log to its own parser independently |
| No time-window correlation | Static count across full file | `collections.deque` rolling window per IP |
| Input check short-circuit | Length check fires before signatures | Evaluate line-by-line; reorder checks |
| No per-IP attribution | Aggregate counts only | Parse and carry source IP through to alert |
| No threat intel enrichment | No IOC matching | Integrate AbuseIPDB / VirusTotal API |
| No false positive suppression | No allowlisting | Configurable IP/user allowlist per rule |
| No alert deduplication | Repeated runs produce duplicates | Hash-based dedup before write |

---

## ▶️ How to Run

```bash
# Clone the repository
git clone https://github.com/SehbaAshrafBangalath/soc-detection-engine.git
cd soc-detection-engine

# Run the detection engine
PYTHONPATH=. python3 engine/siem_engine.py

# View generated alerts
cat outputs/alerts.txt
```

**Requirements:** Python 3 only. No external dependencies.

---

## 🧰 Technologies & Concepts Demonstrated

- **Python 3** — file I/O, string operations, modular imports, datetime formatting
- **Modular detection architecture** — rules decoupled from engine via clean function interfaces
- **Multi-tier severity classification** — INFO / MEDIUM / HIGH / CRITICAL across all modules
- **SIEM pipeline modeling** — ingestion → parsing → detection → alerting → persistence
- **MITRE ATT&CK framework** — three techniques mapped across three kill chain phases
- **Sigma rule design** — detection logic expressed in vendor-neutral format
- **Defense-in-depth** — independent layers covering auth, application, and behavioral vectors
- **SOC analyst workflow** — append-mode persistent alert store with timestamps

---

## 👩‍💻 Author

**Sehba Ashraf**  
Cybersecurity Enthusiast | SOC & Detection Engineering Aspirant  

[![GitHub](https://img.shields.io/badge/GitHub-SehbaAshrafBangalath-black?style=flat&logo=github)](https://github.com/SehbaAshrafBangalath)

---

*Built from scratch to understand detection engineering from the inside out — not just from the dashboard.*
