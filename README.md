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
