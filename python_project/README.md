# Automated Security Log Analyzer & Threat Detection System

A highly structured, modular, and realistic Python application simulating a Tier 2/3 Security Operations Center (SOC) incident triage workflow. This project is built specifically to highlight production-grade threat parsing, behavioral correlation rules, risk scoring, and professional incident reporting.

It can be showcased as a **Cybersecurity Portfolio Project** for SOC Analyst, Incident Responder, or security engineering job applications.

---

## 🛠️ System Architecture & Codebase Design

The project strictly decouples core responsibilities into distinct modules, aligning with standard enterprise software engineering and security operations principles:

1.  **`main.py`** — The command-line orchestration module. Parses input flags, executes the pipeline phases, and streams colorful real-time detection logs directly to the SOC terminal.
2.  **`log_parser.py`** — Ingests and sanitizes raw CSV logs. Normalizes datatypes (ISO 8601 timestamps, boolean operators), sorts records chronologically, and handles malformed rows gracefully to ensure high-fidelity downstream analytics.
3.  **`threat_detector.py`** — Tracks stateful sliding windows, heuristic patterns, and multi-event correlations to identify intrusion signatures (IoCs).
4.  **`risk_engine.py`** — The dynamic risk scoring engine. Translates raw alert indicators into contextual risk metrics (0-100) based on administrator status, successful/failed attack outcomes, external IP reputations, and threat amplification frequencies.
5.  **`report_generator.py`** — Exports both a detailed, human-readable executive incident report (`.txt`) and a machine-readable JSON structure (`.json`) containing complete forensic metrics and NIST-aligned remediation playbooks.
6.  **`sample_logs.csv`** — A realistic security event log dataset featuring normal administrative traffic interspersed with active, multi-stage attack scenarios.

---

## 🔍 Security Detection Playbooks Covered

This analyzer implements advanced rule-based correlation heuristics to identify standard enterprise threats:

*   **Brute Force Attacks (`BRUTE_FORCE`)**: Detects multiple consecutive failed logins (`>= 5` failures) targeting a single account from a single IP address within a 5-minute sliding window.
*   **Brute Force Success (`BRUTE_FORCE_SUCCESS`)**: Tracks if a brute-force IP address eventually registers a successful authentication within a short period of time. This signifies a **confirmed credential compromise** (Critical Alert).
*   **Password Spraying (`PASSWORD_SPRAY`)**: Detects an IP attempting failed logins across multiple *different* accounts in a 5-minute sliding window, seeking to bypass standard single-account lockout thresholds.
*   **Impossible Travel (`IMPOSSIBLE_TRAVEL`)**: Identifies accounts registering successful logins from geographically distant IP addresses (such as an internal workstation and an external VPN IP) within a tight timeline (e.g. less than 10 minutes), flagging potential session hijacking.
*   **Privilege Escalation (`PRIVILEGE_ESCALATION`)**: Analyzes standard user activity for unauthorized command executions or access attempts targeting critical system paths (such as reading `/etc/shadow` or executing unauthorized `sudo su` commands).
*   **Off-Hours Activity Anomaly (`UNUSUAL_TIME`)**: Highlights successful logons made by non-service accounts during highly vulnerable windows (specifically 2:00 AM to 5:00 AM local time), a common indicator of exfiltration or ransomware planting.

---

## 📊 Contextual Risk Scoring Matrix

The `RiskEngine` computes a contextual risk score from **0 to 100** by combining base alert severity with multiple environmental multipliers:

| Variable | Influence on Score | Cybersecurity Rationale |
| :--- | :--- | :--- |
| **Base Classifications** | Low: `15` \| Med: `40` \| High: `65` \| Critical: `85` | Baseline severity based on type of signature matched. |
| **Attack Outcome** | Successful attack = `+15` points | Failed login attempts are noise; a successful login after failures indicates a breached security perimeter. |
| **Privilege Level** | Administrator accounts = `+10` points | Compromised admin keys represent unrestricted domain-level access. |
| **Origin Subnet** | Public / External IP = `+8` points | Activity coming from external IP addresses bypasses standard internal intranet network defenses. |
| **Threat Amplification** | Actor repeated alerts = `+5` per alert (Max `+15`) | Entities triggering multiple independent alarms represent a persistent, targeted threat campaign. |

### Risk Level Classifications
*   **`0 - 30` (Low Risk)**: Minor compliance deviations or passive alerts.
*   **`31 - 60` (Medium Risk)**: Anomalous activity deserving passive logging and monitoring.
*   **`61 - 80` (High Risk)**: Active attack behaviors requiring swift human triage.
*   **`81 - 100` (Critical Risk)**: Highly probable active compromises. Requires immediate host isolation and containment procedures.

---

## 🚀 Getting Started

### Prerequisites

The project operates entirely on the **Python 3 Standard Library**, requiring **no third-party dependencies** to compile and run.

### Installation

1.  Clone this directory (or copy the scripts into a local folder).
2.  Verify your Python installation (Python 3.8+ recommended):
    ```bash
    python3 --version
    ```

### Running the Analyzer

Run the analyzer on the pre-loaded sample dataset:
```bash
python3 main.py --file sample_logs.csv
```

To customize thresholds via CLI arguments:
```bash
python3 main.py --file sample_logs.csv --brute-limit 3 --brute-window 600 --travel-window 1200
```

### Reviewing the Output Reports

After execution completes, the system writes security reports directly to your directory:
*   **`soc_incident_report.txt`** — Printout-ready TXT incident brief. Includes an executive summary, Chief Threat Actor stats, a chronological incident timeline, and detailed remediation action lists.
*   **`soc_incident_report.json`** — Machine-readable structured telemetry for SIEM ingestion or Python visualization.

---

## 💼 Real-World SOC Deployment Concept

In a practical enterprise environment, a SOC Analyst or Security Engineer would deploy this system in several ways:

1.  **SIEM Event Forwarder**: Connected to standard system log exports (e.g., Windows Event logs parsed to CSV, or Linux `/var/log/auth.log`) as a scheduled cron job (running every 5 minutes) to perform localized, high-speed security summaries.
2.  **IR Forensic Triage**: Uploaded to an isolated, compromised endpoint during an Incident Response (IR) engagement to scrape local logs and instantly isolate compromised admin credentials without waiting for SIEM searches.
3.  **SOAR Orchestration**: Integrated within SOAR tools (like Palo Alto Cortex XSOAR or Splunk Phantom). The JSON report generated by this tool can trigger automatic webhooks to suspend active Active Directory accounts or block attacking IPs on perimeter firewalls.

---

**Disclaimer**: This log analyzer is developed for educational, threat hunting, and portfolio purposes. Always ensure you have proper authorization before scraping or analyzing system logs in enterprise environments.
