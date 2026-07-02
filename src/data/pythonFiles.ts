// src/data/pythonFiles.ts

export interface PythonFile {
  name: string;
  path: string;
  language: string;
  description: string;
  code: string;
}

export const pythonFiles: PythonFile[] = [
  {
    name: "main.py",
    path: "main.py",
    language: "python",
    description: "The CLI orchestrator. Ingests arguments, coordinates parser, threat detector, and risk engine, and displays beautiful terminal feeds.",
    code: `#!/usr/bin/env python3
# main.py
"""
Automated Security Log Analyzer & Threat Detection System
=========================================================
Created by: Senior Cybersecurity Engineer (SOC Level 3)
Description: 
    An advanced command-line utility that ingests CSV log streams, parses and sanitizes
    them, runs stateful behavioral rules to identify intrusion indicators (IoCs), 
    applies contextual risk scoring, and exports publication-ready SOC reports.

Usage:
    python3 main.py --file sample_logs.csv --brute-limit 5
"""

import argparse
import os
import sys
from datetime import datetime

from log_parser import LogParser
from threat_detector import ThreatDetector
from risk_engine import RiskEngine
from report_generator import ReportGenerator

# Terminal text colors for professional SOC terminal aesthetic
CLR_RESET = "\\033[0m"
CLR_RED = "\\033[91m"
CLR_YELLOW = "\\033[93m"
CLR_GREEN = "\\033[92m"
CLR_CYAN = "\\033[96m"
CLR_MAGENTA = "\\033[95m"
CLR_BOLD = "\\033[1m"


def print_banner():
    """Prints a professional ASCII SOC Cybersecurity logo."""
    banner = f"""{CLR_CYAN}{CLR_BOLD}
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║       A U T O M A T E D   S E C U R I T Y   L O G   A N A L Y Z E R      ║
    ║                &   T H R E A T   D E T E C T I O N                       ║
    ║                                                                          ║
    ║                  [ Tier 2/3 SOC Incident Response Triage ]               ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    {CLR_RESET}"""
    print(banner)


def main():
    print_banner()
    
    # Define CLI argument interfaces
    parser = argparse.ArgumentParser(
        description="Core detection utility for automated offline log triage.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--file", 
        default="sample_logs.csv", 
        help="Path to the target CSV log file for analysis."
    )
    parser.add_argument(
        "--brute-window", 
        type=int, 
        default=300, 
        help="Sliding window in seconds to track brute-force attempts."
    )
    parser.add_argument(
        "--brute-limit", 
        type=int, 
        default=5, 
        help="Threshold of consecutive failed logins to trigger an alert."
    )
    parser.add_argument(
        "--travel-window", 
        type=int, 
        default=600, 
        help="Window in seconds to track impossible travel travel speeds."
    )
    parser.add_argument(
        "--output-txt", 
        default="soc_incident_report.txt", 
        help="Filename for the formatted human-readable text report."
    )
    parser.add_argument(
        "--output-json", 
        default="soc_incident_report.json", 
        help="Filename for the structured JSON export."
    )
    
    args = parser.parse_args()
    
    # Step 1: Ingest and Parse raw logs
    print(f"[*] {CLR_BOLD}Stage 1: Log Ingestion & Parsing{CLR_RESET}")
    print(f"    [+] Loading raw file target: '{args.file}'...")
    
    if not os.path.exists(args.file):
        print(f"[-] {CLR_RED}ERROR: Target log file '{args.file}' does not exist.{CLR_RESET}")
        print("    [i] Ensure you run from the correct directory or generate 'sample_logs.csv' first.")
        sys.exit(1)
        
    log_parser = LogParser(args.file)
    records = log_parser.parse_logs()
    summary = log_parser.get_summary()
    
    print(f"    [+] Log parsing completed. Ingested {CLR_GREEN}{summary['total_parsed']} records{CLR_RESET}.")
    if summary['errors_skipped'] > 0:
        print(f"    [{CLR_YELLOW}!{CLR_RESET}] Malformed rows skipped during ingest: {CLR_YELLOW}{summary['errors_skipped']}{CLR_RESET}")
    print(f"    [+] Timeline scope: {summary['span_start']} to {summary['span_end']}")
    print("-" * 80)

    # Step 2: Run Security Threat Analytics
    print(f"[*] {CLR_BOLD}Stage 2: Running Stateful Threat Detection Analytics{CLR_RESET}")
    print(f"    [+] Settings: Brute Force window = {args.brute_window}s, threshold = {args.brute_limit} attempts")
    print(f"    [+] Scanning chronological streams...")
    
    detector = ThreatDetector(records)
    raw_alerts = detector.analyze(
        brute_force_window=args.brute_window, 
        brute_force_limit=args.brute_limit, 
        impossible_travel_window=args.travel_window
    )
    print(f"    [+] Completed signature matching. Found {CLR_YELLOW if raw_alerts else CLR_GREEN}{len(raw_alerts)} threats{CLR_RESET} with base indicators.")
    print("-" * 80)

    # Step 3: Run Contextual Risk Scoring Engine
    print(f"[*] {CLR_BOLD}Stage 3: Running Contextual Risk Engine{CLR_RESET}")
    risk_engine = RiskEngine(raw_alerts, records)
    alerts = risk_engine.process_all_alerts()
    metrics = risk_engine.compile_threat_metrics()
    
    print(f"    [+] Applied risk matrices. Active Incident Severity: {CLR_RED if metrics['counts']['CRITICAL'] or metrics['counts']['HIGH'] else CLR_GREEN}{metrics['max_score']}/100{CLR_RESET}")
    print(f"    [+] Average threat risk score: {metrics['avg_score']}/100")
    print("-" * 80)

    # Real-Time Log Alert Monitor Printing (Mimics active SIEM logs)
    print(f"[*] {CLR_BOLD}Real-Time Alert Feed Stream:{CLR_RESET}")
    print("=" * 80)
    if not alerts:
        print(f"    {CLR_GREEN}[+] SECURE: No alerts triggered during log scans.{CLR_RESET}")
    else:
        for alert in alerts:
            # Colorize output based on risk classification
            risk_lvl = alert['risk_classification']
            score = alert['risk_score']
            
            if risk_lvl == "CRITICAL":
                color_prefix = f"{CLR_RED}{CLR_BOLD}[!!! CRITICAL Alert]"
            elif risk_lvl == "HIGH":
                color_prefix = f"{CLR_RED}[! HIGH Alert]"
            elif risk_lvl == "MEDIUM":
                color_prefix = f"{CLR_YELLOW}[+ MEDIUM Alert]"
            else:
                color_prefix = f"{CLR_GREEN}[* LOW Alert]"
                
            print(f"{color_prefix} ID: {alert['alert_id']} | Risk Score: {score}/100 | {CLR_BOLD}{alert['title']}{CLR_RESET}")
            print(f"    Actor: {alert['primary_actor']} | IP: {alert['ip_address']} | Time: {alert['timestamp']}")
            print(f"    Summary: {alert['details']}")
            print("-" * 80)

    # Step 4: Generate reports
    print(f"[*] {CLR_BOLD}Stage 4: Generating Incident Response Reports{CLR_RESET}")
    report_gen = ReportGenerator(alerts, summary, metrics)
    
    current_dir = os.getcwd()
    txt_path = report_gen.save_reports(
        output_dir=current_dir, 
        text_filename=args.output_txt, 
        json_filename=args.output_json
    )
    
    print(f"    [+] Formatted SOC Report saved to : {CLR_GREEN}{os.path.join(current_dir, args.output_txt)}{CLR_RESET}")
    print(f"    [+] Machine JSON Incident data to : {CLR_GREEN}{os.path.join(current_dir, args.output_json)}{CLR_RESET}")
    print("=" * 80)
    print(f"{CLR_GREEN}{CLR_BOLD}[✓] Incident Triage Routine Completed Successfully.{CLR_RESET}")


if __name__ == "__main__":
    main()`
  },
  {
    name: "log_parser.py",
    path: "log_parser.py",
    language: "python",
    description: "Parser module. Ingests raw CSV/JSON fields, normalizes them into dictionary records, converts strings to timestamp/boolean objects, and handles row errors.",
    code: `# log_parser.py
"""
SOC Log Parser Module
=====================
This module handles reading, validating, and normalizing raw CSV log files.
In a professional SOC workflow, parsing must be resilient to corrupted records, 
missing fields, and malformed timestamps. It transforms raw string data into 
structured dictionaries with typed variables (datetime objects, booleans)
that the Threat Detector and Risk Engine can analyze reliably.
"""

import csv
import sys
from datetime import datetime


class LogParser:
    """
    Handles CSV parsing, field validation, and data normalization for security logs.
    """
    def __init__(self, filepath):
        self.filepath = filepath
        self.parsed_records = []
        self.error_count = 0

    def parse_logs(self):
        """
        Reads CSV and parses each row into a normalized structure.
        Gracefully handles missing files, empty lines, and malformed timestamps.
        """
        try:
            with open(self.filepath, mode='r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                
                # Verify header requirements
                required_headers = {'timestamp', 'username', 'ip_address', 'event_type', 'status', 'details', 'is_admin'}
                actual_headers = set(reader.fieldnames or [])
                missing_headers = required_headers - actual_headers
                
                if missing_headers:
                    print(f"[-] PARSE ERROR: Log file is missing critical security headers: {missing_headers}", file=sys.stderr)
                    sys.exit(1)

                for line_num, row in enumerate(reader, start=2):
                    try:
                        # Extract and strip values
                        raw_time = row['timestamp'].strip()
                        username = row['username'].strip()
                        ip_address = row['ip_address'].strip()
                        event_type = row['event_type'].strip()
                        status = row['status'].strip()
                        details = row['details'].strip()
                        is_admin_str = row['is_admin'].strip().lower()

                        # 1. Normalize Timestamp (Supports ISO 8601 / standard UTC stamps)
                        try:
                            # Replace 'Z' with UTC offset for datetime compatibility
                            clean_time = raw_time.replace('Z', '+00:00')
                            timestamp = datetime.fromisoformat(clean_time)
                        except ValueError:
                            # Fallback parse format for common CSV exports
                            timestamp = datetime.strptime(raw_time, "%Y-%m-%d %H:%M:%S")

                        # 2. Normalize Booleans
                        is_admin = is_admin_str in ('true', '1', 'yes', 'y')

                        # Build structured record
                        record = {
                            'id': line_num - 1,
                            'timestamp': timestamp,
                            'raw_timestamp': raw_time,
                            'username': username,
                            'ip_address': ip_address,
                            'event_type': event_type,
                            'status': status,
                            'details': details,
                            'is_admin': is_admin
                        }
                        self.parsed_records.append(record)

                    except Exception as e:
                        self.error_count += 1
                        print(f"[!] WARNING: Failed parsing log record at line {line_num}: {e}. Skipping.", file=sys.stderr)

            # Sort records chronologically to guarantee accurate time-window threat detection
            self.parsed_records.sort(key=lambda x: x['timestamp'])
            return self.parsed_records

        except FileNotFoundError:
            print(f"[-] CRITICAL ERROR: Log file '{self.filepath}' was not found. Please verify the path.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[-] CRITICAL ERROR during log ingestion: {e}", file=sys.stderr)
            sys.exit(1)

    def get_summary(self):
        """Returns brief statistics on the parser session."""
        return {
            "total_parsed": len(self.parsed_records),
            "errors_skipped": self.error_count,
            "span_start": self.parsed_records[0]['timestamp'] if self.parsed_records else None,
            "span_end": self.parsed_records[-1]['timestamp'] if self.parsed_records else None
        }


# Quick diagnostic check
if __name__ == "__main__":
    import os
    sample_path = os.path.join(os.path.dirname(__file__), 'sample_logs.csv')
    if os.path.exists(sample_path):
        parser = LogParser(sample_path)
        records = parser.parse_logs()
        summary = parser.get_summary()
        print(f"[+] Diagnostic Parsing Success: Loaded {summary['total_parsed']} records.")
        print(f"[+] Time range: {summary['span_start']} to {summary['span_end']}")
    else:
        print(f"[-] Diagnostic Check: 'sample_logs.csv' not found. Put it in: {sample_path}")`
  },
  {
    name: "threat_detector.py",
    path: "threat_detector.py",
    language: "python",
    description: "Threat analytics module. Implements sliding window correlation heuristics for brute force, password spraying, impossible travel speed, unauthorized hours, and privilege escalation indicators.",
    code: `# threat_detector.py
"""
SOC Threat Detector Module
===========================
This module holds the core detection analytics. It operates on chronological lists
of normalized log records, applying stateful sliding windows, heuristic patterns, 
and behavioral analytics to uncover complex cyber threats. 

Detection Analytics Included:
1. Brute Force Detection: Sliding time window tracks failed logins per IP.
   Differentiates between failed (blocked) and successful (compromise!) brute force.
2. Password Spraying Detection: One IP attempting single login failures across multiple accounts.
3. Multi-IP Session / Impossible Travel Anomaly: A single user authenticated from different 
   IP addresses in a short time frame.
4. Privilege Escalation: Non-admin users executing commands or accessing directories that fail 
   due to permissions (e.g., /etc/shadow, sudo su, admin endpoints).
5. Off-Hours / Unusual Login Time: Logins occurring in the vulnerable window (2 AM - 5 AM).
"""

from datetime import timedelta


class ThreatDetector:
    """
    Implements behavioral and rule-based threat detection logic over ingested logs.
    """
    def __init__(self, records):
        # Assumes records are pre-sorted chronologically
        self.records = records
        self.alerts = []
        self._alert_id_counter = 1

    def _create_alert(self, title, category, severity, details, primary_actor, ip_address, triggered_logs):
        """Helper to build a unified alert structure."""
        alert = {
            "alert_id": f"ALRT-{self._alert_id_counter:03d}",
            "title": title,
            "category": category,
            "severity_basis": severity,  # Baseline severity before risk engine tuning
            "details": details,
            "primary_actor": primary_actor,
            "ip_address": ip_address,
            "timestamp": triggered_logs[-1]['timestamp'] if triggered_logs else None,
            "triggered_logs": [log['id'] for log in triggered_logs],
            "log_details": triggered_logs
        }
        self._alert_id_counter += 1
        self.alerts.append(alert)
        return alert

    def analyze(self, brute_force_window=300, brute_force_limit=5, impossible_travel_window=600):
        """
        Runs all configured cybersecurity detection analytics.
        """
        self.detect_brute_force_and_spraying(window_seconds=brute_force_window, limit=brute_force_limit)
        self.detect_impossible_travel(window_seconds=impossible_travel_window)
        self.detect_privilege_escalation()
        self.detect_unusual_hours(start_hour=2, end_hour=5)
        
        # Sort alerts chronologically
        self.alerts.sort(key=lambda x: x['timestamp'] if x['timestamp'] else timedelta())
        return self.alerts

    def detect_brute_force_and_spraying(self, window_seconds=300, limit=5):
        """
        Correlates authentication events per IP to identify Brute Force and Password Spraying.
        - Brute Force: >='limit' login failures for a SINGLE username from one IP within a window.
        - Password Spraying: >='limit' login failures across DIFFERENT usernames from one IP.
        """
        # Sliding window tracker
        for i, current_log in enumerate(self.records):
            if current_log['event_type'] != 'login' or current_log['status'] != 'failed':
                continue
                
            ip = current_log['ip_address']
            user = current_log['username']
            current_time = current_log['timestamp']
            
            # Look backwards in sliding window
            window_start = current_time - timedelta(seconds=window_seconds)
            failures_from_ip = []
            
            for log in self.records[i::-1]: # Scan backwards from current index
                if log['timestamp'] < window_start:
                    break
                if log['ip_address'] == ip and log['event_type'] == 'login' and log['status'] == 'failed':
                    failures_from_ip.append(log)

            # Analyze failures within the window
            if len(failures_from_ip) >= limit:
                # 1. Determine if it is a single user target (Brute Force) or password spraying (multi-user)
                targeted_users = {log['username'] for log in failures_from_ip}
                
                # Check if we have already alerted for this window/incident cluster to prevent duplicate alerts
                already_alerted = False
                for alt in self.alerts:
                    if alt['category'] in ("BRUTE_FORCE", "PASSWORD_SPRAY") and alt['ip_address'] == ip:
                        # If the time difference is within the window, skip duplicate
                        if abs((alt['timestamp'] - current_time).total_seconds()) < window_seconds:
                            already_alerted = True
                            break
                            
                if already_alerted:
                    continue

                if len(targeted_users) == 1:
                    # BRUTE FORCE DETECTED
                    target_user = list(targeted_users)[0]
                    
                    # Core SOC Logic: Check if they eventually logged in successfully from the same IP (Brute Force Compromise!)
                    compromised = False
                    success_log = None
                    # Scan forward a short time to see if login succeeds
                    for log in self.records[i+1:]:
                        if (log['timestamp'] - current_time).total_seconds() > 300: # 5 mins forward
                            break
                        if log['ip_address'] == ip and log['username'] == target_user and log['event_type'] == 'login' and log['status'] == 'success':
                            compromised = True
                            success_log = log
                            break
                    
                    if compromised and success_log:
                        triggered = failures_from_ip + [success_log]
                        details = (f"IP address {ip} conducted brute-force attacks against account '{target_user}' "
                                   f"with {len(failures_from_ip)} failures, and SUCCESSFULLY COMPROMISED the account "
                                   f"at {success_log['raw_timestamp']}.")
                        self._create_alert(
                            title="Successful Brute Force Compromise",
                            category="BRUTE_FORCE_SUCCESS",
                            severity="CRITICAL", # Success is a catastrophic security event
                            details=details,
                            primary_actor=target_user,
                            ip_address=ip,
                            triggered_logs=triggered
                        )
                    else:
                        details = (f"IP address {ip} performed brute-force attempts on username '{target_user}' "
                                   f"with {len(failures_from_ip)} failures inside a 5-minute sliding window.")
                        self._create_alert(
                            title="Brute Force Attack Attempt",
                            category="BRUTE_FORCE",
                            severity="HIGH", # Blocked attempt is still a high threat
                            details=details,
                            primary_actor=target_user,
                            ip_address=ip,
                            triggered_logs=failures_from_ip
                        )
                else:
                    # PASSWORD SPRAY DETECTED
                    details = (f"IP address {ip} conducted password-spraying attacks against {len(targeted_users)} accounts "
                               f"({', '.join(list(targeted_users)[:4])}...) with {len(failures_from_ip)} total failures in a 5-minute window.")
                    self._create_alert(
                        title="Password Spray Attack Detected",
                        category="PASSWORD_SPRAY",
                        severity="HIGH",
                        details=details,
                        primary_actor="MULTIPLE_ACCOUNTS",
                        ip_address=ip,
                        triggered_logs=failures_from_ip
                    )

    def detect_impossible_travel(self, window_seconds=600):
        """
        Flags single accounts authenticated from different IP addresses within a tight time window.
        In a cloud/on-prem hybrid SOC, this often indicates credential sharing, session hijacking, or VPN leaks.
        """
        user_logins = {}
        for log in self.records:
            if log['event_type'] == 'login' and log['status'] == 'success':
                user = log['username']
                if user not in user_logins:
                    user_logins[user] = []
                user_logins[user].append(log)

        for user, logins in user_logins.items():
            if len(logins) < 2:
                continue
                
            for i in range(1, len(logins)):
                prev_login = logins[i-1]
                curr_login = logins[i]
                
                time_diff = (curr_login['timestamp'] - prev_login['timestamp']).total_seconds()
                
                # Check if logins occurred within time limit from different IPs
                if time_diff <= window_seconds and prev_login['ip_address'] != curr_login['ip_address']:
                    # Ensure we don't duplicate alerts for this user/IP pair in this cluster
                    already_alerted = False
                    for alt in self.alerts:
                        if alt['category'] == "IMPOSSIBLE_TRAVEL" and alt['primary_actor'] == user:
                            if abs((alt['timestamp'] - curr_login['timestamp']).total_seconds()) < window_seconds:
                                already_alerted = True
                                break
                    if already_alerted:
                        continue

                    details = (f"Suspicious session activity for '{user}': Logged in from internal IP {prev_login['ip_address']} "
                               f"and external IP {curr_login['ip_address']} within {int(time_diff)} seconds. "
                               f"This indicates physically impossible travel speeds.")
                    self._create_alert(
                        title="Impossible Travel & Concurrent Session Anomaly",
                        category="IMPOSSIBLE_TRAVEL",
                        severity="HIGH",
                        details=details,
                        primary_actor=user,
                        ip_address=curr_login['ip_address'],
                        triggered_logs=[prev_login, curr_login]
                    )

    def detect_privilege_escalation(self):
        """
        Traces command executions or file accesses by standard users that fail due to permissions,
        using deep keyword heuristics representing an adversary hunting for local admin rights.
        """
        # Indicators of compromise (IOC) list for privilege escalation hunting
        priv_keywords = ['sudo', 'root', '/etc/shadow', 'unauthorized', 'secure', 'sam-registry', 'passwords']
        
        for log in self.records:
            if log['status'] == 'failed' and log['event_type'] in ('command_execution', 'file_access', 'configuration_change'):
                details_lower = log['details'].lower()
                
                # Check if it contains privilege keywords and was conducted by a standard user
                is_priv_escalation = any(kw in details_lower for kw in priv_keywords)
                
                if is_priv_escalation and not log['is_admin']:
                    details = (f"Non-privileged user '{log['username']}' attempted a restricted action: "
                               f"'{log['details']}'. Event failed with unauthorized permission codes.")
                    self._create_alert(
                        title="Privilege Escalation Attempt Blocked",
                        category="PRIVILEGE_ESCALATION",
                        severity="MEDIUM", # Blocked actions are medium; repeated ones escalate in risk engine
                        details=details,
                        primary_actor=log['username'],
                        ip_address=log['ip_address'],
                        triggered_logs=[log]
                    )

    def detect_unusual_hours(self, start_hour=2, end_hour=5):
        """
        Identifies interactive logins occurring during high-vulnerability periods (default 2 AM to 5 AM).
        SOC Analysts track these because adversaries often deploy ransomware or perform exfiltration during quiet hours.
        """
        for log in self.records:
            if log['event_type'] == 'login' and log['status'] == 'success':
                login_hour = log['timestamp'].hour
                
                if start_hour <= login_hour <= end_hour:
                    # Avoid alerting for automated system services by validating if is_admin and standard details
                    is_service = "service" in log['username'].lower() or "sync" in log['username'].lower()
                    
                    if is_service:
                        continue # Skip alerting on known automated service accounts
                        
                    # Prevent duplicate off-hours alerts for the same user on the same day
                    already_alerted = False
                    for alt in self.alerts:
                        if alt['category'] == "UNUSUAL_TIME" and alt['primary_actor'] == log['username']:
                            if alt['timestamp'].date() == log['timestamp'].date():
                                already_alerted = True
                                break
                    if already_alerted:
                        continue

                    details = (f"Interactive logon by user '{log['username']}' at {log['raw_timestamp']} "
                               f"({login_hour:02d}:{log['timestamp'].minute:02d} local time) which is outside "
                               f"normal working hours (Off-hours window: {start_hour}AM-{end_hour}AM).")
                    
                    # Off-hours logins by admins are treated with higher baseline severity
                    sev = "HIGH" if log['is_admin'] else "MEDIUM"
                    title = "Administrative Login during Anomalous Hours" if log['is_admin'] else "User Logon during Anomalous Hours"
                    
                    self._create_alert(
                        title=title,
                        category="UNUSUAL_TIME",
                        severity=sev,
                        details=details,
                        primary_actor=log['username'],
                        ip_address=log['ip_address'],
                        triggered_logs=[log]
                    )`
  },
  {
    name: "risk_engine.py",
    path: "risk_engine.py",
    language: "python",
    description: "The mathematical risk compiler. Calculates risk metrics (0-100) combining base signature severity with security multipliers: compromise outcomes, administrative credentials, public vs private subnets, and repeated alarms.",
    code: `# risk_engine.py
"""
SOC Risk Scoring Engine Module
===============================
This module dynamically computes risk scores (0 to 100) for security alerts 
and actor entities. In real cybersecurity environments, risk calculation must go 
beyond basic static rules; it must account for contextual signals such as:
1. Privileged status (e.g., Administrator / root accounts).
2. Threat amplification (e.g., an actor involved in multiple distinct alerts).
3. Attack outcomes (e.g., successfully breaking in vs. failing to log in).
4. Network classification (e.g., external public IP vs. local LAN subnets).

Risk classifications:
-   0 to 30:  [LOW RISK]        Non-critical, standard operational deviations.
-  31 to 60:  [MEDIUM RISK]     Suspicious behavior requiring passive tracking.
-  61 to 80:  [HIGH RISK]       Active threat requiring timely human triage.
-  81 to 100: [CRITICAL RISK]   Confirmed compromise or imminent danger. Immediate action required.
"""

import re


class RiskEngine:
    """
    Computes mathematical risk scores based on context modifiers and stateful threat records.
    """
    def __init__(self, alerts, logs):
        self.alerts = alerts
        self.logs = logs
        # Count frequency of actor alerts for threat amplification calculations
        self.actor_incident_counts = {}
        self._precompute_actor_activity()

    def _precompute_actor_activity(self):
        """Builds a directory of how many times each username and IP appears in alerts."""
        for alert in self.alerts:
            actor = alert['primary_actor']
            ip = alert['ip_address']
            
            if actor != "MULTIPLE_ACCOUNTS":
                self.actor_incident_counts[actor] = self.actor_incident_counts.get(actor, 0) + 1
            if ip and ip != "N/A":
                self.actor_incident_counts[ip] = self.actor_incident_counts.get(ip, 0) + 1

    def calculate_risk_score(self, alert):
        """
        Dynamically calculates a risk score from 0 to 100 for a given alert.
        Applies mathematical weightings and environmental offsets.
        """
        # 1. Base Score from initial severity classification
        severity = alert['severity_basis'].upper()
        if severity == "CRITICAL":
            score = 85
        elif severity == "HIGH":
            score = 65
        elif severity == "MEDIUM":
            score = 40
        else:
            score = 15

        # 2. Status Modifier: Did the threat succeed?
        # A successful attack is far more dangerous than an unsuccessful attempt.
        is_successful_attack = (
            "SUCCESS" in alert['category'] or 
            any(log['status'] == 'success' for log in alert.get('log_details', []))
        )
        if is_successful_attack:
            score += 15

        # 3. Privilege Modifier: Are administrative credentials compromised?
        is_admin_involved = any(log.get('is_admin', False) for log in alert.get('log_details', []))
        if is_admin_involved:
            score += 10

        # 4. Network Subnet Modifier: External public IPs vs Internal LAN subnets
        ip = alert['ip_address']
        if ip and ip != "N/A":
            is_internal = ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.")
            if not is_internal:
                # External threat actors are classified higher
                score += 8

        # 5. Threat Amplification Modifier: Has this entity triggered multiple alerts?
        actor = alert['primary_actor']
        actor_count = self.actor_incident_counts.get(actor, 0)
        ip_count = self.actor_incident_counts.get(ip, 0) if ip else 0
        
        # Add +5 points for each additional alert involving this actor/IP
        extra_incidents = max(0, max(actor_count, ip_count) - 1)
        score += min(15, extra_incidents * 5)

        # 6. Contain and cap between 0 and 100
        final_score = max(0, min(100, score))
        return int(final_score)

    def classify_risk(self, score):
        """Maps numeric score to standard SOC risk levels."""
        if score <= 30:
            return "LOW"
        elif score <= 60:
            return "MEDIUM"
        elif score <= 80:
            return "HIGH"
        else:
            return "CRITICAL"

    def process_all_alerts(self):
        """
        Processes every alert, injects calculated scores, and assigns final classifications.
        """
        enriched_alerts = []
        for alert in self.alerts:
            score = self.calculate_risk_score(alert)
            classification = self.classify_risk(score)
            
            # Enrich alert dictionary
            alert['risk_score'] = score
            alert['risk_classification'] = classification
            enriched_alerts.append(alert)

        # Re-sort alerts by risk score descending (highest threat first!)
        enriched_alerts.sort(key=lambda x: x['risk_score'], reverse=True)
        return enriched_alerts

    def compile_threat_metrics(self):
        """Returns aggregated risk metrics for executive summaries."""
        total_alerts = len(self.alerts)
        if total_alerts == 0:
            return {"max_score": 0, "avg_score": 0, "categories": {}, "counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}}

        scores = [a['risk_score'] for a in self.alerts]
        classifications = [a['risk_classification'] for a in self.alerts]
        
        counts = {
            "LOW": classifications.count("LOW"),
            "MEDIUM": classifications.count("MEDIUM"),
            "HIGH": classifications.count("HIGH"),
            "CRITICAL": classifications.count("CRITICAL")
        }

        return {
            "max_score": max(scores),
            "avg_score": round(sum(scores) / len(scores), 1),
            "counts": counts
        }
`
  },
  {
    name: "report_generator.py",
    path: "report_generator.py",
    language: "python",
    description: "The Incident Report Compiler. Translates incident metrics, top offenders, chronologies, and detections into highly polished, executive TXT briefs and structured machine JSON records with remediation checklists.",
    code: `# report_generator.py
"""
SOC Incident Report Generator Module
====================================
Transforms structural threat alerts into highly professional security reports.
Generates both human-readable standard SOC incident summaries (TXT) and 
machine-readable JSON schemas for SIEM ingestion or automated ticketing.

Includes customized SOC containment, eradication, and defense recommendations
tailored directly to the specific threat types identified.
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    """
    Formats parsed security results and threat alerts into executive and tactical reports.
    """
    def __init__(self, alerts, parser_summary, risk_metrics):
        self.alerts = alerts
        self.parser_summary = parser_summary
        self.metrics = risk_metrics
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _get_remediation_steps(self, alert_category):
        """Returns standard NIST SP 800-61 Incident Response playbook actions based on threat."""
        category = alert_category.upper()
        
        playbooks = {
            "BRUTE_FORCE_SUCCESS": [
                "[IMMEDIATE] Suspend credentials for the compromised user account.",
                "[IMMEDIATE] Terminate all active sessions/tokens for this user across all identity providers.",
                "[CONTAINMENT] Add the attacking IP to the perimeter firewall / Web Application Firewall (WAF) blocklist.",
                "[INVESTIGATION] Review audit trails for files read/modified by this user within 60 minutes after compromise.",
                "[HARDENING] Implement account lockouts (e.g., lock for 30 mins after 5 failures) and enforce Multi-Factor Authentication (MFA)."
            ],
            "BRUTE_FORCE": [
                "[CONTAINMENT] Temporarily block the source IP address on the host or perimeter firewall.",
                "[HARDENING] Audit target account password strength and verify MFA registration.",
                "[MONITORING] Increase logging verbosity on targeted authentication systems."
            ],
            "PASSWORD_SPRAY": [
                "[CONTAINMENT] Apply dynamic rate limiting or IP blocklists to the source IP.",
                "[INVESTIGATION] Confirm if any sprayed user account logged in successfully from other IPs around the same time.",
                "[HARDENING] Enforce modern password policy standards and restrict access via Geo-IP policies."
            ],
            "IMPOSSIBLE_TRAVEL": [
                "[IMMEDIATE] Force-logout all sessions and trigger password reset for the affected user.",
                "[CONTAINMENT] Require step-up MFA challenge for all logins from external/non-corporate IP ranges.",
                "[INVESTIGATION] Examine user-agent strings and compare browser profiles of both sessions."
            ],
            "PRIVILEGE_ESCALATION": [
                "[IMMEDIATE] Isolate the compromised host/workstation from the network segment.",
                "[CONTAINMENT] Disable the offending user account until identity can be verified.",
                "[INVESTIGATION] Check for unauthorized local administrative group changes (e.g., local Administrators, wheel, sudoers).",
                "[HARDENING] Enforce Principle of Least Privilege and deploy Endpoint Detection & Response (EDR) agents to detect local privilege tools."
            ],
            "UNUSUAL_TIME": [
                "[MONITORING] Contact the affected user out-of-band to verify if login was authorized business activity.",
                "[INVESTIGATION] Check if the workstation has scheduled tasks or background scripts executing on behalf of this user.",
                "[HARDENING] Establish restrictive conditional access policies for off-hours login windows unless explicitly whitelisted."
            ]
        }
        
        return playbooks.get(category, [
            "Triage alert and verify legitimacy of the activity.",
            "Verify source IP reputation via external Threat Intel channels.",
            "Monitor user's surrounding actions for 4 hours."
        ])

    def generate_json_report(self):
        """Produces a structured JSON document representing the SOC investigation state."""
        report = {
            "metadata": {
                "generated_at": self.timestamp,
                "tool": "Automated Security Log Analyzer & Threat Detection System",
                "analyst_tier": "SOC Tier 2 Automator"
            },
            "ingestion_stats": {
                "total_records_analyzed": self.parser_summary["total_parsed"],
                "records_skipped_errors": self.parser_summary["errors_skipped"],
                "log_chronological_start": str(self.parser_summary["span_start"]),
                "log_chronological_end": str(self.parser_summary["span_end"])
            },
            "risk_metrics": self.metrics,
            "detected_threats": []
        }

        for alert in self.alerts:
            alert_copy = {
                "alert_id": alert["alert_id"],
                "title": alert["title"],
                "category": alert["category"],
                "risk_score": alert["risk_score"],
                "severity_level": alert["risk_classification"],
                "primary_actor": alert["primary_actor"],
                "ip_address": alert["ip_address"],
                "timestamp": str(alert["timestamp"]),
                "summary": alert["details"],
                "remediation_playbook": self._get_remediation_steps(alert["category"]),
                "associated_log_ids": alert["triggered_logs"]
            }
            report["detected_threats"].append(alert_copy)

        return json.dumps(report, indent=4)

    def generate_text_report(self):
        """Produces a highly readable, executive-ready TXT incident report."""
        lines = []
        border = "=" * 80
        section_border = "-" * 80
        
        lines.append(border)
        lines.append("                 SOC INCIDENT REPORT & THREAT DETECTION SUMMARY")
        lines.append(border)
        lines.append(f"Report Generated At : {self.timestamp}")
        lines.append(f"Logs Analyzed       : {self.parser_summary['total_parsed']} events")
        lines.append(f"Log Time Span       : {self.parser_summary['span_start']} to {self.parser_summary['span_end']}")
        lines.append(border)
        lines.append("")
        
        # 1. EXECUTIVE SUMMARY
        lines.append("1. EXECUTIVE SUMMARY")
        lines.append(section_border)
        total_threats = len(self.alerts)
        if total_threats == 0:
            lines.append("[+] SECURITY STATUS: SECURE")
            lines.append("    No threat indicators or anomalous behavioral footprints were detected.")
        else:
            lines.append(f"[-] SECURITY STATUS: ACTION REQUIRED - {total_threats} alerts triggered")
            lines.append(f"    Max Incident Risk Score : {self.metrics['max_score']}/100")
            lines.append(f"    Average Alert Risk Score: {self.metrics['avg_score']}/100")
            lines.append("")
            lines.append("    Risk Severity Counts:")
            lines.append(f"      - CRITICAL : {self.metrics['counts']['CRITICAL']} alert(s)")
            lines.append(f"      - HIGH     : {self.metrics['counts']['HIGH']} alert(s)")
            lines.append(f"      - MEDIUM   : {self.metrics['counts']['MEDIUM']} alert(s)")
            lines.append(f"      - LOW      : {self.metrics['counts']['LOW']} alert(s)")
        lines.append("")
        
        # 2. TOP SUSPICIOUS ENTITIES
        if total_threats > 0:
            lines.append("2. CHIEF THREAT ACTORS & SUSPICIOUS IPs")
            lines.append(section_border)
            actors = {}
            ips = {}
            for alert in self.alerts:
                act = alert['primary_actor']
                ip = alert['ip_address']
                if act and act != "MULTIPLE_ACCOUNTS":
                    actors[act] = actors.get(act, 0) + 1
                if ip and ip != "N/A":
                    ips[ip] = ips.get(ip, 0) + 1
                    
            top_actors = sorted(actors.items(), key=lambda x: x[1], reverse=True)[:3]
            top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:3]
            
            lines.append("    Top Target/Offending Usernames:")
            for act, count in top_actors:
                lines.append(f"      - {act} (triggered {count} alert(s))")
            if not top_actors:
                lines.append("      - None")
                
            lines.append("    Top Source IP Addresses:")
            for ip, count in top_ips:
                lines.append(f"      - {ip} (triggered {count} alert(s))")
            if not top_ips:
                lines.append("      - None")
            lines.append("")

        # 3. CHRONOLOGICAL TIMELINE
        lines.append("3. DETECTED SECURITY INCIDENTS TIMELINE (HIGHEST RISK FIRST)")
        lines.append(section_border)
        if total_threats == 0:
            lines.append("    No events detected.")
        else:
            for idx, alert in enumerate(self.alerts, 1):
                lines.append(f"[{idx}] {alert['title'].upper()}")
                lines.append(f"    Alert ID       : {alert['alert_id']}")
                lines.append(f"    Time of Event  : {alert['timestamp']}")
                lines.append(f"    Threat Category: {alert['category']}")
                lines.append(f"    Primary Actor  : {alert['primary_actor']}")
                lines.append(f"    Source IP      : {alert['ip_address']}")
                lines.append(f"    Risk Score     : {alert['risk_score']}/100 ({alert['risk_classification']})")
                lines.append("    Description    : " + alert['details'])
                lines.append("")
        
        # 4. REMEDIATION RECOMMENDATIONS
        if total_threats > 0:
            lines.append("4. TACTICAL REMEDIATION PLAYBOOKS (NIST SP 800-61 COOLDOWN)")
            lines.append(section_border)
            # Gather unique categories to prevent duplicating playbooks
            categories_handled = set()
            for alert in self.alerts:
                cat = alert['category']
                if cat in categories_handled:
                    continue
                categories_handled.add(cat)
                
                lines.append(f"--> Playbook for category: {cat}")
                steps = self._get_remediation_steps(cat)
                for step in steps:
                    lines.append(f"    [ ] {step}")
                lines.append("")
        
        lines.append(border)
        lines.append("                 SOC REPORT GENERATOR - SECURE OPERATIONS TIER")
        lines.append(border)
        
        return "\\n".join(lines)

    def save_reports(self, output_dir, text_filename, json_filename=None):
        """Writes reports to physical files."""
        os.makedirs(output_dir, exist_ok=True)
        
        text_path = os.path.join(output_dir, text_filename)
        with open(text_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_text_report())
            
        if json_filename:
            json_path = os.path.join(output_dir, json_filename)
            with open(json_path, 'w', encoding='utf-8') as f:
                f.write(self.generate_json_report())
                
        return text_path`
  },
  {
    name: "sample_logs.csv",
    path: "sample_logs.csv",
    language: "csv",
    description: "A comprehensive sample dataset containing 30 logs with regular activity and multi-stage attack patterns (Brute force attempts and success, Impossible geographical travel VPN logins, Privilege escalation command failures, and Off-hours admin logons).",
    code: `timestamp,username,ip_address,event_type,status,details,is_admin
2026-07-01T09:00:15Z,a.vance,192.168.10.25,login,success,Desktop workstation login,false
2026-07-01T09:05:22Z,a.vance,192.168.10.25,file_access,success,Accessed /share/marketing/q3_plan.pdf,false
2026-07-01T10:15:00Z,db_sync,10.0.5.14,database_query,success,Synchronized core transaction table,false
2026-07-01T11:00:00Z,sec_engineer,192.168.10.15,login,success,SOC SIEM workstation connection,true
2026-07-01T11:15:30Z,sec_engineer,192.168.10.15,configuration_change,success,Updated firewall log forwarding rules,true
2026-07-01T14:20:01Z,admin,198.51.100.42,login,failed,Invalid password credentials,true
2026-07-01T14:20:12Z,admin,198.51.100.42,login,failed,Invalid password credentials,true
2026-07-01T14:20:25Z,admin,198.51.100.42,login,failed,Invalid password credentials,true
2026-07-01T14:20:38Z,admin,198.51.100.42,login,failed,Invalid password credentials,true
2026-07-01T14:20:50Z,admin,198.51.100.42,login,failed,Invalid password credentials,true
2026-07-01T14:21:05Z,admin,198.51.100.42,login,success,Successful login after multiple failures,true
2026-07-01T15:30:00Z,m.rogers,192.168.10.82,login,success,Workstation login (internal subnet),false
2026-07-01T15:35:12Z,m.rogers,45.223.10.12,login,success,Login from external IP (Berlin DE VPN),false
2026-07-01T15:38:00Z,m.rogers,45.223.10.12,file_access,success,Read /share/financials/salaries.xlsx,false
2026-07-01T16:45:10Z,test_user,192.168.12.110,login,success,Standard login,false
2026-07-01T16:46:15Z,test_user,192.168.12.110,command_execution,failed,Attempted sudo access to /etc/shadow without privilege,false
2026-07-01T16:47:00Z,test_user,192.168.12.110,file_access,failed,Unauthorized read on /var/log/secure,false
2026-07-01T17:01:22Z,unknown_svc,185.220.101.5,login,failed,Authentication failure - username not found,false
2026-07-01T17:01:35Z,root,185.220.101.5,login,failed,Authentication failure - incorrect password,true
2026-07-01T17:01:50Z,root,185.220.101.5,login,failed,Authentication failure - incorrect password,true
2026-07-01T17:02:10Z,root,185.220.101.5,login,failed,Authentication failure - incorrect password,true
2026-07-01T17:02:30Z,root,185.220.101.5,login,failed,Authentication failure - incorrect password,true
2026-07-01T02:14:10Z,b.jones,192.168.10.55,login,success,Workstation login (Off-hours),false
2026-07-01T03:45:00Z,service_agent,10.0.5.20,database_query,success,Regular backup agent execution,false
2026-07-01T04:12:05Z,a.vance,198.51.100.99,login,success,Domain Controller administrator console login,true
2026-07-01T18:22:15Z,system_admin,192.168.10.5,login,success,Active Directory synchronization,true
2026-07-01T18:30:10Z,system_admin,192.168.10.5,configuration_change,success,Modified domain password policy,true
2026-07-01T19:00:00Z,t.clark,192.168.10.102,login,success,Workstation login,false
2026-07-01T19:02:45Z,t.clark,192.168.10.102,file_access,success,Read /share/it/passwords.txt.tmp,false
2026-07-01T19:05:00Z,t.clark,192.168.10.102,command_execution,success,Uploaded local script to domain backup share,false`
  },
  {
    name: "requirements.txt",
    path: "requirements.txt",
    language: "text",
    description: "The dependencies definition file. This system is designed for maximum portabilty using the Python Standard Library (3.8+), ensuring zero external dependency bloat.",
    code: `# Automated Security Log Analyzer & Threat Detection System
# Requirements File
#
# This project is designed to be highly portable, running entirely on the Python Standard Library
# (3.8+) without external dependencies, making it ideal for incident response triage in restricted environments.
#
# Optional dependencies for advanced data visualization and analyst use:
matplotlib>=3.5.0
pandas>=1.4.0`
  },
  {
    name: "README.md",
    path: "README.md",
    language: "markdown",
    description: "Comprehensive documentation. Explains architecture, security algorithms, mathematical risk modifiers, and enterprise deployment best practices.",
    code: `# Automated Security Log Analyzer & Threat Detection System

A highly structured, modular, and realistic Python application simulating a Tier 2/3 Security Operations Center (SOC) incident triage workflow. This project is built specifically to highlight production-grade threat parsing, behavioral correlation rules, risk scoring, and professional incident reporting.

It can be showcased as a **Cybersecurity Portfolio Project** for SOC Analyst, Incident Responder, or security engineering job applications.

---

## 🛠️ System Architecture & Codebase Design

The project strictly decouples core responsibilities into distinct modules, aligning with standard enterprise software engineering and security operations principles:

1.  **\`main.py\`** — The command-line orchestration module. Parses input flags, executes the pipeline phases, and streams colorful real-time detection logs directly to the SOC terminal.
2.  **\`log_parser.py\`** — Ingests and sanitizes raw CSV logs. Normalizes datatypes (ISO 8601 timestamps, boolean operators), sorts records chronologically, and handles malformed rows gracefully to ensure high-fidelity downstream analytics.
3.  **\`threat_detector.py\`** — Tracks stateful sliding windows, heuristic patterns, and multi-event correlations to identify intrusion signatures (IoCs).
4.  **\`risk_engine.py\`** — The dynamic risk scoring engine. Translates raw alert indicators into contextual risk metrics (0-100) based on administrator status, successful/failed attack outcomes, external IP reputations, and threat amplification frequencies.
5.  **\`report_generator.py\`** — Exports both a detailed, human-readable executive incident report (\`.txt\`) and a machine-readable JSON structure (\`.json\`) containing complete forensic metrics and NIST-aligned remediation playbooks.
6.  **\`sample_logs.csv\`** — A realistic security event log dataset featuring normal administrative traffic interspersed with active, multi-stage attack scenarios.

---

## 🔍 Security Detection Playbooks Covered

This analyzer implements advanced rule-based correlation heuristics to identify standard enterprise threats:

*   **Brute Force Attacks (\`BRUTE_FORCE\`)**: Detects multiple consecutive failed logins (\`>= 5\` failures) targeting a single account from a single IP address within a 5-minute sliding window.
*   **Brute Force Success (\`BRUTE_FORCE_SUCCESS\`)**: Tracks if a brute-force IP address eventually registers a successful authentication within a short period of time. This signifies a **confirmed credential compromise** (Critical Alert).
*   **Password Spraying (\`PASSWORD_SPRAY\`)**: Detects an IP attempting failed logins across multiple *different* accounts in a 5-minute sliding window, seeking to bypass standard single-account lockout thresholds.
*   **Impossible Travel (\`IMPOSSIBLE_TRAVEL\`)**: Identifies accounts registering successful logins from geographically distant IP addresses (such as an internal workstation and an external VPN IP) within a tight timeline (e.g. less than 10 minutes), flagging potential session hijacking.
*   **Privilege Escalation (\`PRIVILEGE_ESCALATION\`)**: Analyzes standard user activity for unauthorized command executions or access attempts targeting critical system paths (such as reading \`/etc/shadow\` or executing unauthorized \`sudo su\` commands).
*   **Off-Hours Activity Anomaly (\`UNUSUAL_TIME\`)**: Highlights successful logons made by non-service accounts during highly vulnerable windows (specifically 2:00 AM to 5:00 AM local time), a common indicator of exfiltration or ransomware planting.

---

## 📊 Contextual Risk Scoring Matrix

The \`RiskEngine\` computes a contextual risk score from **0 to 100** by combining base alert severity with multiple environmental multipliers:

| Variable | Influence on Score | Cybersecurity Rationale |
| :--- | :--- | :--- |
| **Base Classifications** | Low: \`15\` \\| Med: \`40\` \\| High: \`65\` \\| Critical: \`85\` | Baseline severity based on type of signature matched. |
| **Attack Outcome** | Successful attack = \`+15\` points | Failed login attempts are noise; a successful login after failures indicates a breached security perimeter. |
| **Privilege Level** | Administrator accounts = \`+10\` points | Compromised admin keys represent unrestricted domain-level access. |
| **Origin Subnet** | Public / External IP = \`+8\` points | Activity coming from external IP addresses bypasses standard internal intranet network defenses. |
| **Threat Amplification** | Actor repeated alerts = \`+5\` per alert (Max \`+15\`) | Entities triggering multiple independent alarms represent a persistent, targeted threat campaign. |

### Risk Level Classifications
*   **\`0 - 30\` (Low Risk)**: Minor compliance deviations or passive alerts.
*   **\`31 - 60\` (Medium Risk)**: Anomalous activity deserving passive logging and monitoring.
*   **\`61 - 80\` (High Risk)**: Active attack behaviors requiring swift human triage.
*   **\`81 - 100\` (Critical Risk)**: Highly probable active compromises. Requires immediate host isolation and containment procedures.

---

## 🚀 Getting Started

### Prerequisites

The project operates entirely on the **Python 3 Standard Library**, requiring **no third-party dependencies** to compile and run.

### Installation

1.  Clone this directory (or copy the scripts into a local folder).
2.  Verify your Python installation (Python 3.8+ recommended):
    \`\`\`bash
    python3 --version
    \`\`\`

### Running the Analyzer

Run the analyzer on the pre-loaded sample dataset:
\`\`\`bash
python3 main.py --file sample_logs.csv
\`\`\`

To customize thresholds via CLI arguments:
\`\`\`bash
python3 main.py --file sample_logs.csv --brute-limit 3 --brute-window 600 --travel-window 1200
\`\`\`

### Reviewing the Output Reports

After execution completes, the system writes security reports directly to your directory:
*   **\`soc_incident_report.txt\`** — Printout-ready TXT incident brief. Includes an executive summary, Chief Threat Actor stats, a chronological incident timeline, and detailed remediation action lists.
*   **\`soc_incident_report.json\`** — Machine-readable structured telemetry for SIEM ingestion or Python visualization.

---

## 💼 Real-World SOC Deployment Concept

In a practical enterprise environment, a SOC Analyst or Security Engineer would deploy this system in several ways:

1.  **SIEM Event Forwarder**: Connected to standard system log exports (e.g., Windows Event logs parsed to CSV, or Linux \`/var/log/auth.log\`) as a scheduled cron job (running every 5 minutes) to perform localized, high-speed security summaries.
2.  **IR Forensic Triage**: Uploaded to an isolated, compromised endpoint during an Incident Response (IR) engagement to scrape local logs and instantly isolate compromised admin credentials without waiting for SIEM searches.
3.  **SOAR Orchestration**: Integrated within SOAR tools (like Palo Alto Cortex XSOAR or Splunk Phantom). The JSON report generated by this tool can trigger automatic webhooks to suspend active Active Directory accounts or block attacking IPs on perimeter firewalls.
`
  }
];
