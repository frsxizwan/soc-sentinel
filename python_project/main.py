#!/usr/bin/env python3
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
CLR_RESET = "\033[0m"
CLR_RED = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_GREEN = "\033[92m"
CLR_CYAN = "\033[96m"
CLR_MAGENTA = "\033[95m"
CLR_BOLD = "\033[1m"


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
    main()
