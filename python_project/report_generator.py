# report_generator.py
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
        
        return "\n".join(lines)

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
                
        return text_path
