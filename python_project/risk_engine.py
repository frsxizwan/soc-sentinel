# risk_engine.py
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
