# threat_detector.py
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
                    )
