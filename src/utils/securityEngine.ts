// src/utils/securityEngine.ts

export interface LogRecord {
  id: number;
  timestamp: Date;
  raw_timestamp: string;
  username: string;
  ip_address: string;
  event_type: string;
  status: 'success' | 'failed' | string;
  details: string;
  is_admin: boolean;
}

export interface RuleSettings {
  bruteForceLimit: number;
  bruteForceWindow: number; // in seconds
  travelWindow: number; // in seconds
}

export interface SecurityAlert {
  alert_id: string;
  title: string;
  category: string;
  severity_basis: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details: string;
  primary_actor: string;
  ip_address: string;
  timestamp: Date;
  triggered_logs: number[]; // log IDs
  risk_score?: number;
  risk_classification?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  remediation_playbook?: string[];
}

export interface SecurityMetrics {
  max_score: number;
  avg_score: number;
  counts: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
}

// Remediation playbook selector
export function getRemediationPlaybook(category: string): string[] {
  const cat = category.toUpperCase();
  const playbooks: Record<string, string[]> = {
    BRUTE_FORCE_SUCCESS: [
      "[IMMEDIATE] Suspend credentials for the compromised user account.",
      "[IMMEDIATE] Terminate all active sessions/tokens for this user across all identity providers.",
      "[CONTAINMENT] Add the attacking IP to the perimeter firewall / Web Application Firewall (WAF) blocklist.",
      "[INVESTIGATION] Review audit trails for files read/modified by this user within 60 minutes after compromise.",
      "[HARDENING] Implement account lockouts (e.g., lock for 30 mins after 5 failures) and enforce Multi-Factor Authentication (MFA)."
    ],
    BRUTE_FORCE: [
      "[CONTAINMENT] Temporarily block the source IP address on the host or perimeter firewall.",
      "[HARDENING] Audit target account password strength and verify MFA registration.",
      "[MONITORING] Increase logging verbosity on targeted authentication systems."
    ],
    PASSWORD_SPRAY: [
      "[CONTAINMENT] Apply dynamic rate limiting or IP blocklists to the source IP.",
      "[INVESTIGATION] Confirm if any sprayed user account logged in successfully from other IPs around the same time.",
      "[HARDENING] Enforce modern password policy standards and restrict access via Geo-IP policies."
    ],
    IMPOSSIBLE_TRAVEL: [
      "[IMMEDIATE] Force-logout all sessions and trigger password reset for the affected user.",
      "[CONTAINMENT] Require step-up MFA challenge for all logins from external/non-corporate IP ranges.",
      "[INVESTIGATION] Examine user-agent strings and compare browser profiles of both sessions."
    ],
    PRIVILEGE_ESCALATION: [
      "[IMMEDIATE] Isolate the compromised host/workstation from the network segment.",
      "[CONTAINMENT] Disable the offending user account until identity can be verified.",
      "[INVESTIGATION] Check for unauthorized local administrative group changes (e.g., local Administrators, wheel, sudoers).",
      "[HARDENING] Enforce Principle of Least Privilege and deploy Endpoint Detection & Response (EDR) agents to detect local privilege tools."
    ],
    UNUSUAL_TIME: [
      "[MONITORING] Contact the affected user out-of-band to verify if login was authorized business activity.",
      "[INVESTIGATION] Check if the workstation has scheduled tasks or background scripts executing on behalf of this user.",
      "[HARDENING] Establish restrictive conditional access policies for off-hours login windows unless explicitly whitelisted."
    ]
  };

  return playbooks[cat] || [
    "Triage alert and verify legitimacy of the activity.",
    "Verify source IP reputation via external Threat Intel channels.",
    "Monitor user's surrounding actions for 4 hours."
  ];
}

// Parses raw CSV lines into parsed log records
export function parseCSVLogs(csvContent: string): LogRecord[] {
  const lines = csvContent.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  if (lines.length <= 1) return [];

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const parsed: LogRecord[] = [];

  for (let i = 1; i < lines.length; i++) {
    const rawLine = lines[i];
    // Simple split that handles comma in double-quotes occasionally, but standard CSV format in our data is simple comma
    const values: string[] = [];
    let insideQuotes = false;
    let currentVal = '';
    
    for (let charIndex = 0; charIndex < rawLine.length; charIndex++) {
      const char = rawLine[charIndex];
      if (char === '"') {
        insideQuotes = !insideQuotes;
      } else if (char === ',' && !insideQuotes) {
        values.push(currentVal.trim());
        currentVal = '';
      } else {
        currentVal += char;
      }
    }
    values.push(currentVal.trim());

    if (values.length < headers.length) continue;

    // Create a dictionary map
    const row: Record<string, string> = {};
    headers.forEach((h, index) => {
      row[h] = values[index] || '';
    });

    try {
      const timestampStr = row['timestamp'] || '';
      let timestamp = new Date(timestampStr);
      if (isNaN(timestamp.getTime())) {
        // Try parsing YYYY-MM-DD HH:MM:SS format
        const t = timestampStr.replace(' ', 'T');
        timestamp = new Date(t);
      }

      const id = i;
      const username = row['username'] || '';
      const ip_address = row['ip_address'] || '';
      const event_type = row['event_type'] || '';
      const status = row['status'] || '';
      const details = row['details'] || '';
      const is_admin = (row['is_admin'] || '').toLowerCase() === 'true' || row['is_admin'] === '1';

      parsed.push({
        id,
        timestamp,
        raw_timestamp: timestampStr,
        username,
        ip_address,
        event_type,
        status,
        details,
        is_admin
      });
    } catch (e) {
      console.error(`Row parse failure at line ${i + 1}:`, e);
    }
  }

  // Chronological sort
  return parsed.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
}

// Analyzes log records to detect threats
export function detectThreats(records: LogRecord[], settings: RuleSettings): SecurityAlert[] {
  const alerts: SecurityAlert[] = [];
  let alertIdCounter = 1;

  const createAlert = (
    title: string,
    category: string,
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    details: string,
    actor: string,
    ip: string,
    triggeredLogs: LogRecord[]
  ) => {
    const alert_id = `ALRT-${String(alertIdCounter++).padStart(3, '0')}`;
    const timestamp = triggeredLogs[triggeredLogs.length - 1]?.timestamp || new Date();
    alerts.push({
      alert_id,
      title,
      category,
      severity_basis: severity,
      details,
      primary_actor: actor,
      ip_address: ip,
      timestamp,
      triggered_logs: triggeredLogs.map(l => l.id)
    });
  };

  // --- DETECTION ANALYTICS 1: BRUTE FORCE & PASSWORD SPRAY ---
  // Scan through records to count failed logins per IP within bruteForceWindow
  for (let i = 0; i < records.length; i++) {
    const current = records[i];
    if (current.event_type !== 'login' || current.status !== 'failed') continue;

    const ip = current.ip_address;
    const current_time = current.timestamp.getTime();
    const windowStart = current_time - (settings.bruteForceWindow * 1000);

    // Look backwards for failed logins from same IP in window
    const failuresFromIp: LogRecord[] = [];
    for (let j = i; j >= 0; j--) {
      const prev = records[j];
      if (prev.timestamp.getTime() < windowStart) break;
      if (prev.ip_address === ip && prev.event_type === 'login' && prev.status === 'failed') {
        failuresFromIp.push(prev);
      }
    }

    if (failuresFromIp.length >= settings.bruteForceLimit) {
      // Group targeted usernames
      const targetedUsers = new Set(failuresFromIp.map(l => l.username));

      // Prevent duplicate alerts in the same time window for same IP
      let alreadyAlerted = false;
      for (const alert of alerts) {
        if ((alert.category === 'BRUTE_FORCE' || alert.category === 'BRUTE_FORCE_SUCCESS' || alert.category === 'PASSWORD_SPRAY') && alert.ip_address === ip) {
          if (Math.abs(alert.timestamp.getTime() - current_time) < settings.bruteForceWindow * 1000) {
            alreadyAlerted = true;
            break;
          }
        }
      }

      if (alreadyAlerted) continue;

      if (targetedUsers.size === 1) {
        const targetUser = Array.from(targetedUsers)[0];
        
        // Check for compromise (success login within 5 mins forward)
        let compromised = false;
        let successLog: LogRecord | undefined;
        for (let k = i + 1; k < records.length; k++) {
          const nextLog = records[k];
          if (nextLog.timestamp.getTime() - current_time > 300000) break; // 5 mins cap
          if (nextLog.ip_address === ip && nextLog.username === targetUser && nextLog.event_type === 'login' && nextLog.status === 'success') {
            compromised = true;
            successLog = nextLog;
            break;
          }
        }

        if (compromised && successLog) {
          const triggered = [...failuresFromIp].reverse().concat(successLog);
          const desc = `IP address ${ip} conducted brute-force attacks against account '${targetUser}' with ${failuresFromIp.length} failures, and SUCCESSFULLY COMPROMISED the account at ${successLog.raw_timestamp}.`;
          createAlert(
            "Successful Brute Force Compromise",
            "BRUTE_FORCE_SUCCESS",
            "CRITICAL",
            desc,
            targetUser,
            ip,
            triggered
          );
        } else {
          const triggered = [...failuresFromIp].reverse();
          const desc = `IP address ${ip} performed brute-force attempts on username '${targetUser}' with ${failuresFromIp.length} failures inside a ${Math.round(settings.bruteForceWindow / 60)}-minute sliding window.`;
          createAlert(
            "Brute Force Attack Attempt",
            "BRUTE_FORCE",
            "HIGH",
            desc,
            targetUser,
            ip,
            triggered
          );
        }
      } else {
        // Password Spray
        const triggered = [...failuresFromIp].reverse();
        const desc = `IP address ${ip} conducted password-spraying attacks against ${targetedUsers.size} accounts (${Array.from(targetedUsers).slice(0, 4).join(', ')}...) with ${failuresFromIp.length} total failures in a ${Math.round(settings.bruteForceWindow / 60)}-minute window.`;
        createAlert(
          "Password Spray Attack Detected",
          "PASSWORD_SPRAY",
          "HIGH",
          desc,
          "MULTIPLE_ACCOUNTS",
          ip,
          triggered
        );
      }
    }
  }

  // --- DETECTION ANALYTICS 2: IMPOSSIBLE TRAVEL / SESSION ANOMALIES ---
  const userLogins: Record<string, LogRecord[]> = {};
  records.forEach(log => {
    if (log.event_type === 'login' && log.status === 'success') {
      const user = log.username;
      if (!userLogins[user]) userLogins[user] = [];
      userLogins[user].push(log);
    }
  });

  Object.entries(userLogins).forEach(([user, logins]) => {
    if (logins.length < 2) return;

    for (let i = 1; i < logins.length; i++) {
      const prevLogin = logins[i - 1];
      const currLogin = logins[i];
      const timeDiff = (currLogin.timestamp.getTime() - prevLogin.timestamp.getTime()) / 1000; // seconds

      if (timeDiff <= settings.travelWindow && prevLogin.ip_address !== currLogin.ip_address) {
        // Prevent duplicate alerts
        let alreadyAlerted = false;
        for (const alert of alerts) {
          if (alert.category === 'IMPOSSIBLE_TRAVEL' && alert.primary_actor === user) {
            if (Math.abs(alert.timestamp.getTime() - currLogin.timestamp.getTime()) < settings.travelWindow * 1000) {
              alreadyAlerted = true;
              break;
            }
          }
        }
        if (alreadyAlerted) continue;

        const desc = `Suspicious session activity for '${user}': Logged in from internal IP ${prevLogin.ip_address} and external IP ${currLogin.ip_address} within ${Math.round(timeDiff)} seconds. This indicates physically impossible travel speeds.`;
        createAlert(
          "Impossible Travel & Concurrent Session Anomaly",
          "IMPOSSIBLE_TRAVEL",
          "HIGH",
          desc,
          user,
          currLogin.ip_address,
          [prevLogin, currLogin]
        );
      }
    }
  });

  // --- DETECTION ANALYTICS 3: PRIVILEGE ESCALATION ---
  const privKeywords = ['sudo', 'root', '/etc/shadow', 'unauthorized', 'secure', 'sam-registry', 'passwords'];
  records.forEach(log => {
    if (log.status === 'failed' && ['command_execution', 'file_access', 'configuration_change'].includes(log.event_type)) {
      const detailsLower = log.details.toLowerCase();
      const isPrivEscalation = privKeywords.some(kw => detailsLower.includes(kw));

      if (isPrivEscalation && !log.is_admin) {
        const desc = `Non-privileged user '${log.username}' attempted a restricted action: '${log.details}'. Event failed with unauthorized permission codes.`;
        createAlert(
          "Privilege Escalation Attempt Blocked",
          "PRIVILEGE_ESCALATION",
          "MEDIUM",
          desc,
          log.username,
          log.ip_address,
          [log]
        );
      }
    }
  });

  // --- DETECTION ANALYTICS 4: UNUSUAL TIMES ---
  records.forEach(log => {
    if (log.event_type === 'login' && log.status === 'success') {
      const loginHour = log.timestamp.getHours();
      
      // Vulnerable window: 2:00 AM to 5:00 AM (inclusive)
      if (loginHour >= 2 && loginHour <= 5) {
        const isService = log.username.toLowerCase().includes('service') || log.username.toLowerCase().includes('sync');
        if (isService) return;

        // Prevent duplicates for same user on same day
        let alreadyAlerted = false;
        for (const alert of alerts) {
          if (alert.category === 'UNUSUAL_TIME' && alert.primary_actor === log.username) {
            if (alert.timestamp.toDateString() === log.timestamp.toDateString()) {
              alreadyAlerted = true;
              break;
            }
          }
        }
        if (alreadyAlerted) return;

        const hourStr = String(loginHour).padStart(2, '0');
        const minStr = String(log.timestamp.getMinutes()).padStart(2, '0');
        const desc = `Interactive logon by user '${log.username}' at ${log.raw_timestamp} (${hourStr}:${minStr} local time) which is outside normal working hours (Off-hours window: 2:00AM - 5:00AM).`;
        
        const sev = log.is_admin ? 'HIGH' : 'MEDIUM';
        const title = log.is_admin ? 'Administrative Login during Anomalous Hours' : 'User Logon during Anomalous Hours';

        createAlert(
          title,
          "UNUSUAL_TIME",
          sev,
          desc,
          log.username,
          log.ip_address,
          [log]
        );
      }
    }
  });

  // Chronological sort
  return alerts.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
}

// Risk calculation module that mirrors risk_engine.py
export function processAlertRisks(alerts: SecurityAlert[], logs: LogRecord[]): SecurityAlert[] {
  // Precompute actor activity counts
  const actorIncidentCounts: Record<string, number> = {};
  
  alerts.forEach(alert => {
    const actor = alert.primary_actor;
    const ip = alert.ip_address;

    if (actor && actor !== "MULTIPLE_ACCOUNTS") {
      actorIncidentCounts[actor] = (actorIncidentCounts[actor] || 0) + 1;
    }
    if (ip && ip !== "N/A") {
      actorIncidentCounts[ip] = (actorIncidentCounts[ip] || 0) + 1;
    }
  });

  const processed = alerts.map(alert => {
    // 1. Base Score
    let score = 15;
    if (alert.severity_basis === 'CRITICAL') score = 85;
    else if (alert.severity_basis === 'HIGH') score = 65;
    else if (alert.severity_basis === 'MEDIUM') score = 40;

    // 2. Status modifier (did the threat succeed?)
    const triggeredLogsList = logs.filter(l => alert.triggered_logs.includes(l.id));
    const isSuccessful = alert.category.includes('SUCCESS') || triggeredLogsList.some(l => l.status === 'success');
    if (isSuccessful) {
      score += 15;
    }

    // 3. Privilege modifier (admin credentials)
    const isAdminInvolved = triggeredLogsList.some(l => l.is_admin);
    if (isAdminInvolved) {
      score += 10;
    }

    // 4. Subnet modifier (external IP vs local)
    const ip = alert.ip_address;
    if (ip && ip !== 'N/A') {
      const isInternal = ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.');
      if (!isInternal) {
        score += 8;
      }
    }

    // 5. Threat amplification
    const actor = alert.primary_actor;
    const actorCount = actorIncidentCounts[actor] || 0;
    const ipCount = ip ? (actorIncidentCounts[ip] || 0) : 0;
    const extraIncidents = Math.max(0, Math.max(actorCount, ipCount) - 1);
    
    score += Math.min(15, extraIncidents * 5);

    // Limit between 0 and 100
    const finalScore = Math.max(0, Math.min(100, score));

    // Classify risk
    let classification: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (finalScore <= 30) classification = 'LOW';
    else if (finalScore <= 60) classification = 'MEDIUM';
    else if (finalScore <= 80) classification = 'HIGH';
    else classification = 'CRITICAL';

    return {
      ...alert,
      risk_score: finalScore,
      risk_classification: classification,
      remediation_playbook: getRemediationPlaybook(alert.category)
    };
  });

  // Sort by risk score descending (highest risk first!)
  return processed.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
}

// Compile metrics
export function compileSecurityMetrics(alerts: SecurityAlert[]): SecurityMetrics {
  const totalAlerts = alerts.length;
  if (totalAlerts === 0) {
    return {
      max_score: 0,
      avg_score: 0,
      counts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
    };
  }

  const scores = alerts.map(a => a.risk_score || 0);
  const max_score = Math.max(...scores);
  const avg_score = Number((scores.reduce((sum, s) => sum + s, 0) / totalAlerts).toFixed(1));

  const counts = {
    LOW: alerts.filter(a => a.risk_classification === 'LOW').length,
    MEDIUM: alerts.filter(a => a.risk_classification === 'MEDIUM').length,
    HIGH: alerts.filter(a => a.risk_classification === 'HIGH').length,
    CRITICAL: alerts.filter(a => a.risk_classification === 'CRITICAL').length
  };

  return {
    max_score,
    avg_score,
    counts
  };
}

// Compiles a standard professional TXT report
export function compileTextReport(
  alerts: SecurityAlert[], 
  stats: { totalParsed: number; errorsSkipped: number; start?: Date; end?: Date },
  metrics: SecurityMetrics
): string {
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const border = "================================================================================";
  const section_border = "--------------------------------------------------------------------------------";
  const lines: string[] = [];

  const startStr = stats.start ? stats.start.toISOString() : 'N/A';
  const endStr = stats.end ? stats.end.toISOString() : 'N/A';

  lines.push(border);
  lines.push("                 SOC INCIDENT REPORT & THREAT DETECTION SUMMARY");
  lines.push(border);
  lines.push(`Report Generated At : ${timestamp}`);
  lines.push(`Logs Analyzed       : ${stats.totalParsed} events`);
  lines.push(`Log Time Span       : ${startStr} to ${endStr}`);
  lines.push(border);
  lines.push("");

  // 1. EXECUTIVE SUMMARY
  lines.push("1. EXECUTIVE SUMMARY");
  lines.push(section_border);
  const totalThreats = alerts.length;
  if (totalThreats === 0) {
    lines.push("[+] SECURITY STATUS: SECURE");
    lines.push("    No threat indicators or anomalous behavioral footprints were detected.");
  } else {
    lines.push(`[-] SECURITY STATUS: ACTION REQUIRED - ${totalThreats} alerts triggered`);
    lines.push(`    Max Incident Risk Score : ${metrics.max_score}/100`);
    lines.push(`    Average Alert Risk Score: ${metrics.avg_score}/100`);
    lines.push("");
    lines.push("    Risk Severity Counts:");
    lines.push(`      - CRITICAL : ${metrics.counts.CRITICAL} alert(s)`);
    lines.push(`      - HIGH     : ${metrics.counts.HIGH} alert(s)`);
    lines.push(`      - MEDIUM   : ${metrics.counts.MEDIUM} alert(s)`);
    lines.push(`      - LOW      : ${metrics.counts.LOW} alert(s)`);
  }
  lines.push("");

  // 2. CHIEF THREAT ACTORS
  if (totalThreats > 0) {
    lines.push("2. CHIEF THREAT ACTORS & SUSPICIOUS IPs");
    lines.push(section_border);
    const actors: Record<string, number> = {};
    const ips: Record<string, number> = {};
    alerts.forEach(alert => {
      const act = alert.primary_actor;
      const ip = alert.ip_address;
      if (act && act !== "MULTIPLE_ACCOUNTS") {
        actors[act] = (actors[act] || 0) + 1;
      }
      if (ip && ip !== "N/A") {
        ips[ip] = (ips[ip] || 0) + 1;
      }
    });

    const topActors = Object.entries(actors).sort((a, b) => b[1] - a[1]).slice(0, 3);
    const topIps = Object.entries(ips).sort((a, b) => b[1] - a[1]).slice(0, 3);

    lines.push("    Top Target/Offending Usernames:");
    topActors.forEach(([act, count]) => {
      lines.push(`      - ${act} (triggered ${count} alert(s))`);
    });
    if (topActors.length === 0) lines.push("      - None");

    lines.push("    Top Source IP Addresses:");
    topIps.forEach(([ip, count]) => {
      lines.push(`      - ${ip} (triggered ${count} alert(s))`);
    });
    if (topIps.length === 0) lines.push("      - None");
    lines.push("");
  }

  // 3. CHRONOLOGICAL TIMELINE
  lines.push("3. DETECTED SECURITY INCIDENTS TIMELINE (HIGHEST RISK FIRST)");
  lines.push(section_border);
  if (totalThreats === 0) {
    lines.push("    No events detected.");
  } else {
    alerts.forEach((alert, idx) => {
      lines.push(`[${idx + 1}] ${alert.title.toUpperCase()}`);
      lines.push(`    Alert ID       : ${alert.alert_id}`);
      lines.push(`    Time of Event  : ${alert.timestamp.toISOString()}`);
      lines.push(`    Threat Category: ${alert.category}`);
      lines.push(`    Primary Actor  : ${alert.primary_actor}`);
      lines.push(`    Source IP      : ${alert.ip_address}`);
      lines.push(`    Risk Score     : ${alert.risk_score}/100 (${alert.risk_classification})`);
      lines.push(`    Description    : ${alert.details}`);
      lines.push("");
    });
  }

  // 4. REMEDIATION PLAYBOOKS
  if (totalThreats > 0) {
    lines.push("4. TACTICAL REMEDIATION PLAYBOOKS (NIST SP 800-61 COOLDOWN)");
    lines.push(section_border);
    const categoriesHandled = new Set<string>();
    
    alerts.forEach(alert => {
      const cat = alert.category;
      if (categoriesHandled.has(cat)) return;
      categoriesHandled.add(cat);

      lines.push(`--> Playbook for category: ${cat}`);
      const steps = alert.remediation_playbook || getRemediationPlaybook(cat);
      steps.forEach(step => {
        lines.push(`    [ ] ${step}`);
      });
      lines.push("");
    });
  }

  lines.push(border);
  lines.push("                 SOC REPORT GENERATOR - SECURE OPERATIONS TIER");
  lines.push(border);

  return lines.join('\n');
}
