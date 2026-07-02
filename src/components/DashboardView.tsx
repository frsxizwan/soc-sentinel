// src/components/DashboardView.tsx
import { useState } from 'react';
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, Users, Database, Globe, ArrowRight, ExternalLink, Activity, Play } from 'lucide-react';
import { SecurityAlert, SecurityMetrics, LogRecord } from '../utils/securityEngine';

interface DashboardViewProps {
  alerts: SecurityAlert[];
  metrics: SecurityMetrics;
  logs: LogRecord[];
  onTabChange: (tab: string) => void;
  onAlertSelect: (alert: SecurityAlert) => void;
}

export default function DashboardView({ alerts, metrics, logs, onTabChange, onAlertSelect }: DashboardViewProps) {
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  // Group top IPs and actors
  const ipCounts: Record<string, number> = {};
  const actorCounts: Record<string, number> = {};
  
  alerts.forEach(a => {
    if (a.ip_address && a.ip_address !== 'N/A') {
      ipCounts[a.ip_address] = (ipCounts[a.ip_address] || 0) + 1;
    }
    if (a.primary_actor && a.primary_actor !== 'MULTIPLE_ACCOUNTS') {
      actorCounts[a.primary_actor] = (actorCounts[a.primary_actor] || 0) + 1;
    }
  });

  const topIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const topActors = Object.entries(actorCounts).sort((a, b) => b[1] - a[1]).slice(0, 4);

  // Calculate some simple stats
  const totalLogs = logs.length;
  const adminLogins = logs.filter(l => l.is_admin && l.event_type === 'login' && l.status === 'success').length;
  const failedEvents = logs.filter(l => l.status === 'failed').length;

  return (
    <div className="space-y-6">
      {/* 1. TOP METRICS GRID */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Maximum Risk Level */}
        <div className="bg-[#0b0f19] border border-slate-900 rounded p-5 flex items-center justify-between shadow-md relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 rounded-full blur-2xl group-hover:bg-red-500/10 transition-all duration-300" />
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider block font-mono">Max Incident Threat</span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-3xl font-display font-bold text-white">{metrics.max_score}</span>
              <span className="text-xs text-slate-500 font-mono">/100</span>
            </div>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded inline-block uppercase mt-1 font-mono ${
              metrics.max_score > 80 
                ? 'bg-red-950/50 text-red-400 border border-red-800/50' 
                : metrics.max_score > 60 
                  ? 'bg-amber-950/50 text-amber-400 border border-amber-800/50'
                  : 'bg-emerald-950/50 text-emerald-400 border border-emerald-800/50'
            }`}>
              {metrics.max_score > 80 ? 'CRITICAL RISK' : metrics.max_score > 60 ? 'HIGH RISK' : 'STABLE'}
            </span>
          </div>
          <div className={`p-3 rounded ${metrics.max_score > 80 ? 'bg-red-950/30 border border-red-900/30 text-red-400' : 'bg-slate-800/80 text-slate-400'}`}>
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        {/* Total Alerts Active */}
        <div className="bg-[#0b0f19] border border-slate-900 rounded p-5 flex items-center justify-between shadow-md relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-full blur-2xl group-hover:bg-amber-500/10 transition-all duration-300" />
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider block font-mono">Intrusion Indicators</span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-3xl font-display font-bold text-white">{alerts.length}</span>
              <span className="text-xs text-slate-500">Alerts</span>
            </div>
            <span className="text-[10px] text-slate-400 font-medium block mt-1">
              Active SIEM alarms triggered
            </span>
          </div>
          <div className={`p-3 rounded ${alerts.length > 0 ? 'bg-amber-950/30 border border-amber-900/30 text-amber-500' : 'bg-emerald-950/30 border border-emerald-900/30 text-emerald-400'}`}>
            {alerts.length > 0 ? <AlertTriangle className="w-6 h-6 animate-pulse" /> : <ShieldCheck className="w-6 h-6" />}
          </div>
        </div>

        {/* Total Ingested Logs */}
        <div className="bg-[#0b0f19] border border-slate-900 rounded p-5 flex items-center justify-between shadow-md relative overflow-hidden">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider block font-mono">Telemetry Ingest</span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-3xl font-display font-bold text-white">{totalLogs}</span>
              <span className="text-xs text-slate-500">Logs</span>
            </div>
            <span className="text-[10px] text-slate-400 font-mono block mt-1">
              {failedEvents} auth failures
            </span>
          </div>
          <div className="p-3 bg-slate-800/80 text-slate-400 rounded">
            <Database className="w-6 h-6" />
          </div>
        </div>

        {/* Administrator access events */}
        <div className="bg-[#0b0f19] border border-slate-900 rounded p-5 flex items-center justify-between shadow-md relative overflow-hidden">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider block font-mono">Administrative Sessions</span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-3xl font-display font-bold text-white">{adminLogins}</span>
              <span className="text-xs text-slate-500">Logons</span>
            </div>
            <span className="text-[10px] text-emerald-400 font-semibold block mt-1">
              Authorized domain configs
            </span>
          </div>
          <div className="p-3 bg-slate-800/80 text-slate-400 rounded">
            <Users className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* 2. SECURITY GRAPHS & INTEL GRID (Bento Box) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Risk Arc Speedometer / Severity Breakdown (5 Cols) */}
        <div className="lg:col-span-5 bg-[#0b0f19] border border-slate-900 rounded p-5 flex flex-col justify-between shadow-md">
          <div className="border-b border-slate-850 pb-3 mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h4 className="text-sm font-semibold text-slate-200">Incident Severity Profiler</h4>
            </div>
            <span className="text-[10px] font-mono text-slate-500">WEIGHT DISTRIBUTION</span>
          </div>

          {/* Custom SVG Risk Speedometer Dial */}
          <div className="flex flex-col items-center py-4 relative">
            <svg className="w-44 h-24 overflow-visible" viewBox="0 0 100 50">
              {/* Background Arc */}
              <path
                d="M 10,50 A 40,40 0 0,1 90,50"
                fill="none"
                stroke="#1e293b"
                strokeWidth="10"
                strokeLinecap="round"
              />
              {/* Colored Indicator Arc */}
              <path
                d="M 10,50 A 40,40 0 0,1 90,50"
                fill="none"
                stroke={metrics.max_score > 80 ? '#f43f5e' : metrics.max_score > 60 ? '#f59e0b' : '#10b981'}
                strokeWidth="10"
                strokeLinecap="round"
                strokeDasharray="125.6"
                strokeDashoffset={125.6 - (125.6 * Math.min(100, metrics.max_score)) / 100}
                className="transition-all duration-1000 ease-out"
              />
              {/* Center pointer */}
              <text x="50" y="44" textAnchor="middle" className="text-[16px] font-bold font-sans fill-slate-100">
                {metrics.max_score}
              </text>
              <text x="50" y="49" textAnchor="middle" className="text-[6px] fill-slate-400 uppercase font-semibold">
                MAX THREAT SCORE
              </text>
            </svg>
            <div className="text-center mt-2">
              <p className="text-xs text-slate-400 font-medium">Average alert risk: <span className="font-semibold text-slate-200">{metrics.avg_score}/100</span></p>
            </div>
          </div>

          {/* Horizontal block bars showing LOW, MEDIUM, HIGH, CRITICAL ratios */}
          <div className="space-y-3 pt-4 border-t border-slate-800">
            <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">Risk Tiers breakdown</span>
            
            <div className="space-y-2">
              {/* Critical */}
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5 text-rose-400 font-medium">
                  <span className="h-2 w-2 rounded-full bg-rose-500" />
                  Critical (81-100)
                </div>
                <span className="font-mono text-slate-300 font-medium">{metrics.counts.CRITICAL} alert(s)</span>
              </div>
              <div className="w-full h-1.5 bg-slate-950 rounded overflow-hidden">
                <div 
                  className="h-full bg-rose-500 transition-all duration-500" 
                  style={{ width: `${alerts.length ? (metrics.counts.CRITICAL / alerts.length) * 100 : 0}%` }}
                />
              </div>

              {/* High */}
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5 text-amber-400 font-medium">
                  <span className="h-2 w-2 rounded-full bg-amber-500" />
                  High (61-80)
                </div>
                <span className="font-mono text-slate-300 font-medium">{metrics.counts.HIGH} alert(s)</span>
              </div>
              <div className="w-full h-1.5 bg-slate-950 rounded overflow-hidden">
                <div 
                  className="h-full bg-amber-500 transition-all duration-500" 
                  style={{ width: `${alerts.length ? (metrics.counts.HIGH / alerts.length) * 100 : 0}%` }}
                />
              </div>

              {/* Medium */}
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5 text-slate-300 font-medium">
                  <span className="h-2 w-2 rounded-full bg-slate-400" />
                  Medium (31-60)
                </div>
                <span className="font-mono text-slate-300 font-medium">{metrics.counts.MEDIUM} alert(s)</span>
              </div>
              <div className="w-full h-1.5 bg-slate-950 rounded overflow-hidden">
                <div 
                  className="h-full bg-slate-400 transition-all duration-500" 
                  style={{ width: `${alerts.length ? (metrics.counts.MEDIUM / alerts.length) * 100 : 0}%` }}
                />
              </div>

              {/* Low */}
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5 text-emerald-400 font-medium">
                  <span className="h-2 w-2 rounded-full bg-emerald-500" />
                  Low (0-30)
                </div>
                <span className="font-mono text-slate-300 font-medium">{metrics.counts.LOW} alert(s)</span>
              </div>
              <div className="w-full h-1.5 bg-slate-950 rounded overflow-hidden">
                <div 
                  className="h-full bg-emerald-500 transition-all duration-500" 
                  style={{ width: `${alerts.length ? (metrics.counts.LOW / alerts.length) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Chief Threat Actors & Source IPs (7 Cols) */}
        <div className="lg:col-span-7 bg-[#0b0f19] border border-slate-900 rounded p-5 flex flex-col justify-between shadow-md">
          <div className="border-b border-slate-850 pb-3 mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-red-500" />
              <h4 className="text-sm font-display font-semibold text-slate-200">Threat Intel Actors Profiling</h4>
            </div>
            <span className="text-[10px] font-mono text-slate-500 font-semibold uppercase">Top targeted assets</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1">
            {/* Top Source IPs bar lists */}
            <div className="space-y-4">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wide flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-rose-500" />
                Source IP Offenders
              </span>
              <div className="space-y-3 font-mono">
                {topIps.length === 0 ? (
                  <p className="text-xs text-slate-550">No malicious IP sources cataloged.</p>
                ) : (
                  topIps.map(([ip, count], i) => (
                    <div key={ip} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="font-medium text-slate-350">{ip}</span>
                        <span className="text-slate-500">{count} incident(s)</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-950 rounded overflow-hidden">
                        {/* Calculate ratio relative to highest value */}
                        <div 
                          className="h-full bg-red-600" 
                          style={{ width: `${(count / topIps[0][1]) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Top Target Usernames bar lists */}
            <div className="space-y-4">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wide flex items-center gap-1.5">
                <Users className="w-3.5 h-3.5 text-red-500" />
                Compromised/Targeted Users
              </span>
              <div className="space-y-3 font-mono">
                {topActors.length === 0 ? (
                  <p className="text-xs text-slate-550">No target users flagged.</p>
                ) : (
                  topActors.map(([user, count]) => (
                    <div key={user} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="font-medium text-slate-350">{user}</span>
                        <span className="text-slate-500">{count} incident(s)</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-950 rounded overflow-hidden">
                        <div 
                          className="h-full bg-red-600" 
                          style={{ width: `${(count / topActors[0][1]) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="mt-5 bg-slate-950/60 rounded p-3 border border-slate-900 flex items-center justify-between">
            <div className="text-xs text-slate-400 flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span>Real-time CSV database loaded securely. All changes propagate instantly.</span>
            </div>
            <button 
              onClick={() => onTabChange('logs')}
              className="text-xs font-semibold text-red-500 hover:text-red-400 flex items-center gap-1 group transition-colors"
            >
              <span>Manage logs</span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </div>
        </div>

      </div>

      {/* 3. CORE THREAT INCIDENTS LIST */}
      <div className="bg-[#0b0f19] border border-slate-900 rounded overflow-hidden shadow-md">
        <div className="px-5 py-4 border-b border-slate-900 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h3 className="font-display font-semibold text-slate-200">Active Security Incidents Triage</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Correlated security incidents requiring analyst assessment. Sorted by calculated risk score descending.
            </p>
          </div>
          <button
            onClick={() => onTabChange('terminal')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 active:scale-95 rounded shadow transition-all self-start md:self-center font-mono uppercase tracking-wider"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Simulate Scan</span>
          </button>
        </div>

        {alerts.length === 0 ? (
          <div className="p-12 text-center max-w-sm mx-auto space-y-3">
            <div className="p-3 bg-slate-950 rounded-full inline-block text-slate-400 border border-slate-900">
              <ShieldCheck className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h5 className="font-semibold text-slate-250">Zero Threats Triggered</h5>
              <p className="text-xs text-slate-500 mt-0.5 font-mono">
                Security parameter rules are relaxed or logs describe clean behavior. Excellent work admin.
              </p>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60 max-h-[500px] overflow-y-auto">
            {alerts.map((alert) => {
              const risk = alert.risk_classification || 'LOW';
              const isCritical = risk === 'CRITICAL';
              const isHigh = risk === 'HIGH';
              const isMedium = risk === 'MEDIUM';

              return (
                <div 
                  key={alert.alert_id} 
                  className={`p-5 transition-all hover:bg-slate-950/30 flex flex-col lg:flex-row lg:items-center justify-between gap-4 group ${
                    selectedAlertId === alert.alert_id ? 'bg-slate-950/40' : ''
                  }`}
                >
                  {/* Left segment - Core identity */}
                  <div className="flex-1 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[10px] font-bold text-slate-500 bg-slate-950 border border-slate-800 px-2 py-0.5 rounded">
                        {alert.alert_id}
                      </span>
                      <h4 className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">
                        {alert.title}
                      </h4>
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                        isCritical 
                          ? 'bg-rose-950/50 text-rose-400 border-rose-800/50' 
                          : isHigh 
                            ? 'bg-amber-950/50 text-amber-400 border-amber-800/50'
                            : isMedium 
                              ? 'bg-blue-950/50 text-blue-400 border-blue-800/50'
                              : 'bg-emerald-950/50 text-emerald-400 border-emerald-800/50'
                      }`}>
                        {risk}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
                      {alert.details}
                    </p>

                    {/* Metadata tags */}
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-slate-400 font-mono">
                      <span>Primary actor: <strong className="text-slate-300 font-semibold">{alert.primary_actor}</strong></span>
                      <span className="text-slate-700">•</span>
                      <span>Source IP: <strong className="text-slate-300 font-semibold">{alert.ip_address}</strong></span>
                      <span className="text-slate-700">•</span>
                      <span>Incident UTC: <span className="text-slate-400">{alert.timestamp.toISOString().replace('T', ' ').substring(0, 19)}</span></span>
                    </div>
                  </div>

                  {/* Right segment - score dial / call to actions */}
                  <div className="flex items-center gap-4 self-end lg:self-center pl-6 lg:pl-0 border-l lg:border-l-0 border-slate-800/60">
                    <div className="text-center">
                      <div className="text-xs text-slate-400 font-mono">Risk Index</div>
                      <div className={`text-2xl font-black font-mono ${
                        isCritical ? 'text-rose-500' : isHigh ? 'text-amber-500' : isMedium ? 'text-blue-500' : 'text-emerald-500'
                      }`}>
                        {alert.risk_score}
                      </div>
                    </div>
                    
                    <button
                      onClick={() => onAlertSelect(alert)}
                      className="p-2 text-slate-400 hover:text-white bg-slate-800/50 hover:bg-slate-800 rounded-lg border border-slate-800 transition-all active:scale-95"
                      title="Inspect Containment Playbook"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
