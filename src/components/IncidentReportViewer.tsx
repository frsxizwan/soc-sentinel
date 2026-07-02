// src/components/IncidentReportViewer.tsx
import React, { useState } from 'react';
import { SecurityAlert, SecurityMetrics, compileTextReport, LogRecord } from '../utils/securityEngine';
import { FileText, Copy, Check, Download, AlertTriangle, PenTool } from 'lucide-react';

interface IncidentReportViewerProps {
  alerts: SecurityAlert[];
  metrics: SecurityMetrics;
  logs: LogRecord[];
  ruleSettings: { bruteForceLimit: number; bruteForceWindow: number; travelWindow: number };
}

export default function IncidentReportViewer({ alerts, metrics, logs, ruleSettings }: IncidentReportViewerProps) {
  const [reportType, setReportType] = useState<'text' | 'json'>('text');
  const [copied, setCopied] = useState(false);
  const [analystNotes, setAnalystNotes] = useState('');
  const [savedAnalystNotes, setSavedAnalystNotes] = useState('');

  // Build log statistics
  const stats = {
    totalParsed: logs.length,
    errorsSkipped: logs.filter(l => isNaN(l.timestamp.getTime())).length,
    start: logs[0]?.timestamp,
    end: logs[logs.length - 1]?.timestamp
  };

  // Compile standard report content
  const baseTextReport = compileTextReport(alerts, stats, metrics);
  
  // Inject custom Analyst notes if they exist
  let textReport = baseTextReport;
  if (savedAnalystNotes) {
    const lines = textReport.split('\n');
    // Find section 1 executive summary or section index and inject
    const indexToInject = lines.findIndex(l => l.includes('1. EXECUTIVE SUMMARY'));
    if (indexToInject !== -1) {
      const notesBlock = [
        "",
        "    [SOC ANALYST CASE FILE INJECTED NOTES]",
        "    --------------------------------------",
        ...savedAnalystNotes.split('\n').map(l => `    >> ${l}`),
        "    --------------------------------------",
        ""
      ];
      lines.splice(indexToInject + 2, 0, ...notesBlock);
      textReport = lines.join('\n');
    }
  }

  // Generate dynamic JSON document
  const rawJsonObject = {
    metadata: {
      generated_at: new Date().toISOString(),
      tool: "Automated Security Log Analyzer & Threat Detection System",
      analyst_tier: "SOC Level 2 Investigator",
      analyst_notes: savedAnalystNotes || "None provided"
    },
    ingestion_stats: {
      total_records_analyzed: stats.totalParsed,
      records_skipped_errors: stats.errorsSkipped,
      log_chronological_start: stats.start?.toISOString(),
      log_chronological_end: stats.end?.toISOString()
    },
    rule_thresholds: {
      brute_force_failure_limit: ruleSettings.bruteForceLimit,
      brute_force_sliding_window_seconds: ruleSettings.bruteForceWindow,
      travel_anomaly_window_seconds: ruleSettings.travelWindow
    },
    risk_metrics: metrics,
    detected_threats: alerts.map(a => ({
      alert_id: a.alert_id,
      title: a.title,
      category: a.category,
      risk_score: a.risk_score,
      severity_level: a.risk_classification,
      primary_actor: a.primary_actor,
      ip_address: a.ip_address,
      timestamp: a.timestamp.toISOString(),
      summary: a.details,
      remediation_playbook: a.remediation_playbook,
      associated_log_ids: a.triggered_logs
    }))
  };

  const jsonReport = JSON.stringify(rawJsonObject, null, 2);
  const activeReport = reportType === 'text' ? textReport : jsonReport;

  const handleCopy = () => {
    navigator.clipboard.writeText(activeReport);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Triggers local browser download
  const handleDownload = () => {
    const filename = reportType === 'text' ? 'soc_incident_report.txt' : 'soc_incident_report.json';
    const mime = reportType === 'text' ? 'text/plain' : 'application/json';
    const blob = new Blob([activeReport], { type: mime });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleSaveNotes = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedAnalystNotes(analystNotes);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-[calc(100vh-140px)] min-h-[500px]">
      
      {/* LEFT: Notes Editor & Actions (4 Cols) */}
      <div className="lg:col-span-4 bg-[#0b0f19] border border-slate-900 rounded p-5 flex flex-col justify-between overflow-y-auto shadow-md">
        <div className="space-y-5">
          <div className="border-b border-slate-850 pb-3 flex items-center gap-2">
            <PenTool className="w-4 h-4 text-red-500" />
            <h4 className="text-sm font-display font-semibold text-slate-200">Incident Analyst Desk</h4>
          </div>

          {/* Form to append analyst annotations */}
          <form onSubmit={handleSaveNotes} className="space-y-3 font-mono">
            <div className="space-y-1">
              <label className="text-xs text-slate-450 font-medium">Add Analyst Assessment Notes</label>
              <textarea
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                rows={5}
                placeholder="Write your diagnostic investigation results here... E.g. Confirmed IP 198.51.100.42 was attempting password spraying. Root logins suspended."
                className="w-full p-3 text-xs bg-slate-950 border border-slate-900 focus:border-red-500 rounded text-slate-200 outline-none placeholder-slate-650 font-sans"
              />
            </div>
            <button
              type="submit"
              className="w-full py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded shadow active:scale-95 transition-all uppercase tracking-wide"
            >
              Inject Notes into Report
            </button>
          </form>

          {/* Incident Severity Badge block */}
          <div className="bg-slate-950/60 p-4 border border-slate-900 rounded space-y-2.5 font-mono">
            <span className="text-[10px] uppercase font-extrabold text-slate-500 tracking-wider block">Investigation Status</span>
            
            <div className="flex items-center gap-2">
              <div className="p-2 bg-rose-950/30 border border-rose-900/30 text-rose-400 rounded">
                <AlertTriangle className="w-4 h-4 animate-pulse" />
              </div>
              <div>
                <span className="text-xs font-semibold text-slate-200 block font-sans">Critical Triage Active</span>
                <span className="text-[10px] text-slate-500">MITRE ATT&CK Mapping Complete</span>
              </div>
            </div>
          </div>
        </div>

        {/* SOC Analyst Credits */}
        <div className="mt-6 bg-slate-950/40 p-3 border border-slate-900 rounded text-[11px] text-slate-400 leading-relaxed font-sans">
          <span className="font-bold text-slate-350 block mb-1 font-mono uppercase tracking-wider text-[10px]">Incident Playbook</span>
          Remediation playbooks are loaded based on standard **NIST SP 800-61** containment strategies, supporting automated SOAR integrations.
        </div>
      </div>

      {/* RIGHT: Display screen (8 Cols) */}
      <div className="lg:col-span-8 flex flex-col bg-black border border-slate-900 rounded overflow-hidden shadow-2xl">
        {/* Tab Selection and Buttons Header */}
        <div className="bg-[#0b0f19] px-4 py-3 border-b border-slate-900 flex flex-col sm:flex-row gap-3 sm:items-center justify-between">
          <div className="flex items-center gap-2 bg-slate-950 p-1 rounded border border-slate-900 self-start font-mono">
            <button
              onClick={() => setReportType('text')}
              className={`px-3 py-1 text-xs font-semibold rounded transition-all ${
                reportType === 'text'
                  ? 'bg-red-950/50 text-red-400 border border-red-900/30 font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Executive Report (TXT)
            </button>
            <button
              onClick={() => setReportType('json')}
              className={`px-3 py-1 text-xs font-semibold rounded transition-all ${
                reportType === 'json'
                  ? 'bg-red-950/50 text-red-400 border border-red-900/30 font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Machine Schema (JSON)
            </button>
          </div>

          <div className="flex items-center gap-2 self-end sm:self-center font-mono">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 active:scale-95 rounded border border-slate-800 transition-all"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-green-400" />
                  <span className="text-green-400">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Report</span>
                </>
              )}
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 active:scale-95 rounded shadow transition-all uppercase tracking-wide"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download File</span>
            </button>
          </div>
        </div>

        {/* Display Paper Container */}
        <div className="flex-1 overflow-auto p-5 font-mono text-xs text-slate-300 leading-relaxed bg-black/40">
          <pre className="whitespace-pre overflow-x-auto">
            <code>{activeReport}</code>
          </pre>
        </div>
      </div>

    </div>
  );
}
