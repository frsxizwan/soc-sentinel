import { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal, 
  Database, 
  Sliders, 
  FileText, 
  FolderCode, 
  BookOpen, 
  User, 
  ExternalLink,
  X,
  Clock,
  Briefcase,
  Layers,
  Sparkles
} from 'lucide-react';

// Core security logic & helpers
import { 
  LogRecord, 
  SecurityAlert, 
  SecurityMetrics, 
  RuleSettings, 
  parseCSVLogs, 
  detectThreats, 
  processAlertRisks, 
  compileSecurityMetrics,
  getRemediationPlaybook
} from './utils/securityEngine';

// Child view components
import DashboardView from './components/DashboardView';
import LogViewer from './components/LogViewer';
import RulesEditor from './components/RulesEditor';
import TerminalSimulation from './components/TerminalSimulation';
import IncidentReportViewer from './components/IncidentReportViewer';
import CodeExplorer from './components/CodeExplorer';
import GuideView from './components/GuideView';

// Original raw CSV sample logs to initialize states
const initialCSVSample = `timestamp,username,ip_address,event_type,status,details,is_admin
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
2026-07-01T19:05:00Z,t.clark,192.168.10.102,command_execution,success,Uploaded local script to domain backup share,false`;

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [logs, setLogs] = useState<LogRecord[]>([]);
  const [ruleSettings, setRuleSettings] = useState<RuleSettings>({
    bruteForceLimit: 5,
    bruteForceWindow: 300, // 5 mins
    travelWindow: 600 // 10 mins
  });

  // State for forensic overlay modal
  const [selectedIncident, setSelectedIncident] = useState<SecurityAlert | null>(null);

  // Parse logs on mount
  useEffect(() => {
    const parsed = parseCSVLogs(initialCSVSample);
    setLogs(parsed);
  }, []);

  // Compute threat detections dynamically based on logs and current settings
  const rawAlerts = detectThreats(logs, ruleSettings);
  const alerts = processAlertRisks(rawAlerts, logs);
  const metrics = compileSecurityMetrics(alerts);

  const handleAddLog = (newLog: Omit<LogRecord, 'id'>) => {
    setLogs(prev => {
      const nextId = prev.length > 0 ? Math.max(...prev.map(l => l.id)) + 1 : 1;
      const parsedLog: LogRecord = {
        ...newLog,
        id: nextId
      };
      // Append and sort chronologically
      return [...prev, parsedLog].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    });
  };

  const handleResetLogs = () => {
    const parsed = parseCSVLogs(initialCSVSample);
    setLogs(parsed);
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans select-none antialiased">
      {/* 1. TOP BAR BRAND HEADER */}
      <header className="bg-slate-950 border-b border-slate-900 px-6 py-3 flex flex-col sm:flex-row gap-4 items-center justify-between shadow-2xl relative z-20">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-red-600 rounded flex items-center justify-center shadow-inner relative overflow-hidden group">
            <div className="w-4 h-4 border-2 border-white rotate-45 transition-transform group-hover:rotate-90 duration-500" />
            <div className="absolute inset-0 bg-red-500/20 blur" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display font-bold text-base text-white tracking-tight uppercase">
                AEGIS <span className="text-red-500 italic">SOC-DETECTOR</span>
              </span>
              <span className="text-[9px] font-mono text-red-400 font-bold bg-red-950/40 px-1.5 py-0.5 rounded border border-red-800/40">
                PRO PORTFOLIO
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-medium">Automated Security Log Analyzer & Threat Detection System</p>
          </div>
        </div>

        {/* Analyst Credentials block */}
        <div className="flex items-center gap-4 bg-slate-900 px-4 py-1.5 rounded-lg border border-slate-800">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs font-mono text-emerald-400">SYSTEM: ACTIVE</span>
          </div>
          <div className="h-6 w-px bg-slate-800" />
          <div className="text-right">
            <span className="text-[10px] uppercase tracking-widest text-slate-500 font-bold leading-none block mb-0.5">Analyst Station</span>
            <span className="text-xs font-semibold text-slate-200 block">FrsxIzwan.MFI@gmail.com</span>
          </div>
          <div className="p-1.5 bg-slate-950 border border-slate-800 rounded text-slate-400">
            <User className="w-3.5 h-3.5" />
          </div>
        </div>
      </header>

      {/* 2. BODY CONTENT LAYOUT */}
      <div className="flex-1 flex flex-col md:flex-row">
        {/* Left hand Sidebar Nav */}
        <nav className="md:w-64 bg-slate-950 border-r border-slate-900 p-4 flex flex-row md:flex-col gap-2 overflow-x-auto md:overflow-x-visible">
          <div className="hidden md:block pb-2 mb-2 border-b border-slate-900">
            <span className="text-[10px] font-bold text-slate-500 tracking-wider uppercase font-mono">Triage Workspace</span>
          </div>

          {/* Navigation Buttons */}
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold transition-all text-left border ${
              activeTab === 'dashboard'
                ? 'bg-slate-900 border-slate-700 text-white font-bold shadow-md'
                : 'border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
            }`}
          >
            <div className={`w-1 h-3 rounded-full ${activeTab === 'dashboard' ? 'bg-red-500' : 'bg-transparent'}`} />
            <Layers className="w-3.5 h-3.5" />
            <span>SOC Dashboard</span>
          </button>

          <button
            onClick={() => setActiveTab('logs')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold transition-all text-left border ${
              activeTab === 'logs'
                ? 'bg-slate-900 border-slate-700 text-white font-bold shadow-md'
                : 'border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
            }`}
          >
            <div className={`w-1 h-3 rounded-full ${activeTab === 'logs' ? 'bg-red-500' : 'bg-transparent'}`} />
            <Database className="w-3.5 h-3.5" />
            <span>Security Log Viewer</span>
          </button>

          <button
            onClick={() => setActiveTab('rules')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold transition-all text-left border ${
              activeTab === 'rules'
                ? 'bg-slate-900 border-slate-700 text-white font-bold shadow-md'
                : 'border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
            }`}
          >
            <div className={`w-1 h-3 rounded-full ${activeTab === 'rules' ? 'bg-red-500' : 'bg-transparent'}`} />
            <Sliders className="w-3.5 h-3.5" />
            <span>Rule Configurator</span>
          </button>

          <button
            onClick={() => setActiveTab('terminal')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold transition-all text-left border ${
              activeTab === 'terminal'
                ? 'bg-slate-900 border-slate-700 text-white font-bold shadow-md'
                : 'border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
            }`}
          >
            <div className={`w-1 h-3 rounded-full ${activeTab === 'terminal' ? 'bg-red-500' : 'bg-transparent'}`} />
            <Terminal className="w-3.5 h-3.5" />
            <span>Execution Console</span>
          </button>

          <button
            onClick={() => setActiveTab('report')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold transition-all text-left border ${
              activeTab === 'report'
                ? 'bg-slate-900 border-slate-700 text-white font-bold shadow-md'
                : 'border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
            }`}
          >
            <div className={`w-1 h-3 rounded-full ${activeTab === 'report' ? 'bg-red-500' : 'bg-transparent'}`} />
            <FileText className="w-3.5 h-3.5" />
            <span>Triage Incident Report</span>
          </button>

          <button
            onClick={() => setActiveTab('code')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold transition-all text-left border ${
              activeTab === 'code'
                ? 'bg-slate-900 border-slate-700 text-white font-bold shadow-md'
                : 'border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
            }`}
          >
            <div className={`w-1 h-3 rounded-full ${activeTab === 'code' ? 'bg-red-500' : 'bg-transparent'}`} />
            <FolderCode className="w-3.5 h-3.5" />
            <span>Python Codebase</span>
          </button>

          <button
            onClick={() => setActiveTab('guide')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold transition-all text-left border ${
              activeTab === 'guide'
                ? 'bg-slate-900 border-slate-700 text-white font-bold shadow-md'
                : 'border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
            }`}
          >
            <div className={`w-1 h-3 rounded-full ${activeTab === 'guide' ? 'bg-red-500' : 'bg-transparent'}`} />
            <BookOpen className="w-3.5 h-3.5" />
            <span>SOC Portfolio Guide</span>
          </button>

          {/* Project Context Sidebar Widget */}
          <div className="hidden md:block mt-auto p-3 bg-slate-900/50 rounded border border-slate-900">
            <p className="text-[10px] uppercase text-slate-500 font-bold mb-1 font-mono">Project Context</p>
            <p className="text-[11px] text-slate-400 leading-tight italic font-mono">AEGIS Risk Engine v2.4.0</p>
          </div>
        </nav>

        {/* Main Display Pane */}
        <main className="flex-1 p-6 overflow-y-auto bg-[#07090e] relative z-10 select-text">
          {activeTab === 'dashboard' && (
            <DashboardView 
              alerts={alerts} 
              metrics={metrics} 
              logs={logs}
              onTabChange={setActiveTab}
              onAlertSelect={setSelectedIncident}
            />
          )}

          {activeTab === 'logs' && (
            <LogViewer 
              logs={logs} 
              onAddLog={handleAddLog} 
              onResetLogs={handleResetLogs} 
            />
          )}

          {activeTab === 'rules' && (
            <RulesEditor 
              settings={ruleSettings} 
              onSettingsChange={setRuleSettings} 
              triggeredAlertCount={alerts.length}
            />
          )}

          {activeTab === 'terminal' && (
            <TerminalSimulation 
              logs={logs} 
              alerts={alerts} 
              metrics={metrics}
              ruleSettings={ruleSettings}
            />
          )}

          {activeTab === 'report' && (
            <IncidentReportViewer 
              alerts={alerts} 
              metrics={metrics} 
              logs={logs}
              ruleSettings={ruleSettings}
            />
          )}

          {activeTab === 'code' && (
            <CodeExplorer />
          )}

          {activeTab === 'guide' && (
            <GuideView />
          )}
        </main>
      </div>

      {/* 3. FOOTER */}
      <footer className="bg-slate-900 border-t border-slate-800 px-6 py-2.5 text-[10px] text-slate-500 font-mono flex flex-col sm:flex-row items-center justify-between select-none relative z-20">
        <span>© 2026 CYBERSECURITY OPERATIONS CENTER (SOC) - TIER 2 TRIAGE LAB</span>
        <div className="flex items-center gap-1.5 mt-1 sm:mt-0">
          <Clock className="w-3.5 h-3.5 text-slate-600" />
          <span>Active Session UTC: 2026-07-01 19:21:27</span>
        </div>
      </footer>

      {/* 4. FORENSIC TRIAGE OVERLAY DIALOG MODAL */}
      {selectedIncident && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-md flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="bg-slate-900 border border-slate-800 rounded-lg w-full max-w-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="bg-slate-950 px-5 py-4 border-b border-slate-850 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-red-500" />
                <span className="font-mono text-xs font-bold text-slate-400">FORENSIC INVESTIGATION FILE</span>
                <span className="text-[10px] font-bold px-1.5 py-0.5 bg-red-950/60 text-red-400 border border-red-900/40 rounded">
                  {selectedIncident.alert_id}
                </span>
              </div>
              <button 
                onClick={() => setSelectedIncident(null)}
                className="p-1 text-slate-500 hover:text-white bg-slate-900 hover:bg-slate-800 rounded-lg border border-slate-800 transition-all active:scale-95"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body content */}
            <div className="flex-1 overflow-y-auto p-5 space-y-5">
              
              {/* Core Alert Summary */}
              <div className="space-y-1.5">
                <h4 className="font-display font-semibold text-slate-100 text-sm">
                  {selectedIncident.title}
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-850">
                  {selectedIncident.details}
                </p>
              </div>

              {/* Alert Meta metrics */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-850 text-center">
                  <span className="text-[9px] uppercase font-semibold text-slate-500 tracking-wider block">Risk Level</span>
                  <span className={`text-xs font-bold block mt-0.5 ${
                    selectedIncident.risk_classification === 'CRITICAL' ? 'text-red-400' : selectedIncident.risk_classification === 'HIGH' ? 'text-amber-400' : 'text-slate-300'
                  }`}>
                    {selectedIncident.risk_classification}
                  </span>
                </div>
                <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-850 text-center">
                  <span className="text-[9px] uppercase font-semibold text-slate-500 tracking-wider block">Score Index</span>
                  <span className="text-sm font-extrabold font-mono block mt-0.5 text-slate-100">
                    {selectedIncident.risk_score}/100
                  </span>
                </div>
                <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-850 text-center">
                  <span className="text-[9px] uppercase font-semibold text-slate-500 tracking-wider block">Target User</span>
                  <span className="text-xs font-semibold block mt-0.5 text-slate-200 truncate" title={selectedIncident.primary_actor}>
                    {selectedIncident.primary_actor}
                  </span>
                </div>
                <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-850 text-center">
                  <span className="text-[9px] uppercase font-semibold text-slate-500 tracking-wider block">Attacking IP</span>
                  <span className="text-xs font-mono block mt-0.5 text-slate-200 truncate" title={selectedIncident.ip_address}>
                    {selectedIncident.ip_address}
                  </span>
                </div>
              </div>

              {/* Connected events / forensic evidence */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wide block">Forensic Log Evidence</span>
                
                <div className="bg-slate-950 border border-slate-850 rounded-lg overflow-hidden">
                  <div className="max-h-36 overflow-y-auto divide-y divide-slate-900/40 text-[10px] font-mono">
                    {logs.filter(l => selectedIncident.triggered_logs.includes(l.id)).map((ev) => (
                      <div key={ev.id} className="p-2.5 hover:bg-slate-900/20 flex flex-col md:flex-row md:items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500">[{ev.id}]</span>
                          <span className="text-slate-400">{ev.timestamp.toISOString().replace('T', ' ').substring(0, 19)}</span>
                          <span className="font-semibold text-slate-300">{ev.username}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-1 rounded border text-[9px] uppercase ${ev.status === 'failed' ? 'bg-red-950/40 text-rose-400 border-rose-900/30' : 'bg-green-950/40 text-emerald-400 border-emerald-900/30'}`}>
                            {ev.status}
                          </span>
                          <span className="text-slate-400 font-sans max-w-xs truncate" title={ev.details}>{ev.details}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Remediation steps list */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wide block">Containment Incident Playbook (NIST SP 800-61)</span>
                
                <div className="space-y-2">
                  {(selectedIncident.remediation_playbook || getRemediationPlaybook(selectedIncident.category)).map((step, sIdx) => (
                    <div key={sIdx} className="flex items-start gap-2 text-xs text-slate-300 leading-relaxed">
                      <div className="w-1.5 h-1.5 rounded-full bg-red-500 mt-1.5 flex-shrink-0" />
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>

            </div>

            {/* Modal Footer actions */}
            <div className="bg-slate-950 px-5 py-3 border-t border-slate-800 flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-500">TRIAGE LEVEL: COMPLETED</span>
              <button
                onClick={() => {
                  setSelectedIncident(null);
                  setActiveTab('report');
                }}
                className="flex items-center gap-1 px-3 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-700 rounded shadow active:scale-95 transition-all"
              >
                <span>Navigate to full report</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
