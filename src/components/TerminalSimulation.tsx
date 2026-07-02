// src/components/TerminalSimulation.tsx
import { useState, useEffect, useRef } from 'react';
import { Play, RotateCcw, Terminal, AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react';
import { LogRecord, SecurityAlert, SecurityMetrics } from '../utils/securityEngine';

interface TerminalSimulationProps {
  logs: LogRecord[];
  alerts: SecurityAlert[];
  metrics: SecurityMetrics;
  onSimComplete?: () => void;
  ruleSettings: { bruteForceLimit: number; bruteForceWindow: number; travelWindow: number };
}

export default function TerminalSimulation({ logs, alerts, metrics, onSimComplete, ruleSettings }: TerminalSimulationProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const activeAlertCount = alerts.length;

  // Auto-scroll terminal to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [terminalLines]);

  const runSimulation = async () => {
    setIsPlaying(true);
    setTerminalLines([]);
    setProgress(0);

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    const addLine = (text: string) => {
      setTerminalLines(prev => [...prev, text]);
    };

    // Stage 0: Initial boot
    addLine("frsxizwan@soc-analyst-terminal:~$ python3 main.py --file sample_logs.csv");
    await sleep(400);
    addLine("\x1b[96m\x1b[1m");
    addLine("    ╔══════════════════════════════════════════════════════════════════════════╗");
    addLine("    ║       A U T O M A T E D   S E C U R I T Y   L O G   A N A L Y Z E R      ║");
    addLine("    ║                &   T H R E A T   D E T E C T I O N                       ║");
    addLine("    ║                                                                          ║");
    addLine("    ║                  [ Tier 2/3 SOC Incident Response Triage ]               ║");
    addLine("    ╚══════════════════════════════════════════════════════════════════════════╝");
    addLine("\x1b[0m");
    await sleep(600);

    // Stage 1: Ingestion
    setProgress(15);
    addLine("[*] \x1b[1mStage 1: Log Ingestion & Parsing\x1b[0m");
    await sleep(300);
    addLine("    [+] Loading raw file target: 'sample_logs.csv'...");
    await sleep(500);
    addLine(`    [+] Log parsing completed. Ingested \x1b[92m${logs.length} records\x1b[0m.`);
    
    const errors = logs.filter(l => isNaN(l.timestamp.getTime())).length;
    if (errors > 0) {
      addLine(`    [\x1b[93m!\x1b[0m] Malformed rows skipped during ingest: \x1b[93m${errors}\x1b[0m`);
    } else {
      addLine("    [+] Data validation checks: \x1b[92mPASS\x1b[0m (Zero structural parser issues).");
    }
    
    if (logs.length > 0) {
      const startStr = logs[0].timestamp.toISOString().replace('T', ' ').substring(0, 19);
      const endStr = logs[logs.length - 1].timestamp.toISOString().replace('T', ' ').substring(0, 19);
      addLine(`    [+] Timeline scope: \x1b[96m${startStr}\x1b[0m to \x1b[96m${endStr}\x1b[0m`);
    }
    addLine("--------------------------------------------------------------------------------");
    await sleep(400);

    // Stage 2: Scanning & Threats Detection
    setProgress(45);
    addLine("[*] \x1b[1mStage 2: Running Stateful Threat Detection Analytics\x1b[0m");
    await sleep(300);
    addLine(`    [+] Settings: Brute Force window = ${ruleSettings.bruteForceWindow}s, threshold = ${ruleSettings.bruteForceLimit} attempts`);
    addLine(`    [+] Settings: Impossible Travel Window = ${ruleSettings.travelWindow}s`);
    await sleep(200);
    addLine("    [+] Scanning chronological streams...");
    await sleep(700);
    addLine(`    [+] Completed signature matching. Found \x1b[93m${alerts.length} threats\x1b[0m with base indicators.`);
    addLine("--------------------------------------------------------------------------------");
    await sleep(400);

    // Stage 3: Risk Engine Scoring
    setProgress(75);
    addLine("[*] \x1b[1mStage 3: Running Contextual Risk Engine\x1b[0m");
    await sleep(400);
    addLine("    [+] Ingesting alert signatures into threat matrices...");
    await sleep(300);
    addLine(`    [+] Applied risk matrices. Active Incident Severity: \x1b[91m\x1b[1m${metrics.max_score}/100\x1b[0m`);
    addLine(`    [+] Average threat risk score: \x1b[93m${metrics.avg_score}/100\x1b[0m`);
    addLine("--------------------------------------------------------------------------------");
    await sleep(400);

    // Stage 4: Alert Feed Stream
    addLine("[*] \x1b[1mReal-Time Alert Feed Stream:\x1b[0m");
    addLine("================================================================================");
    await sleep(300);

    if (alerts.length === 0) {
      addLine("    \x1b[92m[+] SECURE: No alerts triggered during log scans.\x1b[0m");
    } else {
      for (const alert of alerts) {
        const risk = alert.risk_classification || 'LOW';
        const score = alert.risk_score || 0;
        let prefix = "";
        
        if (risk === "CRITICAL") {
          prefix = "\x1b[91m\x1b[1m[!!! CRITICAL Alert]";
        } else if (risk === "HIGH") {
          prefix = "\x1b[91m[! HIGH Alert]";
        } else if (risk === "MEDIUM") {
          prefix = "\x1b[93m[+ MEDIUM Alert]";
        } else {
          prefix = "\x1b[92m[* LOW Alert]";
        }
        
        addLine(`${prefix} ID: ${alert.alert_id} | Risk Score: ${score}/100 | \x1b[1m${alert.title}\x1b[0m`);
        addLine(`    Actor: ${alert.primary_actor} | IP: ${alert.ip_address} | Time: ${alert.timestamp.toISOString()}`);
        addLine(`    Summary: ${alert.details}`);
        addLine("--------------------------------------------------------------------------------");
        await sleep(600); // Create realistic feed pacing
      }
    }

    // Stage 5: Report generation
    setProgress(95);
    addLine("[*] \x1b[1mStage 4: Generating Incident Response Reports\x1b[0m");
    await sleep(400);
    addLine("    [+] Formatted SOC Report saved to : \x1b[92m/python_project/soc_incident_report.txt\x1b[0m");
    addLine("    [+] Machine JSON Incident data to : \x1b[92m/python_project/soc_incident_report.json\x1b[0m");
    addLine("================================================================================");
    await sleep(500);
    addLine("\x1b[92m\x1b[1m[✓] Incident Triage Routine Completed Successfully.\x1b[0m");
    addLine("frsxizwan@soc-analyst-terminal:~$ ");
    setProgress(100);
    setIsPlaying(false);
    
    if (onSimComplete) onSimComplete();
  };

  const handleReset = () => {
    setIsPlaying(false);
    setTerminalLines([]);
    setProgress(0);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-140px)] bg-black border border-slate-900 rounded overflow-hidden shadow-2xl">
      {/* Terminal Title Header */}
      <div className="bg-[#0b0f19] border-b border-slate-900 px-4 py-3 flex items-center justify-between font-mono">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-red-500" />
          <span className="text-xs text-slate-300 font-semibold tracking-wide uppercase">SOC Console Terminal</span>
          <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse ml-1.5" />
        </div>
        <div className="flex items-center gap-3">
          <span className="text-slate-500 text-[10px]">Python Engine Sim v1.2</span>
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-slate-900"></span>
            <span className="w-3 h-3 rounded-full bg-slate-900"></span>
            <span className="w-3 h-3 rounded-full bg-slate-900"></span>
          </div>
        </div>
      </div>

      {/* Control Banner */}
      <div className="bg-slate-950/40 px-5 py-4 border-b border-slate-900 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h4 className="text-sm font-display font-semibold text-slate-200">Simulate Triage CLI Execution</h4>
          <p className="text-xs text-slate-400 mt-1">
            Orchestrates the parsed log data against active heuristics and writes structural reports locally.
          </p>
        </div>
        <div className="flex items-center gap-3 self-start md:self-center font-mono">
          <button
            onClick={runSimulation}
            disabled={isPlaying}
            className={`flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded transition-all shadow-md active:scale-95 uppercase tracking-wide ${
              isPlaying
                ? 'bg-slate-900 text-slate-500 cursor-not-allowed border border-slate-800'
                : 'bg-red-600 hover:bg-red-500 text-white hover:shadow-red-500/10'
            }`}
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{terminalLines.length > 0 ? 'Re-Run Simulation' : 'Run Python Script'}</span>
          </button>
          
          <button
            onClick={handleReset}
            disabled={isPlaying || terminalLines.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-300 bg-slate-900 hover:bg-slate-800 active:scale-95 disabled:opacity-40 disabled:hover:bg-slate-900 border border-slate-800 rounded transition-all"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Clear Screen</span>
          </button>
        </div>
      </div>

      {/* Progress slider bar */}
      {isPlaying && (
        <div className="w-full h-1 bg-slate-950">
          <div className="h-full bg-red-600 transition-all duration-300" style={{ width: `${progress}%` }}></div>
        </div>
      )}

      {/* Retro CRT Terminal Screen */}
      <div 
        ref={scrollRef}
        className="flex-1 bg-black text-emerald-400 font-mono text-xs overflow-auto p-5 select-text leading-relaxed relative flex flex-col"
        style={{
          boxShadow: 'inset 0 0 40px rgba(0,0,0,0.9)',
          backgroundImage: 'linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06))',
          backgroundSize: '100% 4px, 6px 100%'
        }}
      >
        {/* Terminal Background Scanline Effect */}
        <div className="absolute inset-0 pointer-events-none bg-gradient-to-b from-transparent via-red-500/5 to-transparent h-1/2 animate-pulse" />

        {terminalLines.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-500 text-center space-y-3 font-sans max-w-md mx-auto py-12">
            <div className="p-4 bg-slate-900/60 rounded-full border border-slate-800 shadow-xl">
              <Terminal className="w-8 h-8 text-slate-400" />
            </div>
            <div className="space-y-1">
              <h5 className="font-semibold text-slate-300">Terminal Idle</h5>
              <p className="text-xs text-slate-500 font-mono">
                Click "Run Python Script" to fire up the SOC pipeline. Watch logs stream through our ingestion, rule mapping, and scoring phases.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-1.5 flex-1 relative z-10 select-text pr-2">
            {terminalLines.map((line, idx) => {
              // Standard ANSI color conversion logic
              let cleanLine = line;
              let isBold = false;
              let colorClass = "text-emerald-400"; // default terminal color

              if (line.includes("\x1b[96m")) { // Cyan -> mapped to Red for custom styling
                colorClass = "text-red-400 font-medium";
                cleanLine = cleanLine.replace(/\x1b\[96m/g, '');
              }
              if (line.includes("\x1b[92m")) { // Green
                colorClass = "text-emerald-400 font-medium";
                cleanLine = cleanLine.replace(/\x1b\[92m/g, '');
              }
              if (line.includes("\x1b[91m")) { // Red
                colorClass = "text-rose-500 font-semibold";
                cleanLine = cleanLine.replace(/\x1b\[91m/g, '');
              }
              if (line.includes("\x1b[93m")) { // Yellow
                colorClass = "text-amber-400";
                cleanLine = cleanLine.replace(/\x1b\[93m/g, '');
              }
              if (line.includes("\x1b[1m")) { // Bold
                isBold = true;
                cleanLine = cleanLine.replace(/\x1b\[1m/g, '');
              }
              // Strip trailing reset keys
              cleanLine = cleanLine.replace(/\x1b\[0m/g, '');

              // Highlight stage separations
              if (cleanLine.startsWith("[*]")) {
                return (
                  <div key={idx} className="pt-4 pb-1 font-semibold text-slate-200 text-sm flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-red-500" />
                    <span>{cleanLine}</span>
                  </div>
                );
              }

              // Highlight specific Alerts triggered
              if (cleanLine.includes("[!!! CRITICAL Alert]")) {
                return (
                  <div key={idx} className="bg-rose-950/20 border-l-4 border-rose-600 p-2.5 my-2 rounded-r flex items-start gap-2.5">
                    <ShieldAlert className="w-4 h-4 text-rose-500 flex-shrink-0 mt-0.5 animate-bounce" />
                    <div>
                      <span className="text-rose-500 font-extrabold">{cleanLine}</span>
                    </div>
                  </div>
                );
              }
              if (cleanLine.includes("[! HIGH Alert]") || cleanLine.includes("[+ MEDIUM Alert]")) {
                const isHigh = cleanLine.includes("HIGH");
                return (
                  <div key={idx} className={`p-2 my-1.5 rounded border-l-2 ${isHigh ? 'bg-amber-950/10 border-amber-500 text-amber-500' : 'bg-slate-900/40 border-slate-500 text-slate-300'}`}>
                    <div className="flex items-center gap-1.5">
                      <AlertTriangle className={`w-3.5 h-3.5 ${isHigh ? 'text-amber-500' : 'text-slate-400'}`} />
                      <span className="font-semibold">{cleanLine}</span>
                    </div>
                  </div>
                );
              }

              if (cleanLine.includes("[✓]")) {
                return (
                  <div key={idx} className="pt-4 pb-1 text-emerald-400 flex items-center gap-1.5 font-bold">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>{cleanLine}</span>
                  </div>
                );
              }

              return (
                <div 
                  key={idx} 
                  className={`${colorClass} ${isBold ? 'font-bold' : ''} leading-5`}
                >
                  {cleanLine}
                </div>
              );
            })}
            
            {/* Blinking block cursor */}
            {isPlaying && (
              <span className="inline-block w-2.5 h-4 bg-emerald-400 ml-1 animate-ping" />
            )}
          </div>
        )}
      </div>
    </div>
  );
}
