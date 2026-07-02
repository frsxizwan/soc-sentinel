// src/components/RulesEditor.tsx
import React from 'react';
import { Sliders, ShieldCheck, ShieldAlert, Award, FileSpreadsheet } from 'lucide-react';

interface RulesEditorProps {
  settings: { bruteForceLimit: number; bruteForceWindow: number; travelWindow: number };
  onSettingsChange: (newSettings: { bruteForceLimit: number; bruteForceWindow: number; travelWindow: number }) => void;
  triggeredAlertCount: number;
}

export default function RulesEditor({ settings, onSettingsChange, triggeredAlertCount }: RulesEditorProps) {
  
  const handleLimitChange = (val: number) => {
    onSettingsChange({ ...settings, bruteForceLimit: val });
  };

  const handleBfWindowChange = (val: number) => {
    onSettingsChange({ ...settings, bruteForceWindow: val });
  };

  const handleTravelWindowChange = (val: number) => {
    onSettingsChange({ ...settings, travelWindow: val });
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Controls Segment Left (7 Cols) */}
      <div className="lg:col-span-7 bg-[#0b0f19] border border-slate-900 rounded p-5 space-y-6 shadow-md">
        <div className="border-b border-slate-850 pb-3 mb-4 flex items-center gap-2">
          <Sliders className="w-4 h-4 text-red-500" />
          <h4 className="text-sm font-display font-semibold text-slate-200">Adjust SOC Alarm Threshold Constraints</h4>
        </div>

        <div className="space-y-6">
          {/* Brute Force failed attempts limit */}
          <div className="space-y-2">
            <div className="flex justify-between items-center font-mono">
              <label className="text-xs text-slate-300 font-semibold block">
                Brute-Force Login Failure Threshold
              </label>
              <span className="text-xs text-red-500 bg-slate-950 px-2 py-0.5 rounded border border-slate-900">
                {settings.bruteForceLimit} failed attempts
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              The number of consecutive failed authentication events logged before triggering a BRUTE_FORCE alert. Lower thresholds catch more slow attacks but increase false positives on forgotten passwords.
            </p>
            <input
              type="range"
              min="2"
              max="10"
              step="1"
              value={settings.bruteForceLimit}
              onChange={(e) => handleLimitChange(Number(e.target.value))}
              className="w-full accent-red-600 cursor-pointer h-1.5 bg-slate-950 rounded"
            />
          </div>

          {/* Brute Force Window */}
          <div className="space-y-2">
            <div className="flex justify-between items-center font-mono">
              <label className="text-xs text-slate-300 font-semibold block">
                Brute-Force Correlation Window
              </label>
              <span className="text-xs text-red-500 bg-slate-950 px-2 py-0.5 rounded border border-slate-900">
                {settings.bruteForceWindow} seconds ({Math.round(settings.bruteForceWindow / 60)} mins)
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              The sliding time-window constraint in seconds used to bundle failed authentications coming from the same IP. Adversaries often space attacks to bypass short windows.
            </p>
            <input
              type="range"
              min="60"
              max="1800"
              step="60"
              value={settings.bruteForceWindow}
              onChange={(e) => handleBfWindowChange(Number(e.target.value))}
              className="w-full accent-red-600 cursor-pointer h-1.5 bg-slate-950 rounded"
            />
          </div>

          {/* Impossible Travel Window */}
          <div className="space-y-2">
            <div className="flex justify-between items-center font-mono">
              <label className="text-xs text-slate-300 font-semibold block">
                Impossible Travel Geographical Threshold
              </label>
              <span className="text-xs text-red-500 bg-slate-950 px-2 py-0.5 rounded border border-slate-900">
                {settings.travelWindow} seconds ({Math.round(settings.travelWindow / 60)} mins)
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              The time constraint allowed between two successful logins from different IP addresses. If a single user logs in from an office workstation and then from a VPN IP within this window, we flag impossible velocity.
            </p>
            <input
              type="range"
              min="60"
              max="3600"
              step="60"
              value={settings.travelWindow}
              onChange={(e) => handleTravelWindowChange(Number(e.target.value))}
              className="w-full accent-red-600 cursor-pointer h-1.5 bg-slate-950 rounded"
            />
          </div>
        </div>
      </div>

      {/* Real-time Alert Impact Right (5 Cols) */}
      <div className="lg:col-span-5 bg-[#0b0f19] border border-slate-900 rounded p-5 flex flex-col justify-between shadow-md">
        <div className="border-b border-slate-850 pb-3 mb-4">
          <h4 className="text-sm font-display font-semibold text-slate-200">Real-time Rule Output Profile</h4>
        </div>

        {/* Dynamic feedback display */}
        <div className="flex-1 flex flex-col items-center justify-center text-center p-6 space-y-4">
          <div className={`p-4 rounded border shadow-xl ${
            triggeredAlertCount > 0 
              ? 'bg-rose-950/20 text-rose-400 border-rose-900/30' 
              : 'bg-emerald-950/20 text-emerald-400 border-emerald-900/30'
          }`}>
            {triggeredAlertCount > 0 ? (
              <ShieldAlert className="w-10 h-10 animate-pulse" />
            ) : (
              <ShieldCheck className="w-10 h-10" />
            )}
          </div>

          <div className="space-y-1">
            <h5 className="font-semibold text-slate-200 text-sm">
              {triggeredAlertCount > 0 ? `${triggeredAlertCount} Active Alarms Triggered` : 'Perimeter fully Secure'}
            </h5>
            <p className="text-xs text-slate-400 max-w-xs leading-relaxed">
              {triggeredAlertCount > 0 
                ? 'Your current rule thresholds have successfully correlated logs and parsed security alarms.'
                : 'Current constraints are too relaxed to trigger any threat signatures from raw logs. Adjust sliders to fine-tune alerts.'}
            </p>
          </div>
        </div>

        {/* SOC Analysis Guidelines box */}
        <div className="bg-slate-950/50 rounded p-3.5 border border-slate-850 space-y-2 text-xs text-slate-450">
          <span className="font-bold text-slate-300 block uppercase tracking-wider text-[10px] font-mono">Tuning Rationale (SOC Thinking)</span>
          <p className="leading-relaxed">
            SOC analysts constantly audit SIEM correlation thresholds. In an active security incident, an analyst might "tighten" rule windows to detect low-and-slow exfiltration patterns or password spraying, and "relax" rules during system maintenance to reduce alert exhaustion.
          </p>
        </div>
      </div>
    </div>
  );
}
