// src/components/LogViewer.tsx
import React, { useState } from 'react';
import { LogRecord } from '../utils/securityEngine';
import { Search, Plus, Filter, RotateCcw, AlertCircle, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface LogViewerProps {
  logs: LogRecord[];
  onAddLog: (log: Omit<LogRecord, 'id'>) => void;
  onResetLogs: () => void;
}

export default function LogViewer({ logs, onAddLog, onResetLogs }: LogViewerProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  
  // New log form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newIp, setNewIp] = useState('');
  const [newEventType, setNewEventType] = useState('login');
  const [newStatus, setNewStatus] = useState('success');
  const [newDetails, setNewDetails] = useState('');
  const [newIsAdmin, setNewIsAdmin] = useState(false);

  // Filter logs based on search and selected options
  const filteredLogs = logs.filter(log => {
    const matchesSearch = 
      log.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.ip_address.includes(searchTerm) ||
      log.details.toLowerCase().includes(searchTerm.toLowerCase());
      
    const matchesType = eventTypeFilter === 'ALL' || log.event_type === eventTypeFilter;
    const matchesStatus = statusFilter === 'ALL' || log.status === statusFilter;
    
    return matchesSearch && matchesType && matchesStatus;
  });

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername || !newIp || !newDetails) {
      alert("All fields are required to inject a log record.");
      return;
    }

    const timestamp = new Date(); // Injecting at current simulation time
    const raw_timestamp = timestamp.toISOString();

    onAddLog({
      timestamp,
      raw_timestamp,
      username: newUsername,
      ip_address: newIp,
      event_type: newEventType,
      status: newStatus,
      details: newDetails,
      is_admin: newIsAdmin
    });

    // Clear form
    setNewUsername('');
    setNewIp('');
    setNewEventType('login');
    setNewStatus('success');
    setNewDetails('');
    setNewIsAdmin(false);
    setShowAddForm(false);
  };

  // Preset quick templates to help users easily inject attacks!
  const loadAttackTemplate = (type: 'brute_force' | 'impossible_travel' | 'privilege_escalation') => {
    if (type === 'brute_force') {
      setNewUsername('admin_user');
      setNewIp('103.220.55.12');
      setNewEventType('login');
      setNewStatus('failed');
      setNewDetails('Authentication failure - invalid creds (Simulating Brute Force)');
      setNewIsAdmin(true);
    } else if (type === 'impossible_travel') {
      setNewUsername('m.rogers');
      setNewIp('210.14.99.102');
      setNewEventType('login');
      setNewStatus('success');
      setNewDetails('Interactive console logon from Tokyo IP (Simulating Impossible Travel)');
      setNewIsAdmin(false);
    } else {
      setNewUsername('temp_guest');
      setNewIp('192.168.10.88');
      setNewEventType('command_execution');
      setNewStatus('failed');
      setNewDetails('Attempted sudo edit of /etc/shadow (Simulating Privilege Escalation)');
      setNewIsAdmin(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Search and control row */}
      <div className="bg-[#0b0f19] border border-slate-900 rounded p-4 flex flex-col md:flex-row gap-4 items-center justify-between shadow-md">
        <div className="flex-1 w-full flex flex-col md:flex-row gap-3 items-center">
          {/* Search bar */}
          <div className="relative w-full md:max-w-xs font-mono">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search logs by IP, User, details..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-950 border border-slate-900 focus:border-red-500 rounded text-slate-200 placeholder-slate-500 font-sans focus:outline-none transition-all"
            />
          </div>

          {/* Type dropdown */}
          <div className="flex items-center gap-1.5 w-full md:w-auto font-mono">
            <Filter className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
            <select
              value={eventTypeFilter}
              onChange={(e) => setEventTypeFilter(e.target.value)}
              className="w-full md:w-auto bg-slate-950 border border-slate-900 text-slate-300 text-xs py-1.5 px-3 rounded focus:outline-none focus:border-red-500"
            >
              <option value="ALL">All Event Types</option>
              <option value="login">Logins</option>
              <option value="file_access">File Access</option>
              <option value="command_execution">Commands</option>
              <option value="database_query">DB Queries</option>
              <option value="configuration_change">Configs</option>
            </select>
          </div>

          {/* Status dropdown */}
          <div className="w-full md:w-auto font-mono">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full md:w-auto bg-slate-950 border border-slate-900 text-slate-300 text-xs py-1.5 px-3 rounded focus:outline-none focus:border-red-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="success">Success only</option>
              <option value="failed">Failed only</option>
            </select>
          </div>
        </div>

        {/* Action button triggers */}
        <div className="flex items-center gap-3 w-full md:w-auto self-end md:self-center justify-end font-mono">
          <button
            onClick={() => {
              setShowAddForm(!showAddForm);
              loadAttackTemplate('brute_force'); // preset a nice default
            }}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded shadow transition-all active:scale-95 uppercase tracking-wide"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Inject Event</span>
          </button>
          
          <button
            onClick={onResetLogs}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded transition-all active:scale-95"
            title="Reset Logs to Default dataset"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Dataset</span>
          </button>
        </div>
      </div>

      {/* Form modal block */}
      {showAddForm && (
        <div className="bg-[#0b0f19] border border-slate-900 rounded p-5 shadow-2xl space-y-4 animate-fadeIn">
          <div className="flex items-start justify-between border-b border-slate-850 pb-3">
            <div>
              <h4 className="font-display font-semibold text-slate-200 text-sm flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-red-500" />
                Inject Custom Security Log Record
              </h4>
              <p className="text-xs text-slate-400 mt-0.5">
                This adds a new log row into the parsed database. Trigger signatures directly to watch how rules react!
              </p>
            </div>
            {/* Quick attack injector options */}
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-bold text-slate-500 mr-1.5 font-mono">QUICK ATTACK TEMPLATES:</span>
              <button 
                type="button"
                onClick={() => loadAttackTemplate('brute_force')}
                className="text-[10px] font-semibold px-2 py-1 bg-red-950/40 text-rose-400 hover:bg-red-950/80 rounded border border-rose-900/30 transition-all"
              >
                Failed Login
              </button>
              <button 
                type="button"
                onClick={() => loadAttackTemplate('impossible_travel')}
                className="text-[10px] font-semibold px-2 py-1 bg-amber-950/40 text-amber-400 hover:bg-amber-950/80 rounded border border-amber-900/30 transition-all"
              >
                Login (VPN IP)
              </button>
              <button 
                type="button"
                onClick={() => loadAttackTemplate('privilege_escalation')}
                className="text-[10px] font-semibold px-2 py-1 bg-purple-950/40 text-purple-400 hover:bg-purple-950/80 rounded border border-purple-900/30 transition-all"
              >
                Restricted Sudo File
              </button>
            </div>
          </div>

          <form onSubmit={handleFormSubmit} className="grid grid-cols-1 md:grid-cols-12 gap-4">
            {/* User */}
            <div className="md:col-span-3 space-y-1">
              <label className="text-xs text-slate-450 font-medium">Username</label>
              <input
                type="text"
                required
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="e.g. system_admin, guest_user"
                className="w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-900 focus:border-red-500 rounded text-slate-200 outline-none font-mono"
              />
            </div>

            {/* IP Address */}
            <div className="md:col-span-3 space-y-1">
              <label className="text-xs text-slate-455 font-medium">Source IP Address</label>
              <input
                type="text"
                required
                value={newIp}
                onChange={(e) => setNewIp(e.target.value)}
                placeholder="e.g. 192.168.10.42, 45.12.9.22"
                className="w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-900 focus:border-red-500 rounded text-slate-200 outline-none font-mono"
              />
            </div>

            {/* Event Type */}
            <div className="md:col-span-3 space-y-1">
              <label className="text-xs text-slate-450 font-medium">Event Type</label>
              <select
                value={newEventType}
                onChange={(e) => setNewEventType(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-900 focus:border-red-500 rounded text-slate-200 outline-none font-mono"
              >
                <option value="login">login</option>
                <option value="file_access">file_access</option>
                <option value="command_execution">command_execution</option>
                <option value="database_query">database_query</option>
                <option value="configuration_change">configuration_change</option>
              </select>
            </div>

            {/* Status */}
            <div className="md:col-span-3 space-y-1">
              <label className="text-xs text-slate-450 font-medium">Status</label>
              <select
                value={newStatus}
                onChange={(e) => setNewStatus(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-900 focus:border-red-500 rounded text-slate-200 outline-none font-mono"
              >
                <option value="success">success</option>
                <option value="failed">failed</option>
              </select>
            </div>

            {/* Details */}
            <div className="md:col-span-9 space-y-1">
              <label className="text-xs text-slate-450 font-medium">Activity Details</label>
              <input
                type="text"
                required
                value={newDetails}
                onChange={(e) => setNewDetails(e.target.value)}
                placeholder="e.g. Attempted unauthorized read on /var/log/secure"
                className="w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-900 focus:border-red-500 rounded text-slate-200 outline-none font-mono"
              />
            </div>

            {/* Admin status toggles */}
            <div className="md:col-span-3 flex items-center h-full pt-6 pl-2 font-mono">
              <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={newIsAdmin}
                  onChange={(e) => setNewIsAdmin(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-900 text-red-600 focus:ring-0 w-4 h-4"
                />
                <span>Target is Administrator</span>
              </label>
            </div>

            {/* Buttons */}
            <div className="md:col-span-12 flex justify-end gap-3 pt-2 font-mono">
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="px-4 py-1.5 text-xs font-semibold text-slate-400 hover:text-white bg-slate-900 hover:bg-slate-800 rounded border border-slate-800 transition-all active:scale-95"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded shadow transition-all active:scale-95 uppercase tracking-wide"
              >
                Inject event
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Main Table View */}
      <div className="bg-[#0b0f19] border border-slate-900 rounded overflow-hidden shadow-md">
        <div className="overflow-x-auto max-h-[550px]">
          <table className="w-full text-left border-collapse font-sans text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase font-mono tracking-wider font-semibold text-[10px]">
                <th className="px-5 py-3">ID</th>
                <th className="px-5 py-3">Timestamp (UTC)</th>
                <th className="px-5 py-3">Username</th>
                <th className="px-5 py-3">IP Address</th>
                <th className="px-5 py-3">Event Type</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Activity Description</th>
                <th className="px-5 py-3">Admin</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40 text-slate-300 font-mono">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-5 py-12 text-center text-slate-500">
                    No log records match the current filters. Search query returned 0 rows.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => {
                  const isFail = log.status === 'failed';
                  const isSuccess = log.status === 'success';

                  return (
                    <tr key={log.id} className="hover:bg-slate-950/20 transition-all">
                      <td className="px-5 py-3 text-slate-500 font-bold">{log.id}</td>
                      <td className="px-5 py-3 text-slate-400 truncate max-w-[150px]">
                        {log.timestamp.toISOString().replace('T', ' ').substring(0, 19)}
                      </td>
                      <td className="px-5 py-3 font-semibold text-slate-200">{log.username}</td>
                      <td className="px-5 py-3 text-slate-300 font-semibold">{log.ip_address}</td>
                      <td className="px-5 py-3 truncate">
                        <span className="bg-slate-950 px-2 py-0.5 border border-slate-800 rounded font-bold text-[10px]">
                          {log.event_type}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        <span className={`inline-flex items-center gap-1 font-bold ${isFail ? 'text-rose-400' : isSuccess ? 'text-emerald-400' : 'text-slate-400'}`}>
                          {isFail ? (
                            <>
                              <AlertCircle className="w-3 h-3 flex-shrink-0" />
                              <span>failed</span>
                            </>
                          ) : isSuccess ? (
                            <>
                              <CheckCircle2 className="w-3 h-3 flex-shrink-0" />
                              <span>success</span>
                            </>
                          ) : (
                            <span>{log.status}</span>
                          )}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-slate-300 font-sans max-w-sm truncate" title={log.details}>
                        {log.details}
                      </td>
                      <td className="px-5 py-3">
                        {log.is_admin ? (
                          <span className="bg-rose-950/50 text-rose-400 border border-rose-900/30 font-bold text-[9px] px-1.5 py-0.5 rounded uppercase">
                            Admin
                          </span>
                        ) : (
                          <span className="text-slate-600 font-bold text-[9px] uppercase">
                            Std
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {/* Table summary line */}
        <div className="bg-slate-950/80 px-5 py-3 border-t border-slate-800 flex justify-between items-center text-[10px] text-slate-500 font-mono">
          <span>INGEST STATISTICS: SHOWING {filteredLogs.length} OF {logs.length} LOG RECORDED DATA</span>
          <span>SYSTEM CHRONO ORDER: ACTIVE</span>
        </div>
      </div>
    </div>
  );
}
