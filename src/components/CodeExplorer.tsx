// src/components/CodeExplorer.tsx
import React, { useState } from 'react';
import { pythonFiles, PythonFile } from '../data/pythonFiles';
import { FolderCode, FileText, FileCode, Check, Copy, HardDrive, Info } from 'lucide-react';

export default function CodeExplorer() {
  const [activeFile, setActiveFile] = useState<PythonFile>(pythonFiles[0]);
  const [copied, setCopied] = useState<string | null>(null);

  const handleCopy = (file: PythonFile) => {
    navigator.clipboard.writeText(file.code);
    setCopied(file.name);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-[calc(100vh-140px)] min-h-[500px]">
      {/* File Tree Left Navigation (3 cols) */}
      <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col overflow-y-auto">
        <div className="flex items-center gap-2 pb-4 mb-4 border-b border-slate-800">
          <FolderCode className="w-5 h-5 text-cyan-400" />
          <h3 className="font-semibold text-slate-100 text-sm tracking-wide uppercase">Python Codebase</h3>
        </div>
        
        {/* Workspace Root Folder structure */}
        <div className="space-y-1">
          <div className="flex items-center gap-1.5 px-2 py-1 text-xs font-semibold text-slate-500 uppercase tracking-wider">
            <HardDrive className="w-3.5 h-3.5" />
            Project Root
          </div>
          
          <div className="pl-2 space-y-1">
            {pythonFiles.map((file) => {
              const isSelected = activeFile.name === file.name;
              const isPython = file.language === 'python';
              const isCsv = file.language === 'csv';
              
              return (
                <button
                  key={file.name}
                  onClick={() => setActiveFile(file)}
                  className={`w-full flex items-center gap-2 px-3 py-2 text-sm rounded-lg transition-all text-left group ${
                    isSelected
                      ? 'bg-cyan-950/40 text-cyan-400 border-l-2 border-cyan-400 font-medium'
                      : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                  }`}
                >
                  {isPython ? (
                    <FileCode className={`w-4 h-4 flex-shrink-0 ${isSelected ? 'text-cyan-400' : 'text-cyan-500/80'}`} />
                  ) : isCsv ? (
                    <FileText className={`w-4 h-4 flex-shrink-0 ${isSelected ? 'text-green-400' : 'text-green-500/80'}`} />
                  ) : (
                    <FileText className={`w-4 h-4 flex-shrink-0 ${isSelected ? 'text-yellow-400' : 'text-slate-500'}`} />
                  )}
                  <span className="truncate flex-1">{file.name}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Tech Info card at the bottom of sidebar */}
        <div className="mt-auto bg-slate-950/60 rounded-xl p-3 border border-slate-800/80 text-xs text-slate-400 leading-relaxed mt-6">
          <div className="flex items-center gap-1 text-cyan-400 font-medium mb-1">
            <Info className="w-3.5 h-3.5" />
            SOC Portfolio Note
          </div>
          All modules run purely on the Python Standard Library (3.8+). Resilient to missing inputs, empty rows, and malformed timestamps.
        </div>
      </div>

      {/* Code Editor Right Display (9 cols) */}
      <div className="lg:col-span-9 flex flex-col bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        {/* Editor Title Bar */}
        <div className="bg-slate-900 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <span className="w-3 h-3 rounded-full bg-rose-500/80"></span>
              <span className="w-3 h-3 rounded-full bg-amber-500/80"></span>
              <span className="w-3 h-3 rounded-full bg-emerald-500/80"></span>
            </div>
            <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2.5 py-1 rounded-md border border-slate-800">
              /python_project/{activeFile.path}
            </span>
          </div>

          <button
            onClick={() => handleCopy(activeFile)}
            className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 active:scale-95 rounded-lg border border-slate-700 transition-all"
          >
            {copied === activeFile.name ? (
              <>
                <Check className="w-3.5 h-3.5 text-green-400" />
                <span className="text-green-400">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Code</span>
              </>
            )}
          </button>
        </div>

        {/* File Description Summary */}
        <div className="bg-slate-900/40 px-5 py-3 border-b border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-300 leading-relaxed">
          <div className="w-5 h-5 flex-shrink-0 bg-cyan-950/80 rounded flex items-center justify-center border border-cyan-800/50 mt-0.5 text-cyan-400 font-bold font-mono">
            i
          </div>
          <div>
            <span className="font-semibold text-slate-200 uppercase tracking-wider block text-[10px] mb-0.5">Module Functionality</span>
            {activeFile.description}
          </div>
        </div>

        {/* Code Content Area */}
        <div className="flex-1 overflow-auto font-mono text-sm leading-6 p-4 text-slate-300 select-text">
          <div className="flex gap-4">
            {/* Fake line numbers */}
            <div className="text-right text-slate-600 select-none text-xs border-r border-slate-800/50 pr-3.5 text-opacity-50">
              {activeFile.code.split('\n').map((_, i) => (
                <div key={i} className="h-6">{i + 1}</div>
              ))}
            </div>
            {/* Raw preformatted code with syntax coloring tricks */}
            <pre className="text-xs overflow-x-auto text-slate-300 flex-1 whitespace-pre">
              <code className="block leading-6">{highlightPythonCode(activeFile.code, activeFile.language)}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

// Simple regex highlighter to make code view spectacular without huge dynamic parsing library
function highlightPythonCode(code: string, language: string): React.ReactNode[] {
  if (language !== 'python' && language !== 'json' && language !== 'markdown') {
    return [code];
  }

  const lines = code.split('\n');
  return lines.map((line, idx) => {
    // 1. Comments
    if (line.trim().startsWith('#')) {
      return <span key={idx} className="text-slate-500 italic block h-6">{line}</span>;
    }

    // 2. Python strings or docstrings
    // Let's keep it simple, return lines but color major things
    let renderedLine: React.ReactNode = line;
    
    // Simple inline colors
    const keywords = ['def ', 'class ', 'import ', 'from ', 'return ', 'if ', 'else', 'for ', 'while ', 'in ', 'not ', 'and ', 'try:', 'except ', 'with ', 'as ', 'elif ', 'try:'];
    const bolds = ['self.'];
    
    // If it's a docstring line, color it dark green
    if (line.includes('"""') || line.trim().startsWith('"""') || (line.trim().length > 0 && line.startsWith('    ') && idx > 1 && lines[idx-1].includes('"""') && !lines[idx-1].endsWith('"""'))) {
      return <span key={idx} className="text-emerald-600 font-medium block h-6">{line}</span>;
    }

    return (
      <span key={idx} className="block h-6 whitespace-pre">
        {line.split(/(\s+)/).map((part, pIdx) => {
          if (keywords.some(kw => part.startsWith(kw) || part === kw.trim())) {
            return <span key={pIdx} className="text-pink-400 font-semibold">{part}</span>;
          }
          if (part.startsWith('class') || part.startsWith('def')) {
            return <span key={pIdx} className="text-pink-400 font-semibold">{part}</span>;
          }
          if (bolds.some(b => part.includes(b))) {
            return <span key={pIdx} className="text-sky-400">{part}</span>;
          }
          if (part.startsWith('ALRT-') || part.startsWith('"ALRT-')) {
            return <span key={pIdx} className="text-amber-300 font-bold">{part}</span>;
          }
          if (part.startsWith('"') || part.startsWith("'") || part.endsWith('"') || part.endsWith("'")) {
            return <span key={pIdx} className="text-amber-200">{part}</span>;
          }
          if (part.match(/^\d+$/)) {
            return <span key={pIdx} className="text-violet-400">{part}</span>;
          }
          return part;
        })}
      </span>
    );
  });
}
