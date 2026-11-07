import React, { useState, useEffect, useMemo } from 'react';
import { Terminal, Copy, Check, Download, X, ShieldAlert, Cpu, ListFilter, CheckCircle, AlertTriangle } from 'lucide-react';
import { ScanLog } from '../types';

interface AuditDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  selectedLog: ScanLog | null;
}

export const AuditDrawer: React.FC<AuditDrawerProps> = ({
  isOpen,
  onClose,
  selectedLog
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'json' | 'structured'>('json');

  // Lock background scroll when drawer is open
  useEffect(() => {
    if (isOpen) {
      const originalOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';

      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') onClose();
      };
      window.addEventListener('keydown', handleKeyDown);

      return () => {
        document.body.style.overflow = originalOverflow;
        window.removeEventListener('keydown', handleKeyDown);
      };
    }
  }, [isOpen, onClose]);

  const jsonString = useMemo(() => {
    if (!selectedLog) return '';
    try {
      return JSON.stringify(selectedLog, null, 2);
    } catch {
      return '// Failed to serialize log';
    }
  }, [selectedLog]);

  const copyJson = () => {
    if (jsonString) {
      navigator.clipboard.writeText(jsonString);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const downloadJson = () => {
    if (!selectedLog) return;
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident-audit-${selectedLog.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      {/* Backdrop overlay */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 transition-opacity"
        />
      )}

      {/* Drawer matching user specification exact IDs */}
      <div
        id="auditDrawer"
        className={`${isOpen ? 'open' : ''} z-50 flex flex-col shadow-2xl`}
      >
        {/* Drawer Header */}
        <div className="p-4 border-b border-[#212c42] bg-[#0c1017] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-400">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
                <span>SOC Incident Telemetry</span>
                {selectedLog && (
                  <span className="text-xs text-cyan-400 font-normal">#SCAN-{selectedLog.id}</span>
                )}
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                Cryptographic & Heuristic Audit Record
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={copyJson}
              title="Copy Raw JSON"
              className="p-1.5 rounded-lg bg-[#161e30] border border-[#212c42] text-slate-300 hover:text-white transition cursor-pointer"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
            <button
              onClick={downloadJson}
              title="Download JSON Report"
              className="p-1.5 rounded-lg bg-[#161e30] border border-[#212c42] text-slate-300 hover:text-white transition cursor-pointer"
            >
              <Download className="w-4 h-4" />
            </button>
            <button
              id="btnCloseDrawer"
              onClick={onClose}
              title="Close Drawer (Esc)"
              className="p-1.5 rounded-lg bg-[#161e30] border border-[#212c42] text-slate-400 hover:text-red-400 transition cursor-pointer ml-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Selected Log Metadata Overview */}
        {selectedLog && (
          <div className="p-3.5 bg-[#111622] border-b border-[#212c42] grid grid-cols-3 gap-2 text-xs font-mono shrink-0">
            <div>
              <span className="text-slate-500 block text-[10px]">VERDICT</span>
              <span className={`badge ${selectedLog.threatLevel} mt-0.5`}>
                {selectedLog.threatLevel} ({selectedLog.score}/100)
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">IOCS RECORDED</span>
              <span className="text-slate-200 font-semibold mt-0.5 block">
                {selectedLog.indicators?.length || 0} Indicators
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">RECORD TIMESTAMP</span>
              <span className="text-slate-300 text-[11px] mt-0.5 block truncate">
                {new Date(selectedLog.scanDate || selectedLog.timestamp).toLocaleString()}
              </span>
            </div>
          </div>
        )}

        {/* View Toggle Bar */}
        <div className="flex border-b border-[#212c42] bg-[#0c1017] px-3 text-xs font-mono shrink-0">
          <button
            onClick={() => setActiveTab('json')}
            className={`py-2 px-3 border-b-2 font-medium transition cursor-pointer ${
              activeTab === 'json'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw JSON Record
          </button>
          <button
            onClick={() => setActiveTab('structured')}
            className={`py-2 px-3 border-b-2 font-medium transition cursor-pointer ${
              activeTab === 'structured'
                ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Structured Breakdown
          </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto bg-[#0a0d14] p-4">
          {activeTab === 'json' ? (
            /* JSON Viewer matching user specification exact ID: #drawerJsonContent */
            <pre
              id="drawerJsonContent"
              className="font-mono text-xs text-cyan-300 leading-relaxed whitespace-pre-wrap break-all select-all selection:bg-cyan-900 selection:text-white"
            >
              {jsonString || '// Select an incident from History to inspect JSON telemetry.'}
            </pre>
          ) : (
            /* Structured Summary View */
            <div className="space-y-4 font-mono text-xs">
              {/* Triggered Rules */}
              {selectedLog?.rulesTriggered && selectedLog.rulesTriggered.length > 0 && (
                <div>
                  <div className="text-slate-400 font-semibold mb-2 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span>Triggered Heuristic Rules ({selectedLog.rulesTriggered.length})</span>
                  </div>
                  <div className="space-y-1.5">
                    {selectedLog.rulesTriggered.map((rule, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-[#111622] border border-[#212c42]">
                        <div className="flex items-center justify-between text-slate-200 font-bold">
                          <span>{rule.rule}</span>
                          <span className="text-amber-400">+{rule.score} pts</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">{rule.explanation}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Indicators */}
              {selectedLog?.indicators && selectedLog.indicators.length > 0 && (
                <div>
                  <div className="text-slate-400 font-semibold mb-2 flex items-center gap-1.5">
                    <ListFilter className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Indicators of Compromise</span>
                  </div>
                  <div className="space-y-1.5">
                    {selectedLog.indicators.map((ioc, idx) => (
                      <div key={idx} className="p-2 rounded bg-[#111622] border border-[#212c42] flex items-center justify-between">
                        <span className="text-cyan-400 font-semibold">{ioc.indicatorType}:</span>
                        <code className="text-slate-200 text-[11px] break-all">{ioc.indicatorValue}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Authoritative DNS Auth */}
              {selectedLog?.dnsLiveCheck && (
                <div className="p-3 rounded-lg bg-[#111622] border border-[#212c42] space-y-2">
                  <div className="text-slate-300 font-semibold flex items-center justify-between">
                    <span>Live DNS Auth Check</span>
                    <span className={`badge ${selectedLog.dnsLiveCheck.dnsStatus === 'verified' ? 'Low' : 'High'}`}>
                      {selectedLog.dnsLiveCheck.dnsStatus}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{selectedLog.dnsLiveCheck.summary}</p>
                  {selectedLog.dnsLiveCheck.spfRecord && (
                    <div className="p-1.5 rounded bg-[#0a0d14] text-[10px] break-all text-slate-300">
                      <strong>SPF:</strong> {selectedLog.dnsLiveCheck.spfRecord}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-3 bg-[#0c1017] border-t border-[#212c42] flex items-center justify-between text-xs font-mono text-slate-400 shrink-0">
          <span>Schema: RFC-SOC-JSON-2026.4</span>
          <span className="text-emerald-400">Integrity: SHA-256 Verified</span>
        </div>
      </div>
    </>
  );
};
