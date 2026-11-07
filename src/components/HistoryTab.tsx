import React, { useState, useMemo } from 'react';
import {
  History,
  RefreshCw,
  Search,
  Filter,
  FileJson,
  Download,
  Trash2,
  FileText
} from 'lucide-react';
import { ScanLog } from '../types';
import { ReportModal } from './ReportModal';

interface HistoryTabProps {
  logs: ScanLog[];
  loading: boolean;
  filterRisk: string;
  onFilterChange: (risk: string) => void;
  onRefresh: () => void;
  onInspectJson: (log: ScanLog) => void;
  onClearHistory?: () => void;
}

export const HistoryTab: React.FC<HistoryTabProps> = ({
  logs,
  loading,
  filterRisk,
  onFilterChange,
  onRefresh,
  onInspectJson,
  onClearHistory
}) => {
  const [search, setSearch] = useState<string>('');
  const [selectedReportLog, setSelectedReportLog] = useState<ScanLog | null>(null);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchesRisk =
        filterRisk === 'all' || !filterRisk
          ? true
          : log.threatLevel.toLowerCase() === filterRisk.toLowerCase();

      const matchesSearch =
        search.trim() === ''
          ? true
          : log.id.toString().includes(search) ||
            log.threatLevel.toLowerCase().includes(search.toLowerCase()) ||
            log.indicators?.some((i) => i.indicatorValue.toLowerCase().includes(search.toLowerCase())) ||
            log.highlightKeywords?.some((k) => k.toLowerCase().includes(search.toLowerCase()));

      return matchesRisk && matchesSearch;
    });
  }, [logs, filterRisk, search]);

  const exportAllLogs = () => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-scan-audit-history-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Controls */}
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <History className="w-4 h-4 text-[#38bdf8]" />
            Forensic Scan Audit History
          </h2>
          <p className="text-xs text-[#94a3b8] mt-1">
            Historical incident records of parsed email payloads, IOC extractions, and threat scores.
          </p>
        </div>

        {/* Filter Controls matching user specification IDs */}
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          {/* Risk Filter Select matching user ID: historyFilterRisk */}
          <div className="flex items-center gap-2 bg-[#0e121a] border border-[#242e40] rounded-md px-2.5 py-1.5 text-xs">
            <Filter className="w-3.5 h-3.5 text-[#64748b]" />
            <select
              id="historyFilterRisk"
              value={filterRisk}
              onChange={(e) => onFilterChange(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer text-xs"
            >
              <option value="all">All Risk Levels</option>
              <option value="High">High Risk Only</option>
              <option value="Medium">Medium Risk Only</option>
              <option value="Low">Low Risk Only</option>
            </select>
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#64748b] absolute left-2.5 top-2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by ID or IOC..."
              className="pl-8 pr-3 py-1.5 rounded-md bg-[#0e121a] border border-[#242e40] text-xs font-mono text-slate-200 focus:outline-none focus:border-[#3b82f6] w-36 sm:w-44"
            />
          </div>

          {/* Refresh Button matching user ID: btnRefreshHistory */}
          <button
            id="btnRefreshHistory"
            onClick={onRefresh}
            title="Refresh History Feed"
            className="p-1.5 rounded-md bg-[#1a2230] hover:bg-[#202b3d] text-[#94a3b8] hover:text-white border border-[#242e40] transition cursor-pointer flex items-center gap-1.5 text-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">Refresh</span>
          </button>

          {/* Export JSON */}
          <button
            onClick={exportAllLogs}
            title="Export All History as JSON"
            className="p-1.5 rounded-md bg-[#1a2230] hover:bg-[#202b3d] text-[#94a3b8] hover:text-white border border-[#242e40] transition cursor-pointer flex items-center gap-1.5 text-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Export</span>
          </button>

          {onClearHistory && logs.length > 0 && (
            <button
              onClick={() => {
                if (confirm('Clear audit history logs?')) {
                  onClearHistory();
                }
              }}
              title="Clear History"
              className="p-1.5 rounded-md bg-[#22151b] hover:bg-[#2d1822] border border-[#3b1d28] text-[#fb7185] transition cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* History Table matching user specification exact ID: #historyTable tbody */}
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4 overflow-hidden">
        <div className="overflow-x-auto">
          <table id="historyTable" className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-[#242e40] text-[#64748b]">
                <th className="pb-3 font-medium">Scan ID</th>
                <th className="pb-3 font-medium">Timestamp</th>
                <th className="pb-3 font-medium">Severity</th>
                <th className="pb-3 font-medium">Score</th>
                <th className="pb-3 font-medium text-right">Audit</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#242e40]">
              {loading ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-[#64748b] italic">
                    <span className="inline-block w-3.5 h-3.5 border-2 border-[#38bdf8] border-t-transparent rounded-full animate-spin mr-2" />
                    Querying audit records...
                  </td>
                </tr>
              ) : filteredLogs.length > 0 ? (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#1a2230] transition">
                    <td className="py-3 font-semibold text-slate-200">
                      #{log.id}
                    </td>
                    <td className="py-3 text-[#94a3b8]">
                      {new Date(log.scanDate || log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3">
                      <span className={`badge ${log.threatLevel}`}>
                        {log.threatLevel}
                      </span>
                    </td>
                    <td className="py-3 font-semibold text-slate-300 tabular-nums">
                      {log.score} / 100
                    </td>
                    <td className="py-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => setSelectedReportLog(log)}
                          className="px-2 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] hover:text-white border border-[#263347] text-slate-300 font-mono text-xs transition cursor-pointer inline-flex items-center gap-1"
                          title="Generate Investigation Report"
                        >
                          <FileText className="w-3.5 h-3.5 text-[#38bdf8]" />
                          <span>Report</span>
                        </button>

                        {/* Button matching user specification: Inspect JSON */}
                        <button
                          onClick={() => onInspectJson(log)}
                          className="btn btn-secondary btn-sm px-2.5 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] hover:text-white border border-[#263347] text-slate-300 font-mono text-xs transition cursor-pointer inline-flex items-center gap-1.5"
                        >
                          <FileJson className="w-3.5 h-3.5 text-[#38bdf8]" />
                          <span>Inspect JSON</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-[#64748b] italic">
                    No scan records matching the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Report Modal */}
      {selectedReportLog && (
        <ReportModal
          isOpen={!!selectedReportLog}
          onClose={() => setSelectedReportLog(null)}
          result={selectedReportLog}
        />
      )}
    </div>
  );
};
