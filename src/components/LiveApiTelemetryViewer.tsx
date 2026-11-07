import React, { useState } from 'react';
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  Clock,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Terminal,
  Copy,
  Check,
  ShieldCheck,
  Network
} from 'lucide-react';
import { ApiTelemetryRecord } from '../types';

interface LiveApiTelemetryViewerProps {
  telemetry: ApiTelemetryRecord[];
  title?: string;
  subtitle?: string;
}

export const LiveApiTelemetryViewer: React.FC<LiveApiTelemetryViewerProps> = ({
  telemetry,
  title = 'Live Security API Requests & Network Telemetry',
  subtitle = 'Real-time outbound requests made to external threat intelligence providers and DNS registries.'
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!telemetry || telemetry.length === 0) {
    return (
      <div className="bg-[#121722] border border-[#20293a] rounded-lg p-4 text-xs text-[#94a3b8] flex items-center gap-2">
        <Activity className="w-4 h-4 text-[#38bdf8] animate-pulse" />
        No outbound API queries recorded yet. Submit a scan to dispatch live queries to Google DoH, URLhaus, OpenPhish & IP-API.
      </div>
    );
  }

  const toggleExpand = (id: string) => {
    setExpandedId(prev => (prev === id ? null : id));
  };

  const copyCurl = (rec: ApiTelemetryRecord, e: React.MouseEvent) => {
    e.stopPropagation();
    const curl = rec.method === 'GET'
      ? `curl -i -X GET "${rec.endpoint}"`
      : `curl -i -X ${rec.method} "${rec.endpoint}"`;
    navigator.clipboard.writeText(curl);
    setCopiedId(rec.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const maliciousCount = telemetry.filter(t => t.verdict === 'MALICIOUS').length;
  const suspiciousCount = telemetry.filter(t => t.verdict === 'SUSPICIOUS').length;
  const cleanCount = telemetry.filter(t => t.verdict === 'CLEAN').length;
  const avgLatency = Math.round(telemetry.reduce((acc, t) => acc + t.latencyMs, 0) / telemetry.length);

  return (
    <div className="bg-[#111722] border border-[#222c3d] rounded-lg overflow-hidden space-y-0">
      {/* Header bar */}
      <div className="p-4 bg-[#151c2a] border-b border-[#222c3d] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-[#38bdf8]" />
            <h3 className="text-xs font-semibold text-slate-100 uppercase tracking-wider font-mono">
              {title}
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#0284c7]/20 border border-[#0284c7]/40 text-[#38bdf8] flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#38bdf8] animate-ping" />
              {telemetry.length} Real Outbound Queries
            </span>
          </div>
          <p className="text-[11px] text-[#94a3b8] mt-1">{subtitle}</p>
        </div>

        {/* Live metric summary pills */}
        <div className="flex items-center gap-2 flex-wrap">
          {maliciousCount > 0 && (
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-red-950/40 border border-red-800/60 text-red-400 font-medium">
              {maliciousCount} Flagged Malicious
            </span>
          )}
          {suspiciousCount > 0 && (
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-950/40 border border-amber-800/60 text-amber-400">
              {suspiciousCount} Suspicious
            </span>
          )}
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950/40 border border-emerald-800/60 text-emerald-400">
            {cleanCount} Clean
          </span>
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#1a2333] border border-[#2b3950] text-slate-300 flex items-center gap-1">
            <Clock className="w-3 h-3 text-[#94a3b8]" />
            avg {avgLatency}ms
          </span>
        </div>
      </div>

      {/* Query List */}
      <div className="divide-y divide-[#1e2638]">
        {telemetry.map((rec) => {
          const isExpanded = expandedId === rec.id;
          const isMalicious = rec.verdict === 'MALICIOUS';
          const isSuspicious = rec.verdict === 'SUSPICIOUS';
          const isClean = rec.verdict === 'CLEAN';

          const statusColor = rec.status === '200 OK'
            ? 'text-emerald-400 border-emerald-800/60 bg-emerald-950/30'
            : rec.status === '404 Clean'
            ? 'text-slate-300 border-slate-700 bg-slate-900/50'
            : 'text-amber-400 border-amber-800/60 bg-amber-950/30';

          const verdictBadge = isMalicious ? (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-red-900/40 border border-red-700 text-red-300 flex items-center gap-1">
              <AlertOctagon className="w-3 h-3 text-red-400" />
              THREAT HIT
            </span>
          ) : isSuspicious ? (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-amber-900/40 border border-amber-700 text-amber-300 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3 text-amber-400" />
              ANOMALY
            </span>
          ) : isClean ? (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950/40 border border-emerald-800 text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              VERIFIED CLEAN
            </span>
          ) : (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-950/40 border border-blue-800 text-blue-300">
              INFO
            </span>
          );

          return (
            <div
              key={rec.id}
              className={`transition-colors ${
                isExpanded ? 'bg-[#141b27]' : 'hover:bg-[#131924]'
              }`}
            >
              <div
                onClick={() => toggleExpand(rec.id)}
                className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#1e2738] text-[#38bdf8] border border-[#2d3a52]">
                      {rec.method}
                    </span>
                    <span className="text-xs font-semibold text-slate-200">
                      {rec.service}
                    </span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${statusColor}`}>
                      {rec.status}
                    </span>
                    <span className="text-[10px] font-mono text-[#94a3b8] flex items-center gap-1">
                      <Clock className="w-2.5 h-2.5" />
                      {rec.latencyMs}ms
                    </span>
                    {verdictBadge}
                  </div>

                  <div className="text-[11px] font-mono text-slate-300 truncate">
                    <span className="text-[#64748b]">Endpoint:</span>{' '}
                    <span className="text-[#38bdf8]">{rec.endpoint}</span>
                  </div>

                  <p className="text-xs text-slate-300 font-mono">
                    {rec.summary}
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                  <button
                    onClick={(e) => copyCurl(rec, e)}
                    title="Copy cURL command for terminal verification"
                    className="p-1.5 rounded bg-[#1a2333] hover:bg-[#232f45] border border-[#2b3950] text-[#94a3b8] hover:text-slate-200 text-[11px] flex items-center gap-1 transition"
                  >
                    {copiedId === rec.id ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span className="text-[10px] text-emerald-400">cURL Copied</span>
                      </>
                    ) : (
                      <>
                        <Terminal className="w-3 h-3 text-[#38bdf8]" />
                        <span className="text-[10px] hidden md:inline">cURL</span>
                      </>
                    )}
                  </button>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleExpand(rec.id);
                    }}
                    className="p-1.5 rounded bg-[#1a2333] hover:bg-[#232f45] border border-[#2b3950] text-[#94a3b8] hover:text-slate-200 text-[11px] flex items-center gap-1 transition"
                  >
                    <span className="text-[10px]">{isExpanded ? 'Hide Payload' : 'Inspect JSON'}</span>
                    {isExpanded ? (
                      <ChevronUp className="w-3 h-3" />
                    ) : (
                      <ChevronDown className="w-3 h-3" />
                    )}
                  </button>
                </div>
              </div>

              {/* Expanded JSON Inspector */}
              {isExpanded && (
                <div className="px-4 pb-4 pt-1 bg-[#0b0f17] border-t border-[#1b2333] space-y-2">
                  <div className="flex items-center justify-between text-[11px] text-[#94a3b8] pt-2 font-mono">
                    <span>Target Queried: <strong className="text-slate-200">{rec.targetQueried}</strong></span>
                    <span>HTTP Latency: <strong className="text-[#38bdf8]">{rec.latencyMs}ms</strong></span>
                  </div>
                  <div className="relative">
                    <pre className="p-3 rounded bg-[#090d14] border border-[#1e2738] text-[11px] font-mono text-emerald-400/90 overflow-x-auto max-h-60 leading-relaxed">
                      {JSON.stringify(rec.rawResponse || { summary: rec.summary, status: rec.status, target: rec.targetQueried }, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
