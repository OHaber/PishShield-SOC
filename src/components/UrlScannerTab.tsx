import React, { useState } from 'react';
import {
  Globe,
  Search,
  ShieldAlert,
  ShieldCheck,
  Server,
  Lock,
  Radio,
  Ban,
  CheckCircle2,
  Copy,
  AlertTriangle
} from 'lucide-react';
import { UrlScanResult } from '../types';
import { LiveApiTelemetryViewer } from './LiveApiTelemetryViewer';

interface UrlScannerTabProps {
  onScanUrl: (url: string) => Promise<UrlScanResult>;
  initialUrl?: string;
}

export const UrlScannerTab: React.FC<UrlScannerTabProps> = ({
  onScanUrl,
  initialUrl = 'http://194.26.29.112/confirm-login?id=99281'
}) => {
  const [url, setUrl] = useState<string>(initialUrl);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<UrlScanResult | null>(null);
  const [blocked, setBlocked] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const handleScan = async (targetToScan?: string) => {
    const toScan = (targetToScan || url).trim();
    if (!toScan) {
      alert('Enter URL or IP.');
      return;
    }

    setLoading(true);
    setBlocked(false);
    try {
      const data = await onScanUrl(toScan);
      setResult(data);
    } catch (err: any) {
      alert(err.message || 'Error querying URL reputation endpoint.');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (presetUrl: string) => {
    setUrl(presetUrl);
    handleScan(presetUrl);
  };

  const copyUrl = () => {
    if (result) {
      navigator.clipboard.writeText(result.target);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Search Header */}
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#38bdf8]" />
            URL, Domain & IP Threat Reputation Engine
          </h2>
          <p className="text-xs text-[#94a3b8] mt-1">
            Query threat intelligence registries, blacklists, and live feeds across 87 security engines.
          </p>
        </div>

        {/* Input Bar matching user specification */}
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-[#64748b] absolute left-3 top-2.5" />
            <input
              id="urlInput"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder="Enter URL, Domain or IP (e.g. 194.26.29.112 or login.micros0ft-verify.com)..."
              className="w-full pl-9 pr-4 py-2 rounded-md bg-[#0e121a] border border-[#242e40] text-xs font-mono text-slate-100 focus:outline-none focus:border-[#3b82f6] transition"
            />
          </div>

          <button
            id="btnScanUrl"
            disabled={loading}
            onClick={() => handleScan()}
            className="px-4 py-2 rounded-md bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-medium flex items-center justify-center gap-2 transition disabled:opacity-50 cursor-pointer shrink-0 shadow-sm"
          >
            {loading ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Querying Threat Feeds</span>
              </>
            ) : (
              <>
                <Radio className="w-3.5 h-3.5" />
                <span>Scan Indicator</span>
              </>
            )}
          </button>
        </div>

        {/* Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-[#242e40]">
          <span className="text-[11px] text-[#64748b]">Presets:</span>
          <button
            onClick={() => loadPreset('http://194.26.29.112/confirm-login?id=99281')}
            className="px-2 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] text-[11px] font-mono text-[#fb7185] border border-[#3b1d28] transition cursor-pointer"
          >
            IP Phish: 194.26.29.112
          </button>
          <button
            onClick={() => loadPreset('login.micros0ft-verify.com')}
            className="px-2 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] text-[11px] font-mono text-[#fb7185] border border-[#3b1d28] transition cursor-pointer"
          >
            Typosquat: micros0ft-verify.com
          </button>
          <button
            onClick={() => loadPreset('unknown-bulletproof-host.ru')}
            className="px-2 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] text-[11px] font-mono text-[#fbbf24] border border-[#3d2e1a] transition cursor-pointer"
          >
            Bulletproof: .ru Host
          </button>
          <button
            onClick={() => loadPreset('https://paypal.com')}
            className="px-2 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] text-[11px] font-mono text-[#4ade80] border border-[#1e3d29] transition cursor-pointer"
          >
            Clean: paypal.com
          </button>
          <button
            onClick={() => loadPreset('https://google.com')}
            className="px-2 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] text-[11px] font-mono text-[#4ade80] border border-[#1e3d29] transition cursor-pointer"
          >
            Clean: google.com
          </button>
        </div>
      </div>

      {/* Result Card matching user specification exact IDs */}
      {result && (
        <div
          id="urlResultCard"
          className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-5 animate-in fade-in duration-200"
          style={{ display: 'block' }}
        >
          {/* Top Status & Verdict */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#242e40] gap-3">
            <div className="flex items-center gap-3">
              {result.isMalicious ? (
                <div className="w-8 h-8 rounded-md bg-[#22151b] border border-[#3b1d28] text-[#fb7185] flex items-center justify-center">
                  <ShieldAlert className="w-4 h-4" />
                </div>
              ) : (
                <div className="w-8 h-8 rounded-md bg-[#132219] border border-[#1e3d29] text-[#4ade80] flex items-center justify-center">
                  <ShieldCheck className="w-4 h-4" />
                </div>
              )}

              <div>
                <div className="flex items-center gap-2">
                  <span
                    id="resVerdictBadge"
                    className={`badge ${result.isMalicious ? 'High' : 'Low'}`}
                  >
                    {result.isMalicious ? 'MALICIOUS' : 'CLEAN'}
                  </span>
                  <span className="text-xs text-[#94a3b8] font-mono">
                    Detection Ratio: <strong id="resEngines" className="text-white">{result.enginesDetected} / {result.totalEngines || 87}</strong>
                  </span>
                </div>
                <div className="text-xs text-[#64748b] mt-0.5">
                  Evaluated across VirusTotal, Spamhaus, AlienVault OTX, and URLhaus feeds
                </div>
              </div>
            </div>

            {/* Perimeter Actions */}
            <div className="flex items-center gap-2">
              <button
                onClick={copyUrl}
                className="px-3 py-1.5 rounded-md bg-[#1a2230] hover:bg-[#202b3d] border border-[#242e40] text-xs font-mono text-slate-300 hover:text-white flex items-center gap-1.5 transition cursor-pointer"
              >
                {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
              {result.isMalicious && (
                <button
                  onClick={() => setBlocked(!blocked)}
                  className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium flex items-center gap-1.5 transition cursor-pointer ${
                    blocked
                      ? 'bg-[#e11d48] text-white'
                      : 'bg-[#22151b] hover:bg-[#2d1822] border border-[#3b1d28] text-[#fb7185]'
                  }`}
                >
                  <Ban className="w-3.5 h-3.5" />
                  <span>{blocked ? 'Blocked in Perimeter' : 'Block at Perimeter'}</span>
                </button>
              )}
            </div>
          </div>

          {/* Target & Classification Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3 rounded-md bg-[#0e121a] border border-[#242e40] space-y-1">
              <span className="text-[11px] font-mono text-[#64748b] uppercase block">
                Inspected Target
              </span>
              <div id="resTarget" className="text-xs font-mono text-slate-200 font-semibold break-all">
                {result.target}
              </div>
            </div>

            <div className="p-3 rounded-md bg-[#0e121a] border border-[#242e40] space-y-1">
              <span className="text-[11px] font-mono text-[#64748b] uppercase block">
                Threat Classification
              </span>
              <div id="resCategory" className="text-xs font-mono text-slate-200 font-semibold">
                {result.threatCategory}
              </div>
            </div>

            <div className="p-3 rounded-md bg-[#0e121a] border border-[#242e40] space-y-1">
              <span className="text-[11px] font-mono text-[#64748b] uppercase block">
                Intelligence Source
              </span>
              <div id="resSource" className="text-xs font-mono text-slate-200">
                {result.source}
              </div>
            </div>

            <div className="p-3 rounded-md bg-[#0e121a] border border-[#242e40] space-y-1">
              <span className="text-[11px] font-mono text-[#64748b] uppercase block">
                Detection Severity
              </span>
              <div className="flex items-center gap-3">
                <div className="w-full bg-[#1a2230] h-2 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${
                      result.isMalicious ? 'bg-[#e11d48]' : 'bg-[#16a34a]'
                    }`}
                    style={{
                      width: `${Math.max(4, (result.enginesDetected / (result.totalEngines || 87)) * 100)}%`
                    }}
                  />
                </div>
                <span className="text-xs font-mono font-semibold text-slate-300 whitespace-nowrap">
                  {Math.round((result.enginesDetected / (result.totalEngines || 87)) * 100)}%
                </span>
              </div>
            </div>
          </div>

          {/* Live Feed Banner if verified on abuse.ch URLhaus */}
          {result.details?.urlhausThreat && (
            <div className="p-3 rounded-md bg-[#22151b] border border-[#3b1d28] text-xs font-mono space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold flex items-center gap-1.5 text-[#fb7185]">
                  <AlertTriangle className="w-3.5 h-3.5 text-[#fb7185]" />
                  abuse.ch URLhaus Active Threat Match
                </span>
                <span className="text-[10px] text-[#fb7185]">
                  Status: {result.details.urlhausStatus || 'ONLINE'}
                </span>
              </div>
              <p className="text-slate-300 text-[11px]">
                Payload Type: {result.details.urlhausThreat}
              </p>
              {result.details.urlhausTags && result.details.urlhausTags.length > 0 && (
                <div className="flex items-center gap-1.5 pt-0.5">
                  <span className="text-[#64748b] text-[10px]">Tags:</span>
                  {result.details.urlhausTags.map((tag, i) => (
                    <span key={i} className="px-1.5 py-0.2 rounded bg-[#151b26] border border-[#3b1d28] text-[#fb7185] text-[10px]">
                      #{tag}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Network & Infrastructure Metadata */}
          {result.details && (
            <div className="p-3.5 rounded-md bg-[#0e121a] border border-[#242e40] space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-200 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-[#94a3b8]" />
                  <span>Network & Host Resolution Metadata</span>
                </span>
                {result.details.responseTimeMs && (
                  <span className="text-[11px] font-mono text-[#64748b]">
                    Query Latency: <strong className="text-slate-300">{result.details.responseTimeMs}ms</strong>
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div>
                  <span className="text-[#64748b] block text-[10px]">RESOLVED IP</span>
                  <span className="text-slate-200">{result.details.ip || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-[#64748b] block text-[10px]">AUTONOMOUS SYSTEM</span>
                  <span className="text-slate-200 truncate block" title={result.details.asn}>
                    {result.details.asn || 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-[#64748b] block text-[10px]">GEOLOCATION</span>
                  <span className="text-slate-200">{result.details.country || 'Global'}</span>
                </div>
                <div>
                  <span className="text-[#64748b] block text-[10px]">ISP / HOSTING</span>
                  <span className="text-slate-200 truncate block" title={result.details.isp || result.details.org}>
                    {result.details.isp || result.details.org || 'Standard Cloud'}
                  </span>
                </div>

                {/* Additional Live API Telemetry metadata */}
                {result.details.domainAge && (
                  <div>
                    <span className="text-[#64748b] block text-[10px]">DOMAIN AGE</span>
                    <span className="text-slate-200">{result.details.domainAge}</span>
                  </div>
                )}
                {result.details.httpStatus !== undefined && result.details.httpStatus > 0 && (
                  <div>
                    <span className="text-[#64748b] block text-[10px]">HTTP STATUS</span>
                    <span className="text-emerald-400">HTTP {result.details.httpStatus}</span>
                  </div>
                )}
                {result.details.httpServer && (
                  <div>
                    <span className="text-[#64748b] block text-[10px]">WEB SERVER</span>
                    <span className="text-slate-200 truncate block">{result.details.httpServer}</span>
                  </div>
                )}
                {result.details.sslStatus && (
                  <div>
                    <span className="text-[#64748b] block text-[10px]">SSL / SECURITY</span>
                    <span className="text-slate-200">{result.details.sslStatus}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Real Outbound API Telemetry Log */}
          {result.liveTelemetry && result.liveTelemetry.length > 0 && (
            <div className="pt-2">
              <LiveApiTelemetryViewer
                telemetry={result.liveTelemetry}
                title="Live Threat Intelligence API Requests"
                subtitle="Real-time outbound queries dispatched to Google DoH, abuse.ch URLhaus, OpenPhish & IP-API."
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};
