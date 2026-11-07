import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Send,
  FileCode,
  AlertTriangle,
  CheckCircle,
  Copy,
  ExternalLink,
  Sparkles,
  ListFilter,
  Route,
  Type,
  Paperclip,
  CheckSquare,
  Shield,
  FileCheck,
  FileText,
  Network
} from 'lucide-react';
import { PhishingAnalysisResult } from '../types';
import { SAMPLE_EMAILS } from '../threatEngine';
import { DefenseModal } from './DefenseModal';
import { ReportModal } from './ReportModal';
import { LiveApiTelemetryViewer } from './LiveApiTelemetryViewer';
import {
  parseReceivedHops,
  detectHomoglyphsAndTyposquat,
  extractMimeAttachments,
  generateIncidentPlaybook,
  defangIndicator,
  PlaybookStep
} from '../socTools';

interface AnalyzerTabProps {
  onAnalyze: (content: string) => Promise<PhishingAnalysisResult>;
  onInspectUrl: (target: string) => void;
  lastAnalysis: PhishingAnalysisResult | null;
}

export const AnalyzerTab: React.FC<AnalyzerTabProps> = ({
  onAnalyze,
  onInspectUrl,
  lastAnalysis
}) => {
  const [content, setContent] = useState<string>(SAMPLE_EMAILS.paypalPhish);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<PhishingAnalysisResult | null>(lastAnalysis);
  const [activeSubTab, setActiveSubTab] = useState<
    'telemetry' | 'highlight' | 'headers' | 'rules' | 'dns' | 'route' | 'homoglyphs' | 'attachments' | 'playbook' | 'ai'
  >('telemetry');
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [defangActive, setDefangActive] = useState<boolean>(false);
  const [showDefenseModal, setShowDefenseModal] = useState<boolean>(false);
  const [showReportModal, setShowReportModal] = useState<boolean>(false);
  const [playbookChecklist, setPlaybookChecklist] = useState<Record<string, boolean>>({});

  const handleRunAnalysis = async () => {
    if (!content.trim()) {
      alert('Please enter email content or headers.');
      return;
    }

    setLoading(true);
    try {
      const data = await onAnalyze(content);
      setResult(data);
    } catch (err: any) {
      alert(err.message || 'Analysis failed. Check backend connection.');
    } finally {
      setLoading(false);
    }
  };

  const loadSample = (sampleText: string) => {
    setContent(sampleText);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIoc(id);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  const togglePlaybookStep = (stepId: string) => {
    setPlaybookChecklist((prev) => ({
      ...prev,
      [stepId]: !prev[stepId]
    }));
  };

  // Parsed route hops
  const hops = useMemo(() => parseReceivedHops(content), [content]);

  // Detected homoglyphs & typosquatting
  const homoglyphs = useMemo(() => detectHomoglyphsAndTyposquat(content), [content]);

  // MIME attachments
  const attachments = useMemo(() => extractMimeAttachments(content), [content]);

  // Incident playbook
  const playbookSteps = useMemo(() => {
    if (!result) return [];
    return generateIncidentPlaybook(result);
  }, [result]);

  // Render highlighted text with HTML safe replacement matching user snippet
  const renderHighlightedContent = () => {
    if (!result) return <p className="text-[#64748b] italic text-xs">No scan executed yet.</p>;

    const text = result.rawContent || content;
    const escaped = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    let highlighted = escaped;
    if (result.highlightKeywords && result.highlightKeywords.length > 0) {
      result.highlightKeywords.forEach((kw) => {
        const safeKw = kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`(${safeKw})`, 'gi');
        highlighted = highlighted.replace(regex, `<span class="highlight-danger">$1</span>`);
      });
    }

    highlighted = highlighted.replace(
      /(http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s<"]*)/gi,
      `<span class="highlight-danger font-mono font-bold">$1 [IP TARGET]</span>`
    );

    return (
      <div
        id="highlightOutput"
        className="font-mono text-xs text-slate-300 leading-relaxed whitespace-pre-wrap select-text"
        dangerouslySetInnerHTML={{ __html: highlighted }}
      />
    );
  };

  const score = result ? result.score : 0;
  const offset = 251.3 - (251.3 * score) / 100;
  const dialColor = score >= 70 ? '#e11d48' : score >= 35 ? '#d97706' : '#16a34a';
  const threatLevel = result ? result.threatLevel : 'Low';

  return (
    <div className="space-y-6">
      {/* Top Banner / Sample Selectors */}
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#38bdf8]" />
            Email Header & Payload Forensic Triage
          </h2>
          <p className="text-xs text-[#94a3b8] mt-0.5">
            Inspect raw MIME headers, SPF/DKIM authenticity, hop-by-hop delivery route, and homoglyphs.
          </p>
        </div>

        {/* Sample selectors matching user specification */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-[#64748b]">Load Sample:</span>
          <button
            id="btnLoadPhishSample"
            onClick={() => loadSample(SAMPLE_EMAILS.paypalPhish)}
            className="px-2.5 py-1.5 rounded-md bg-[#22151b] hover:bg-[#2d1822] border border-[#3b1d28] text-xs font-mono text-[#fb7185] transition cursor-pointer"
          >
            PayPal Phish
          </button>
          <button
            onClick={() => loadSample(SAMPLE_EMAILS.m365Phish)}
            className="px-2.5 py-1.5 rounded-md bg-[#221c13] hover:bg-[#2e2417] border border-[#3d2e1a] text-xs font-mono text-[#fbbf24] transition cursor-pointer"
          >
            M365 Lure
          </button>
          <button
            onClick={() => loadSample(SAMPLE_EMAILS.becWireFraud)}
            className="px-2.5 py-1.5 rounded-md bg-[#221c13] hover:bg-[#2e2417] border border-[#3d2e1a] text-xs font-mono text-[#fbbf24] transition cursor-pointer"
          >
            CEO BEC
          </button>
          <button
            onClick={() => loadSample(SAMPLE_EMAILS.dhlPayload)}
            className="px-2.5 py-1.5 rounded-md bg-[#22151b] hover:bg-[#2d1822] border border-[#3b1d28] text-xs font-mono text-[#fb7185] transition cursor-pointer"
          >
            DHL Payload
          </button>
          <button
            onClick={() => loadSample(SAMPLE_EMAILS.homoglyphBank)}
            className="px-2.5 py-1.5 rounded-md bg-[#22151b] hover:bg-[#2d1822] border border-[#3b1d28] text-xs font-mono text-[#fb7185] transition cursor-pointer"
          >
            Cyrillic Spoof
          </button>
          <button
            onClick={() => loadSample(SAMPLE_EMAILS.quishingMfa)}
            className="px-2.5 py-1.5 rounded-md bg-[#221c13] hover:bg-[#2e2417] border border-[#3d2e1a] text-xs font-mono text-[#fbbf24] transition cursor-pointer"
          >
            QR Quishing
          </button>
          <button
            onClick={() => loadSample(SAMPLE_EMAILS.cleanCorporateEmail)}
            className="px-2.5 py-1.5 rounded-md bg-[#132219] hover:bg-[#1a2e22] border border-[#1e3d29] text-xs font-mono text-[#4ade80] transition cursor-pointer"
          >
            Clean Corp
          </button>
        </div>
      </div>

      {/* Main 2-Column Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Email Input */}
        <div className="lg:col-span-6 space-y-4">
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4 flex flex-col h-full">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#242e40]">
              <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
                <FileCode className="w-4 h-4 text-[#94a3b8]" />
                <span>Raw Message & RFC 5322 Headers</span>
              </div>
              <span className="text-[11px] text-[#64748b] font-mono">Plaintext Format</span>
            </div>

            <textarea
              id="emailRawInput"
              rows={16}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste raw email content including headers (From, Return-Path, Authentication-Results, Received, Subject)..."
              className="w-full flex-1 p-3.5 rounded-md bg-[#0e121a] border border-[#242e40] text-xs font-mono text-slate-200 leading-relaxed focus:outline-none focus:border-[#3b82f6] transition resize-y min-h-[340px]"
            />

            <div className="flex items-center justify-between pt-4 mt-2">
              <span className="text-xs text-[#64748b]">
                {content.length} characters · {content.split('\n').length} lines
              </span>
              <button
                id="btnAnalyzeEmail"
                disabled={loading}
                onClick={handleRunAnalysis}
                className="px-4 py-2 rounded-md bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-medium flex items-center gap-2 transition disabled:opacity-50 cursor-pointer shadow-sm"
              >
                {loading ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Analyzing Indicators</span>
                  </>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>Run Phishing Inspection</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Output & Verdict */}
        <div className="lg:col-span-6 space-y-4">
          {/* Gauge & Verdict Banner */}
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between gap-4">
              {/* Dial Gauge */}
              <div className="flex items-center gap-4">
                <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      fill="transparent"
                      stroke="#1a2230"
                      strokeWidth="7"
                    />
                    <circle
                      id="dialProgress"
                      cx="50"
                      cy="50"
                      r="40"
                      fill="transparent"
                      stroke={dialColor}
                      strokeWidth="7"
                      strokeDasharray="251.3"
                      strokeDashoffset={offset}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                    <span id="dialScoreText" className="text-xl font-bold font-mono text-white tabular-nums">
                      {score}
                    </span>
                    <span className="text-[9px] text-[#64748b] font-mono">
                      / 100
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-xs text-[#94a3b8]">Threat Risk Score</div>
                  <div className="text-sm font-semibold text-slate-100 mt-0.5">
                    {score >= 70 ? 'Critical Threat Risk' : score >= 35 ? 'Elevated Suspicion' : 'Low Threat / Clean'}
                  </div>
                  <div className="text-xs text-[#64748b] mt-1">
                    {result ? `${result.rulesTriggered?.length || 0} heuristic rules triggered` : 'Ready for analysis'}
                  </div>
                </div>
              </div>

              {/* Status Badge & Defense Trigger */}
              <div className="flex flex-col items-end gap-2">
                <span className={`badge ${threatLevel} text-xs`}>
                  {threatLevel}
                </span>

                {result && (
                  <div className="flex items-center gap-1.5 flex-wrap justify-end">
                    <button
                      onClick={() => setShowReportModal(true)}
                      className="px-2.5 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] border border-[#2d3a50] text-slate-200 text-[11px] font-mono flex items-center gap-1.5 cursor-pointer transition"
                    >
                      <FileText className="w-3.5 h-3.5 text-[#38bdf8]" />
                      <span>Incident Report</span>
                    </button>

                    <button
                      onClick={() => setShowDefenseModal(true)}
                      className="px-2.5 py-1 rounded bg-[#1a2230] hover:bg-[#202b3d] border border-[#2d3a50] text-[#38bdf8] text-[11px] font-mono flex items-center gap-1.5 cursor-pointer transition"
                    >
                      <Shield className="w-3.5 h-3.5" />
                      <span>Defense Rules & SIEM</span>
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Verdict Banner matching user specification */}
            <div
              id="verdictBanner"
              className={`verdict-banner ${threatLevel}`}
            >
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>
                VERDICT: {threatLevel.toUpperCase()} RISK ({score}/100)
              </span>
            </div>
          </div>

          {/* Detailed Forensic Subtabs */}
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg overflow-hidden">
            <div className="flex border-b border-[#242e40] bg-[#111622] px-2 text-xs overflow-x-auto no-scrollbar">
              <button
                onClick={() => setActiveSubTab('telemetry')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
                  activeSubTab === 'telemetry'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                <Network className="w-3 h-3 text-[#38bdf8]" />
                <span>Live API Traffic</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#0284c7]/20 text-[#38bdf8] border border-[#0284c7]/30">
                  {result?.liveTelemetry?.length || 0}
                </span>
              </button>

              <button
                onClick={() => setActiveSubTab('highlight')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                  activeSubTab === 'highlight'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                Highlighted Text
                {result && result.highlightKeywords.length > 0 && (
                  <span className="ml-1 text-[10px] text-[#fb7185] font-mono">
                    ({result.highlightKeywords.length})
                  </span>
                )}
              </button>

              <button
                onClick={() => setActiveSubTab('rules')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                  activeSubTab === 'rules'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                Rules Triggered
                {result && (result.rulesTriggered?.length || 0) > 0 && (
                  <span className="ml-1 text-[10px] text-[#fbbf24] font-mono">
                    ({result.rulesTriggered?.length})
                  </span>
                )}
              </button>

              <button
                onClick={() => setActiveSubTab('headers')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                  activeSubTab === 'headers'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                MIME Headers
              </button>

              <button
                onClick={() => setActiveSubTab('dns')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                  activeSubTab === 'dns'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                Live DNS Auth
              </button>

              <button
                onClick={() => setActiveSubTab('route')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                  activeSubTab === 'route'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                <Route className="w-3 h-3 inline mr-1 text-[#38bdf8]" />
                Hop Route ({hops.length})
              </button>

              <button
                onClick={() => setActiveSubTab('homoglyphs')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                  activeSubTab === 'homoglyphs'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                <Type className="w-3 h-3 inline mr-1 text-[#fbbf24]" />
                Homoglyphs ({homoglyphs.length})
              </button>

              <button
                onClick={() => setActiveSubTab('attachments')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                  activeSubTab === 'attachments'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                <Paperclip className="w-3 h-3 inline mr-1 text-[#a855f7]" />
                Attachments ({attachments.length})
              </button>

              <button
                onClick={() => setActiveSubTab('playbook')}
                className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                  activeSubTab === 'playbook'
                    ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                    : 'border-transparent text-[#94a3b8] hover:text-white'
                }`}
              >
                <CheckSquare className="w-3 h-3 inline mr-1 text-[#4ade80]" />
                SOC Playbook
              </button>

              {result?.aiAnalysis && (
                <button
                  onClick={() => setActiveSubTab('ai')}
                  className={`py-2 px-2.5 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
                    activeSubTab === 'ai'
                      ? 'border-[#38bdf8] text-white bg-[#1a2230]'
                      : 'border-transparent text-[#94a3b8] hover:text-white'
                  }`}
                >
                  <Sparkles className="w-3 h-3 inline mr-1 text-[#a855f7]" />
                  AI Forensics
                </button>
              )}
            </div>

            <div className="p-4 max-h-[460px] overflow-y-auto">
              {activeSubTab === 'telemetry' && (
                <LiveApiTelemetryViewer
                  telemetry={result?.liveTelemetry || []}
                  title="Live Security API Requests & Threat Telemetry"
                  subtitle="Real-time outbound requests made to Google DoH, abuse.ch URLhaus, OpenPhish & IP-API."
                />
              )}

              {activeSubTab === 'highlight' && renderHighlightedContent()}

              {activeSubTab === 'rules' && (
                <div className="space-y-2">
                  {result?.rulesTriggered && result.rulesTriggered.length > 0 ? (
                    result.rulesTriggered.map((rule, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-md bg-[#0e121a] border border-[#242e40] flex items-start justify-between gap-3 text-xs"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-slate-200">
                              {rule.rule}
                            </span>
                            <span className="text-[10px] font-mono text-[#fbbf24]">
                              +{rule.score} pts
                            </span>
                          </div>
                          <p className="text-[11px] text-[#94a3b8] mt-1">{rule.explanation}</p>
                        </div>
                        <span className={`badge ${rule.severity === 'critical' ? 'High' : 'Medium'} text-[10px] shrink-0`}>
                          {rule.severity}
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-[#64748b] italic">No security heuristic violations triggered.</p>
                  )}
                </div>
              )}

              {activeSubTab === 'headers' && (
                <div className="space-y-1.5 font-mono text-xs">
                  {result?.headers && Object.keys(result.headers).length > 0 ? (
                    Object.entries(result.headers).map(([k, v]) => (
                      <div key={k} className="p-2 rounded bg-[#0e121a] border border-[#242e40]">
                        <span className="text-[#38bdf8] font-semibold uppercase">{k}: </span>
                        <span className="text-slate-300 break-all">{v}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-[#64748b] italic">No RFC headers identified.</p>
                  )}
                </div>
              )}

              {activeSubTab === 'dns' && (
                <div className="space-y-3 font-mono text-xs">
                  {result?.dnsLiveCheck ? (
                    <>
                      <div className="p-3 rounded-md bg-[#0e121a] border border-[#242e40] text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-200">
                            Authoritative DNS: {result.dnsLiveCheck.domain}
                          </span>
                          <span className={`badge ${result.dnsLiveCheck.dnsStatus === 'verified' ? 'Low' : 'High'}`}>
                            {result.dnsLiveCheck.dnsStatus}
                          </span>
                        </div>
                        <p className="text-[11px] text-[#94a3b8]">{result.dnsLiveCheck.summary}</p>
                      </div>

                      <div className="space-y-2">
                        <div className="p-2 rounded bg-[#0e121a] border border-[#242e40]">
                          <span className="text-[#38bdf8] font-semibold block text-[11px] mb-0.5">SPF Record</span>
                          <code className="text-slate-300 text-[11px] break-all block">
                            {result.dnsLiveCheck.spfRecord || 'No v=spf1 record published'}
                          </code>
                        </div>

                        <div className="p-2 rounded bg-[#0e121a] border border-[#242e40]">
                          <span className="text-[#38bdf8] font-semibold block text-[11px] mb-0.5">DMARC Policy</span>
                          <code className="text-slate-300 text-[11px] break-all block">
                            {result.dnsLiveCheck.dmarcRecord || 'No _dmarc record published (Vulnerable to spoofing)'}
                          </code>
                        </div>
                      </div>
                    </>
                  ) : (
                    <p className="text-xs text-[#64748b] italic">
                      Execute email analysis to inspect live authoritative SPF/DMARC records.
                    </p>
                  )}
                </div>
              )}

              {/* Hop Route Delivery Tracer */}
              {activeSubTab === 'route' && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="text-[11px] text-[#94a3b8] flex items-center justify-between pb-1 border-b border-[#242e40]">
                    <span>Forward Delivery Chain (Origin to Destination MX)</span>
                    <span>{hops.length} Mail Transfer Hops</span>
                  </div>
                  <div className="space-y-2">
                    {hops.map((hop) => (
                      <div
                        key={hop.hopNumber}
                        className={`p-2.5 rounded-md border ${
                          hop.isSuspicious
                            ? 'bg-[#22151b] border-[#3b1d28]'
                            : 'bg-[#0e121a] border-[#242e40]'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-bold text-slate-200">
                            Hop #{hop.hopNumber}: {hop.fromServer}
                          </span>
                          {hop.isSuspicious && (
                            <span className="badge High text-[10px]">Suspicious Node</span>
                          )}
                        </div>
                        <div className="text-[11px] text-[#94a3b8] space-y-0.5">
                          <div>Received by: <span className="text-slate-300">{hop.byServer}</span></div>
                          {hop.ip && <div>Node IP: <code className="text-[#38bdf8]">{hop.ip}</code></div>}
                          <div>Transit Protocol: <span className="text-slate-400">{hop.withProtocol}</span></div>
                          <div className="text-[10px] text-[#64748b] italic">{hop.notes}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Homoglyph & Typosquatting Analyzer */}
              {activeSubTab === 'homoglyphs' && (
                <div className="space-y-3 font-mono text-xs">
                  {homoglyphs.length > 0 ? (
                    homoglyphs.map((h, i) => (
                      <div key={i} className="p-3 rounded-md bg-[#221c13] border border-[#3d2e1a] space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[#fbbf24]">{h.suspicionType}</span>
                          <span className="badge Medium text-[10px]">{h.targetBrand ? `Lure: ${h.targetBrand}` : 'Anomalous'}</span>
                        </div>
                        <div className="text-slate-200 text-xs">
                          Target: <code className="text-white bg-[#0e121a] px-1.5 py-0.5 rounded">{h.originalString}</code>
                        </div>
                        <p className="text-[11px] text-[#94a3b8]">{h.explanation}</p>
                      </div>
                    ))
                  ) : (
                    <div className="p-4 text-center text-[#64748b] italic">
                      No deceptive Unicode homoglyphs or brand typosquatting patterns detected in domain names.
                    </div>
                  )}
                </div>
              )}

              {/* Attachments & Smuggling Inspector */}
              {activeSubTab === 'attachments' && (
                <div className="space-y-3 font-mono text-xs">
                  {attachments.length > 0 ? (
                    attachments.map((att, i) => (
                      <div
                        key={i}
                        className={`p-3 rounded-md border ${
                          att.isExecutableOrScript || att.isSmugglingLure
                            ? 'bg-[#22151b] border-[#3b1d28]'
                            : 'bg-[#0e121a] border-[#242e40]'
                        } space-y-1.5`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-200 flex items-center gap-1.5">
                            <Paperclip className="w-3.5 h-3.5 text-[#38bdf8]" />
                            {att.filename}
                          </span>
                          <span className={`badge ${att.isExecutableOrScript || att.isSmugglingLure ? 'High' : 'Low'} text-[10px]`}>
                            {att.isExecutableOrScript ? 'Executable' : att.isSmugglingLure ? 'HTML Smuggling' : 'Clean'}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-[11px] text-[#94a3b8]">
                          <div>MIME: <span className="text-slate-300">{att.contentType}</span></div>
                          <div>Size: <span className="text-slate-300">{(att.sizeBytes / 1024).toFixed(1)} KB</span></div>
                        </div>
                        <div className="text-[10px] text-[#64748b] break-all">
                          SHA-256: <code className="text-slate-300">{att.sha256Hash}</code>
                        </div>
                        {att.suspicionReason && (
                          <div className="text-[11px] text-[#fb7185] pt-0.5">
                            {att.suspicionReason}
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="p-4 text-center text-[#64748b] italic">
                      No file attachments identified in email body.
                    </div>
                  )}
                </div>
              )}

              {/* SOC Incident Playbook */}
              {activeSubTab === 'playbook' && (
                <div className="space-y-3 text-xs">
                  <div className="flex items-center justify-between pb-1 border-b border-[#242e40]">
                    <span className="font-semibold text-slate-200">Incident Remediation Checklist</span>
                    <span className="text-[11px] font-mono text-[#94a3b8]">
                      {Object.values(playbookChecklist).filter(Boolean).length} / {playbookSteps.length} Complete
                    </span>
                  </div>

                  <div className="space-y-2">
                    {playbookSteps.map((step) => {
                      const isDone = playbookChecklist[step.id] || false;
                      return (
                        <div
                          key={step.id}
                          className={`p-3 rounded-md border transition ${
                            isDone
                              ? 'bg-[#132219] border-[#1e3d29] opacity-75'
                              : 'bg-[#0e121a] border-[#242e40]'
                          }`}
                        >
                          <div className="flex items-start gap-2.5">
                            <input
                              type="checkbox"
                              checked={isDone}
                              onChange={() => togglePlaybookStep(step.id)}
                              className="mt-0.5 rounded border-[#242e40] text-[#2563eb] focus:ring-0 cursor-pointer"
                            />
                            <div className="flex-1 space-y-1">
                              <div className="flex items-center justify-between">
                                <span className={`font-semibold ${isDone ? 'line-through text-[#4ade80]' : 'text-slate-200'}`}>
                                  {step.title}
                                </span>
                                <span className="text-[10px] font-mono text-[#64748b] uppercase">
                                  {step.category}
                                </span>
                              </div>
                              <p className="text-[11px] text-[#94a3b8]">{step.description}</p>
                              {step.commandSnippet && (
                                <div className="mt-1 flex items-center justify-between p-2 rounded bg-[#151b26] border border-[#242e40] font-mono text-[11px]">
                                  <code className="text-[#38bdf8] truncate select-all">{step.commandSnippet}</code>
                                  <button
                                    onClick={() => copyToClipboard(step.commandSnippet!, step.id)}
                                    className="p-1 text-[#94a3b8] hover:text-white shrink-0 ml-2 cursor-pointer"
                                  >
                                    {copiedIoc === step.id ? <CheckCircle className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                                  </button>
                                </div>
                              )}
                              {step.externalLink && (
                                <a
                                  href={step.externalLink}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 text-[11px] text-[#38bdf8] hover:underline mt-1"
                                >
                                  <span>Submit to URLhaus Clearinghouse</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {activeSubTab === 'ai' && result?.aiAnalysis && (
                <div className="space-y-3 text-xs">
                  <div className="p-3 rounded-md bg-[#0e121a] border border-[#242e40] text-slate-200">
                    <div className="font-semibold text-slate-100 mb-1">Incident Summary</div>
                    <p className="text-[#94a3b8] leading-relaxed text-[11px]">{result.aiAnalysis.summary}</p>
                  </div>

                  <div>
                    <span className="text-slate-300 font-semibold block mb-1">MITRE ATT&CK Mapping</span>
                    <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                      {result.aiAnalysis.techniques?.map((t, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-[#1d2636] text-slate-300 border border-[#2d3a50]">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-300 font-semibold block mb-1">Mitigation Recommendations</span>
                    <ul className="list-disc list-inside space-y-1 text-[#94a3b8] text-[11px]">
                      {result.aiAnalysis.recommendations?.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* IOCs Table matching user specification: #iocsTable tbody */}
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#242e40]">
              <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
                <ListFilter className="w-4 h-4 text-[#94a3b8]" />
                <span>Extracted Indicators of Compromise</span>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setDefangActive(!defangActive)}
                  className={`text-[11px] font-mono px-2 py-0.5 rounded border transition cursor-pointer ${
                    defangActive
                      ? 'bg-[#1d2636] text-[#38bdf8] border-[#38bdf8]/40'
                      : 'bg-transparent text-[#94a3b8] border-[#242e40] hover:text-white'
                  }`}
                >
                  {defangActive ? 'Defanged Active (Safe)' : 'Defang IOCs'}
                </button>
                <span className="text-[11px] text-[#64748b] font-mono">
                  {result?.indicators?.length || 0} Indicators
                </span>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table id="iocsTable" className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-[#242e40] text-[#64748b]">
                    <th className="pb-2 font-medium">Type</th>
                    <th className="pb-2 font-medium">Indicator Value</th>
                    <th className="pb-2 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#242e40]">
                  {result?.indicators && result.indicators.length > 0 ? (
                    result.indicators.map((ioc, idx) => {
                      const displayVal = defangActive
                        ? defangIndicator(ioc.indicatorValue, ioc.indicatorType)
                        : ioc.indicatorValue;
                      return (
                        <tr key={idx} className="hover:bg-[#1a2230] transition">
                          <td className="py-2.5">
                            <strong className="text-[#38bdf8] font-semibold">{ioc.indicatorType}</strong>
                          </td>
                          <td className="py-2.5">
                            <code className="text-slate-200 bg-[#0e121a] px-2 py-1 rounded border border-[#242e40] break-all">
                              {displayVal}
                            </code>
                          </td>
                          <td className="py-2.5 text-right whitespace-nowrap">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                onClick={() => copyToClipboard(displayVal, `ioc-${idx}`)}
                                title="Copy IOC"
                                className="p-1 rounded bg-[#1a2230] hover:text-white text-[#94a3b8] transition cursor-pointer"
                              >
                                {copiedIoc === `ioc-${idx}` ? (
                                  <CheckCircle className="w-3.5 h-3.5 text-[#4ade80]" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                              {(ioc.indicatorType === 'URL' || ioc.indicatorType === 'IP' || ioc.indicatorType === 'Domain') && (
                                <button
                                  onClick={() => onInspectUrl(ioc.indicatorValue)}
                                  title="Inspect in URL Reputation Scanner"
                                  className="p-1 rounded bg-[#1a2230] hover:bg-[#253246] border border-[#263347] text-[#38bdf8] transition cursor-pointer"
                                >
                                  <ExternalLink className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={3} className="py-4 text-center text-[#64748b] italic">
                        No IOCs recorded. Execute an inspection to parse network targets.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Defense Modal */}
      {result && (
        <>
          <DefenseModal
            isOpen={showDefenseModal}
            onClose={() => setShowDefenseModal(false)}
            result={result}
          />
          <ReportModal
            isOpen={showReportModal}
            onClose={() => setShowReportModal(false)}
            result={result}
          />
        </>
      )}
    </div>
  );
};
