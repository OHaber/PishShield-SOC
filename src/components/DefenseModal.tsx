import React, { useState } from 'react';
import { Terminal, Copy, Check, Download, X, Shield, FileCode, Share2, Layers } from 'lucide-react';
import { PhishingAnalysisResult } from '../types';
import {
  generateDefenseQueries,
  generateStixBundle,
  generateMispEvent,
  defangIndicator
} from '../socTools';

interface DefenseModalProps {
  isOpen: boolean;
  onClose: () => void;
  result: PhishingAnalysisResult;
}

export const DefenseModal: React.FC<DefenseModalProps> = ({
  isOpen,
  onClose,
  result
}) => {
  const [activeTab, setActiveTab] = useState<'firewall' | 'siem' | 'yara' | 'stix' | 'misp' | 'defanged'>('firewall');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!isOpen) return null;

  const queries = generateDefenseQueries(result);
  const stixBundle = JSON.stringify(generateStixBundle(result), null, 2);
  const mispEvent = JSON.stringify(generateMispEvent(result), null, 2);

  const defangedText = (result.indicators || [])
    .map((ioc) => `${ioc.indicatorType.padEnd(8)}: ${defangIndicator(ioc.indicatorValue, ioc.indicatorType)}`)
    .join('\n');

  const copySnippet = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadText = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg max-w-3xl w-full flex flex-col max-h-[85vh] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-[#242e40] bg-[#111622] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-md bg-[#1d2636] border border-[#2d3a50] text-[#38bdf8]">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>Defensive Rules & SIEM Query Generator</span>
                <span className="text-[11px] font-mono text-[#94a3b8]">#SCAN-{result.id}</span>
              </h3>
              <p className="text-[11px] text-[#64748b]">
                Export perimeter blocklists, detection queries, and threat intelligence feeds
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-md text-[#94a3b8] hover:text-white transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-[#242e40] bg-[#0e121a] px-3 text-xs overflow-x-auto no-scrollbar">
          <button
            onClick={() => setActiveTab('firewall')}
            className={`py-2.5 px-3 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
              activeTab === 'firewall'
                ? 'border-[#38bdf8] text-white bg-[#151b26]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            Firewall Rules (iptables / Palo Alto)
          </button>
          <button
            onClick={() => setActiveTab('siem')}
            className={`py-2.5 px-3 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
              activeTab === 'siem'
                ? 'border-[#38bdf8] text-white bg-[#151b26]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            SIEM Queries (Splunk / Sentinel)
          </button>
          <button
            onClick={() => setActiveTab('yara')}
            className={`py-2.5 px-3 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
              activeTab === 'yara'
                ? 'border-[#38bdf8] text-white bg-[#151b26]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            YARA Signature (.yar)
          </button>
          <button
            onClick={() => setActiveTab('defanged')}
            className={`py-2.5 px-3 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
              activeTab === 'defanged'
                ? 'border-[#38bdf8] text-white bg-[#151b26]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            Defanged IOCs
          </button>
          <button
            onClick={() => setActiveTab('stix')}
            className={`py-2.5 px-3 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
              activeTab === 'stix'
                ? 'border-[#38bdf8] text-white bg-[#151b26]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            STIX 2.1
          </button>
          <button
            onClick={() => setActiveTab('misp')}
            className={`py-2.5 px-3 border-b-2 font-medium transition cursor-pointer whitespace-nowrap ${
              activeTab === 'misp'
                ? 'border-[#38bdf8] text-white bg-[#151b26]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            MISP Event
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4">
          {activeTab === 'firewall' && (
            <div className="space-y-4 text-xs font-mono">
              <div className="p-3.5 rounded-md bg-[#0e121a] border border-[#242e40] space-y-2">
                <div className="flex items-center justify-between text-[#94a3b8]">
                  <span className="font-semibold text-slate-200">Linux iptables Drop Policy</span>
                  <button
                    onClick={() => copySnippet(queries.iptables, 'iptables')}
                    className="flex items-center gap-1 text-[11px] text-[#38bdf8] hover:underline cursor-pointer"
                  >
                    {copiedKey === 'iptables' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'iptables' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap select-all">
                  {queries.iptables}
                </pre>
              </div>

              <div className="p-3.5 rounded-md bg-[#0e121a] border border-[#242e40] space-y-2">
                <div className="flex items-center justify-between text-[#94a3b8]">
                  <span className="font-semibold text-slate-200">Palo Alto Networks CLI Command</span>
                  <button
                    onClick={() => copySnippet(queries.paloAlto, 'paloAlto')}
                    className="flex items-center gap-1 text-[11px] text-[#38bdf8] hover:underline cursor-pointer"
                  >
                    {copiedKey === 'paloAlto' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'paloAlto' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap select-all">
                  {queries.paloAlto}
                </pre>
              </div>
            </div>
          )}

          {activeTab === 'siem' && (
            <div className="space-y-4 text-xs font-mono">
              <div className="p-3.5 rounded-md bg-[#0e121a] border border-[#242e40] space-y-2">
                <div className="flex items-center justify-between text-[#94a3b8]">
                  <span className="font-semibold text-slate-200">Splunk SPL Correlation Query</span>
                  <button
                    onClick={() => copySnippet(queries.splunk, 'splunk')}
                    className="flex items-center gap-1 text-[11px] text-[#38bdf8] hover:underline cursor-pointer"
                  >
                    {copiedKey === 'splunk' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'splunk' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap select-all">
                  {queries.splunk}
                </pre>
              </div>

              <div className="p-3.5 rounded-md bg-[#0e121a] border border-[#242e40] space-y-2">
                <div className="flex items-center justify-between text-[#94a3b8]">
                  <span className="font-semibold text-slate-200">Microsoft Sentinel KQL Hunting Rule</span>
                  <button
                    onClick={() => copySnippet(queries.sentinel, 'sentinel')}
                    className="flex items-center gap-1 text-[11px] text-[#38bdf8] hover:underline cursor-pointer"
                  >
                    {copiedKey === 'sentinel' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'sentinel' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap select-all">
                  {queries.sentinel}
                </pre>
              </div>

              <div className="p-3.5 rounded-md bg-[#0e121a] border border-[#242e40] space-y-2">
                <div className="flex items-center justify-between text-[#94a3b8]">
                  <span className="font-semibold text-slate-200">Elasticsearch EQL Filter</span>
                  <button
                    onClick={() => copySnippet(queries.elastic, 'elastic')}
                    className="flex items-center gap-1 text-[11px] text-[#38bdf8] hover:underline cursor-pointer"
                  >
                    {copiedKey === 'elastic' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'elastic' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap select-all">
                  {queries.elastic}
                </pre>
              </div>
            </div>
          )}

          {activeTab === 'yara' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[#94a3b8]">Auto-Generated YARA Rule for Endpoint Detection</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => copySnippet(queries.yara, 'yara')}
                    className="px-2.5 py-1 rounded bg-[#1a2230] text-slate-200 hover:text-white flex items-center gap-1 cursor-pointer"
                  >
                    {copiedKey === 'yara' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'yara' ? 'Copied' : 'Copy Rule'}</span>
                  </button>
                  <button
                    onClick={() => downloadText(queries.yara, `rule_phish_${result.id}.yar`)}
                    className="px-2.5 py-1 rounded bg-[#1a2230] text-slate-200 hover:text-white flex items-center gap-1 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download .yar</span>
                  </button>
                </div>
              </div>
              <pre className="p-4 rounded-md bg-[#0e121a] border border-[#242e40] text-[#38bdf8] text-[11px] leading-relaxed whitespace-pre-wrap select-all">
                {queries.yara}
              </pre>
            </div>
          )}

          {activeTab === 'defanged' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[#94a3b8]">Defanged for Safe Ticket Sharing (Prevents Accidental Clicks)</span>
                <button
                  onClick={() => copySnippet(defangedText, 'defanged')}
                  className="px-2.5 py-1 rounded bg-[#1a2230] text-slate-200 hover:text-white flex items-center gap-1 cursor-pointer"
                >
                  {copiedKey === 'defanged' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'defanged' ? 'Copied' : 'Copy Defanged'}</span>
                </button>
              </div>
              <pre className="p-4 rounded-md bg-[#0e121a] border border-[#242e40] text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap select-all">
                {defangedText || '// No extracted IOCs to defang.'}
              </pre>
            </div>
          )}

          {activeTab === 'stix' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[#94a3b8]">OASIS STIX 2.1 Threat Intel Bundle</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => copySnippet(stixBundle, 'stix')}
                    className="px-2.5 py-1 rounded bg-[#1a2230] text-slate-200 hover:text-white flex items-center gap-1 cursor-pointer"
                  >
                    {copiedKey === 'stix' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'stix' ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={() => downloadText(stixBundle, `stix_incident_${result.id}.json`)}
                    className="px-2.5 py-1 rounded bg-[#1a2230] text-slate-200 hover:text-white flex items-center gap-1 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download JSON</span>
                  </button>
                </div>
              </div>
              <pre className="p-4 rounded-md bg-[#0e121a] border border-[#242e40] text-[#4ade80] text-[11px] leading-relaxed whitespace-pre-wrap select-all max-h-[360px] overflow-y-auto">
                {stixBundle}
              </pre>
            </div>
          )}

          {activeTab === 'misp' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[#94a3b8]">MISP (Malware Information Sharing Platform) Event</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => copySnippet(mispEvent, 'misp')}
                    className="px-2.5 py-1 rounded bg-[#1a2230] text-slate-200 hover:text-white flex items-center gap-1 cursor-pointer"
                  >
                    {copiedKey === 'misp' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'misp' ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={() => downloadText(mispEvent, `misp_event_${result.id}.json`)}
                    className="px-2.5 py-1 rounded bg-[#1a2230] text-slate-200 hover:text-white flex items-center gap-1 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download JSON</span>
                  </button>
                </div>
              </div>
              <pre className="p-4 rounded-md bg-[#0e121a] border border-[#242e40] text-[#fbbf24] text-[11px] leading-relaxed whitespace-pre-wrap select-all max-h-[360px] overflow-y-auto">
                {mispEvent}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#111622] border-t border-[#242e40] flex items-center justify-between text-xs text-[#64748b]">
          <span>Security Automation Format: OASIS / MITRE Compliant</span>
          <button
            onClick={onClose}
            className="px-3 py-1 rounded-md bg-[#1a2230] text-slate-300 hover:text-white cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
