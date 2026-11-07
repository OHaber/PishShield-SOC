import React, { useState, useMemo } from 'react';
import {
  Wrench,
  Shield,
  Copy,
  Check,
  Download,
  Terminal,
  Type,
  FileCode,
  Share2,
  CheckSquare,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  Ban,
  Radio,
  FileCheck,
  AlertTriangle
} from 'lucide-react';
import {
  defangUrl,
  defangIp,
  defangEmail,
  defangIndicator,
  generateDefenseQueries,
  generateStixBundle,
  generateMispEvent,
  detectHomoglyphsAndTyposquat
} from '../socTools';
import { PhishingAnalysisResult, Indicator } from '../types';

export const SocToolsTab: React.FC = () => {
  const [activeSubTool, setActiveSubTool] = useState<
    'defanger' | 'homoglyphs' | 'ruleforge' | 'cti' | 'playbook'
  >('defanger');

  // 1. Defanger state
  const [rawText, setRawText] = useState<string>(
    `Hostile incident detected from 194.26.29.112 sending emails from alerts@paypal-account-center.com pointing to http://login.micros0ft-verify.com/token?auth=99281. Secondary C2 host at 45.145.66.19 and payload download at https://dhl-delivery-package-update.xyz/invoice.zip.`
  );
  const [defangMode, setDefangMode] = useState<boolean>(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // 2. Homoglyph Generator state
  const [testDomain, setTestDomain] = useState<string>('paypal.com');

  // 3. Rule Forge state
  const [forgeTargetIp, setForgeTargetIp] = useState<string>('194.26.29.112');
  const [forgeTargetDomain, setForgeTargetDomain] = useState<string>('paypal-account-center.com');
  const [forgeKeyword, setForgeKeyword] = useState<string>('account suspended');
  const [ruleFormat, setRuleFormat] = useState<
    'splunk' | 'sentinel' | 'elastic' | 'iptables' | 'paloAlto' | 'suricata' | 'sigma' | 'yara'
  >('splunk');

  // 4. Playbook state
  const [playbookSteps, setPlaybookSteps] = useState<
    { id: string; phase: string; title: string; desc: string; done: boolean }[]
  >([
    {
      id: 'step-1',
      phase: '1. Identification',
      title: 'Extract & Validate Authentication Headers',
      desc: 'Verify SPF, DKIM, and DMARC alignment. Confirm sender IP routing through email Received hops.',
      done: true
    },
    {
      id: 'step-2',
      phase: '1. Identification',
      title: 'Analyze Payload URLs & Hosted Infrastructure',
      desc: 'Check domain registration date, ASN ownership, and whether it uses bulletproof or VPS hosting.',
      done: true
    },
    {
      id: 'step-3',
      phase: '2. Containment',
      title: 'Block Sender Domain & IP at Mail Perimeter',
      desc: 'Add sender address and relay IP to Secure Email Gateway (SEG) tenant blocklist.',
      done: false
    },
    {
      id: 'step-4',
      phase: '2. Containment',
      title: 'Null-Route Phishing URLs on Web Proxy & DNS Sinkhole',
      desc: 'Add destination host to DNS Firewall / Cloudflare Gateway block policy to prevent user clicks.',
      done: false
    },
    {
      id: 'step-5',
      phase: '3. Eradication',
      title: 'Purge Phishing Lures from Employee Mailboxes',
      desc: 'Run organization-wide search & purge (e.g., Compliance Center / Google Workspace Quarantine).',
      done: false
    },
    {
      id: 'step-6',
      phase: '3. Eradication',
      title: 'Revoke Active Sessions for Clicked Recipients',
      desc: 'If user submitted credentials, invalidate all Azure AD / Okta refresh tokens and enforce password reset.',
      done: false
    },
    {
      id: 'step-7',
      phase: '4. Recovery',
      title: 'Verify Endpoint Integrity with EDR',
      desc: 'Trigger full Falcon / Defender for Endpoint scan on workstations belonging to interacting users.',
      done: false
    },
    {
      id: 'step-8',
      phase: '5. Threat Intel Sharing',
      title: 'Publish IOCs to MISP & STIX Feed',
      desc: 'Share verified phishing domain, URL, and attachment hashes with threat sharing community.',
      done: false
    }
  ]);

  const copySnippet = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadFile = (content: string, filename: string, type: string = 'text/plain') => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  // --- Defanger Logic ---
  const processedDefangText = useMemo(() => {
    if (defangMode) {
      let t = rawText;
      // URLs
      t = t.replace(/https?:\/\/[^\s"'<>]+/gi, (m) => defangUrl(m));
      // IPs
      t = t.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (m) => defangIp(m));
      // Emails
      t = t.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, (m) => defangEmail(m));
      return t;
    } else {
      // Refang
      let t = rawText;
      t = t.replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().replace('hxxp', 'http'));
      t = t.replace(/\[\.\]/g, '.');
      t = t.replace(/\[@\]/g, '@');
      t = t.replace(/\[:\]/g, ':');
      return t;
    }
  }, [rawText, defangMode]);

  // Extracted unique IOCs
  const extractedIocs = useMemo(() => {
    const urls = rawText.match(/https?:\/\/[^\s"'<>]+/gi) || [];
    const ips = rawText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    const emails = rawText.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || [];

    const list: { type: string; raw: string; defanged: string }[] = [];
    new Set(urls).forEach((u) => list.push({ type: 'URL', raw: u, defanged: defangUrl(u) }));
    new Set(ips).forEach((ip) => list.push({ type: 'IP', raw: ip, defanged: defangIp(ip) }));
    new Set(emails).forEach((e) => list.push({ type: 'Email', raw: e, defanged: defangEmail(e) }));
    return list;
  }, [rawText]);

  // --- Homoglyphs & Typosquat Simulator ---
  const homoglyphPermutations = useMemo(() => {
    const clean = testDomain.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0];
    const parts = clean.split('.');
    const sld = parts[0] || 'domain';
    const tld = parts.slice(1).join('.') || 'com';

    return [
      {
        type: 'Cyrillic IDN Homoglyph',
        spoof: sld.replace(/a/g, 'а').replace(/o/g, 'о').replace(/e/g, 'е').replace(/p/g, 'р') + '.' + tld,
        punycode: 'xn--' + sld.slice(0, 3) + '4ve.' + tld,
        risk: 'High',
        vector: 'Renders identically to human eye in address bar'
      },
      {
        type: 'Omission Typosquat',
        spoof: (sld.length > 3 ? sld.slice(0, 2) + sld.slice(3) : sld + 's') + '.' + tld,
        punycode: 'N/A',
        risk: 'Medium',
        vector: 'Fat-finger mistyping from memory'
      },
      {
        type: 'Leet Substitution',
        spoof: sld.replace(/o/g, '0').replace(/l/g, '1').replace(/e/g, '3') + '.' + tld,
        punycode: 'N/A',
        risk: 'High',
        vector: 'Deceptive characters in phishing emails'
      },
      {
        type: 'Subdomain Prefix Spoof',
        spoof: `${clean}.security-authentication-auth.net`,
        punycode: 'N/A',
        risk: 'Critical',
        vector: 'Valid SSL certificate on attacker-controlled root domain'
      },
      {
        type: 'High-Risk TLD Swap',
        spoof: `${sld}.xyz`,
        punycode: 'N/A',
        risk: 'High',
        vector: 'Low-cost registration often used in malware blast campaigns'
      },
      {
        type: 'Hyphenated Lure',
        spoof: `${sld}-account-recovery-portal.com`,
        punycode: 'N/A',
        risk: 'High',
        vector: 'Urgent security lure designed to impersonate official brand'
      }
    ];
  }, [testDomain]);

  // --- Rule Forge Output ---
  const forgedRuleCode = useMemo(() => {
    const ip = forgeTargetIp.trim() || '194.26.29.112';
    const domain = forgeTargetDomain.trim() || 'paypal-account-center.com';
    const kw = forgeKeyword.trim() || 'account suspended';

    switch (ruleFormat) {
      case 'splunk':
        return `# Splunk SPL: Hunt for Hostile Inbound Connections & DNS Lookups
index=firewall OR index=proxy OR index=dns (dest_ip="${ip}" OR query="*${domain}*")
| eval threat_indicator=if(dest_ip=="${ip}", "Malicious IP", "Malicious Domain")
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(user) as affected_users by src_ip, dest_ip, query, threat_indicator
| convert ctime(first_seen) ctime(last_seen)
| sort - count`;

      case 'sentinel':
        return `// Microsoft Sentinel KQL: Detect Network & Process Communication to Threat IOC
let TargetIP = "${ip}";
let TargetDomain = "${domain}";
DeviceNetworkEvents
| where TimeGenerated >= ago(7d)
| where RemoteIP == TargetIP or RemoteUrl has TargetDomain
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessAccountName, InitiatingProcessFileName
| order by TimeGenerated desc`;

      case 'elastic':
        return `# Elastic KQL / EQL Detection Query
sequence with maxspan=1h
  [network where event.type == "start" and destination.ip == "${ip}"]
  [process where event.action in ("start", "fork") and process.name in ("cmd.exe", "powershell.exe", "curl.exe")]`;

      case 'iptables':
        return `# Linux iptables: Immediate Network Perimeter Block
# 1. Drop inbound packets from malicious IP
iptables -I INPUT -s ${ip} -j DROP

# 2. Drop outbound connections attempted by compromised workstations
iptables -I OUTPUT -d ${ip} -j DROP

# 3. Log dropped packets with prefix for SIEM collector
iptables -I INPUT -s ${ip} -m limit --limit 5/min -j LOG --log-prefix "[SOC_THREAT_BLOCK]: "`;

      case 'paloAlto':
        return `# Palo Alto Networks PAN-OS CLI Commands
set address "IOC_HOST_${ip.replace(/\./g, '_')}" ip-netmask ${ip}/32
set address-group "GRP_MALICIOUS_THREAT_INTEL" static "IOC_HOST_${ip.replace(/\./g, '_')}"
set rulebase security rules "DROP_PHISH_INFRASTRUCTURE" action drop source any destination "GRP_MALICIOUS_THREAT_INTEL"`;

      case 'suricata':
        return `# Suricata / Snort IDS Signature
alert tcp any any -> ${ip} any (msg:"PHISHSHIELD MALICIOUS C2/PHISH CONNECTION DETECTED"; flow:to_server,established; threshold:type limit,track by_src,count 1,seconds 60; classtype:trojan-activity; sid:9000101; rev:1;)
alert dns any any -> any 53 (msg:"PHISHSHIELD SUSPICIOUS DNS LOOKUP FOR PHISH DOMAIN"; content:"${domain}"; nocase; classtype:bad-unknown; sid:9000102; rev:1;)`;

      case 'sigma':
        return `title: Network Connection to Phishing Threat Infrastructure
id: cti-${Date.now().toString(36)}
status: production
description: Identifies outbound TCP/HTTP connections to hostile IP ${ip} or domain ${domain}
author: PhishShield SOC Cyber Threat Intelligence
logsource:
    category: network_connection
    product: windows
detection:
    selection_ip:
        DestinationIp: '${ip}'
    selection_domain:
        DestinationHostname|contains: '${domain}'
    condition: selection_ip or selection_domain
falsepositives:
    - Unknown
level: high
tags:
    - attack.initial_access
    - attack.t1566.002`;

      case 'yara':
        return `rule PhishShield_Generated_Detection_${Date.now().toString(36)} {
    meta:
        description = "Automated YARA rule targeting campaign ${domain}"
        author = "PhishShield SOC Engine"
        date = "${new Date().toISOString().split('T')[0]}"
        severity = "HIGH"
    strings:
        $domain = "${domain}" nocase
        $ip = "${ip}" nocase
        $keyword = "${kw}" nocase
    condition:
        $domain or $ip or ($keyword and filesize < 5MB)
}`;

      default:
        return '';
    }
  }, [forgeTargetIp, forgeTargetDomain, forgeKeyword, ruleFormat]);

  // --- CTI Exporter Objects ---
  const sampleStixData = useMemo(() => {
    const dummyResult: PhishingAnalysisResult = {
      id: 9942,
      score: 85,
      threatLevel: 'High',
      highlightKeywords: [forgeKeyword],
      timestamp: new Date().toISOString(),
      indicators: [
        { indicatorType: 'IP', indicatorValue: forgeTargetIp, reputation: 'Malicious', context: 'Command & Control / Landing Page' },
        { indicatorType: 'Domain', indicatorValue: forgeTargetDomain, reputation: 'Malicious', context: 'Credential Harvest Host' },
        { indicatorType: 'URL', indicatorValue: `http://${forgeTargetDomain}/login`, reputation: 'Malicious', context: 'Phishing URI' }
      ],
      rulesTriggered: [
        { rule: 'HOSTILE_IP_HOSTED', score: 40, severity: 'critical', explanation: 'Host IP in bulletproof netblock' }
      ]
    };
    return {
      stix: JSON.stringify(generateStixBundle(dummyResult), null, 2),
      misp: JSON.stringify(generateMispEvent(dummyResult), null, 2)
    };
  }, [forgeTargetIp, forgeTargetDomain]);

  return (
    <div className="space-y-6">
      {/* Tool Navigation Bar */}
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Wrench className="w-4 h-4 text-[#38bdf8]" />
            SOC Defense & Threat Intelligence Toolkit
          </h2>
          <p className="text-xs text-[#94a3b8] mt-1">
            Defang indicators, simulate lookalike homoglyphs, forge firewall & SIEM rules, and export CTI bundles.
          </p>
        </div>

        {/* Sub-tool switcher */}
        <div className="flex flex-wrap items-center gap-1.5 bg-[#0e121a] p-1 rounded-md border border-[#242e40]">
          <button
            onClick={() => setActiveSubTool('defanger')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTool === 'defanger'
                ? 'bg-[#2563eb] text-white'
                : 'text-[#94a3b8] hover:text-white'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>IOC Sanitizer</span>
          </button>

          <button
            onClick={() => setActiveSubTool('homoglyphs')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTool === 'homoglyphs'
                ? 'bg-[#2563eb] text-white'
                : 'text-[#94a3b8] hover:text-white'
            }`}
          >
            <Type className="w-3.5 h-3.5" />
            <span>Homoglyphs & IDN</span>
          </button>

          <button
            onClick={() => setActiveSubTool('ruleforge')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTool === 'ruleforge'
                ? 'bg-[#2563eb] text-white'
                : 'text-[#94a3b8] hover:text-white'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Rule Forge</span>
          </button>

          <button
            onClick={() => setActiveSubTool('cti')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTool === 'cti'
                ? 'bg-[#2563eb] text-white'
                : 'text-[#94a3b8] hover:text-white'
            }`}
          >
            <Share2 className="w-3.5 h-3.5" />
            <span>STIX / MISP</span>
          </button>

          <button
            onClick={() => setActiveSubTool('playbook')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTool === 'playbook'
                ? 'bg-[#2563eb] text-white'
                : 'text-[#94a3b8] hover:text-white'
            }`}
          >
            <CheckSquare className="w-3.5 h-3.5" />
            <span>NIST Playbook</span>
          </button>
        </div>
      </div>

      {/* --- SUB-TOOL 1: IOC DEFANGER & SANITIZER --- */}
      {activeSubTool === 'defanger' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-slate-100 uppercase tracking-wider font-mono">
                    Input Incident Text, Logs or IOCs
                  </h3>
                  <p className="text-[11px] text-[#94a3b8]">
                    Paste raw text to safely neutralize actionable URLs, IP addresses, and email links.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setDefangMode(!defangMode)}
                    className={`px-2.5 py-1 rounded text-xs font-medium border transition cursor-pointer ${
                      defangMode
                        ? 'bg-[#1e3a8a]/40 border-[#3b82f6] text-[#60a5fa]'
                        : 'bg-[#1f2937] border-[#374151] text-[#94a3b8]'
                    }`}
                  >
                    {defangMode ? 'Mode: Defanging (Safe)' : 'Mode: Refanging (Active)'}
                  </button>

                  <button
                    onClick={() => copySnippet(processedDefangText, 'defanged-text')}
                    className="px-2.5 py-1 rounded bg-[#1a2332] hover:bg-[#222e42] border border-[#2d3a50] text-xs text-slate-200 flex items-center gap-1.5 transition cursor-pointer"
                  >
                    {copiedKey === 'defanged-text' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5 text-[#94a3b8]" />}
                    <span>{copiedKey === 'defanged-text' ? 'Copied' : 'Copy All'}</span>
                  </button>
                </div>
              </div>

              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                rows={8}
                placeholder="Paste threat emails, firewall logs, or raw URLs here..."
                className="w-full p-3 rounded-md bg-[#0e121a] border border-[#242e40] text-xs font-mono text-slate-200 focus:outline-none focus:border-[#3b82f6] transition resize-y"
              />

              <div>
                <div className="text-[11px] font-mono text-[#64748b] mb-1.5 flex items-center justify-between">
                  <span>Processed Sanitized Output:</span>
                  <span>{defangMode ? 'Safe for Tickets & Chat' : 'Live Unmasked Format'}</span>
                </div>
                <div className="p-3 rounded-md bg-[#0e121a] border border-[#242e40] font-mono text-xs text-[#38bdf8] whitespace-pre-wrap select-all max-h-48 overflow-y-auto">
                  {processedDefangText}
                </div>
              </div>
            </div>
          </div>

          {/* Extracted IOC Summary */}
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#242e40] pb-2.5">
              <h3 className="text-xs font-semibold text-slate-100 uppercase tracking-wider font-mono">
                Extracted IOCs ({extractedIocs.length})
              </h3>
              <button
                onClick={() => {
                  const formatted = extractedIocs
                    .map((i) => `${i.type.padEnd(6)}: ${i.defanged}`)
                    .join('\n');
                  copySnippet(formatted, 'iocs-list');
                }}
                className="text-[11px] text-[#38bdf8] hover:underline flex items-center gap-1 cursor-pointer"
              >
                {copiedKey === 'iocs-list' ? 'Copied' : 'Copy List'}
              </button>
            </div>

            {extractedIocs.length === 0 ? (
              <p className="text-xs text-[#64748b] italic">No IPs, URLs or emails detected in input.</p>
            ) : (
              <div className="space-y-2 max-h-[360px] overflow-y-auto pr-1">
                {extractedIocs.map((ioc, idx) => (
                  <div key={idx} className="p-2 rounded bg-[#0e121a] border border-[#242e40] text-[11px]">
                    <div className="flex items-center justify-between text-[#64748b] font-mono text-[10px]">
                      <span>{ioc.type}</span>
                      <button
                        onClick={() => copySnippet(ioc.defanged, `ioc-${idx}`)}
                        className="text-[#94a3b8] hover:text-white cursor-pointer"
                      >
                        {copiedKey === `ioc-${idx}` ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <div className="font-mono text-slate-200 mt-1 break-all select-all">
                      {ioc.defanged}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* --- SUB-TOOL 2: HOMOGLYPHS & BRAND SPOOFING LAB --- */}
      {activeSubTool === 'homoglyphs' && (
        <div className="space-y-6">
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-4">
            <div>
              <h3 className="text-xs font-semibold text-slate-100 uppercase tracking-wider font-mono">
                Target Domain Homoglyph & Typosquat Simulator
              </h3>
              <p className="text-[11px] text-[#94a3b8] mt-1">
                Enter your company or brand domain to test potential unicode Cyrillic spoofing, IDN Punycode vectors, and typosquats.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={testDomain}
                onChange={(e) => setTestDomain(e.target.value)}
                placeholder="Enter domain (e.g., paypal.com, microsoft.com)..."
                className="flex-1 px-3 py-2 rounded-md bg-[#0e121a] border border-[#242e40] text-xs font-mono text-slate-100 focus:outline-none focus:border-[#3b82f6]"
              />

              <div className="flex items-center gap-1.5 shrink-0">
                {['paypal.com', 'microsoft.com', 'google.com', 'chase.com'].map((preset) => (
                  <button
                    key={preset}
                    onClick={() => setTestDomain(preset)}
                    className="px-2.5 py-1.5 rounded bg-[#1a2332] hover:bg-[#222e42] border border-[#2d3a50] text-[11px] text-[#94a3b8] hover:text-white transition cursor-pointer"
                  >
                    {preset}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="bg-[#151b26] border border-[#242e40] rounded-lg overflow-hidden">
            <div className="p-4 border-b border-[#242e40] bg-[#111622] flex items-center justify-between">
              <span className="font-semibold text-xs text-slate-200 uppercase tracking-wider font-mono">
                Simulated Attack Permutations for &quot;{testDomain}&quot;
              </span>
              <span className="text-[11px] text-[#64748b]">
                {homoglyphPermutations.length} Variations Generated
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#242e40] text-[11px] text-[#64748b] font-mono bg-[#0e121a]">
                    <th className="py-2.5 px-4">Deception Technique</th>
                    <th className="py-2.5 px-4">Spoofed Domain Presentation</th>
                    <th className="py-2.5 px-4">Punycode / ASCII Wire</th>
                    <th className="py-2.5 px-4">Risk Level</th>
                    <th className="py-2.5 px-4">Threat Vector</th>
                    <th className="py-2.5 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2738]">
                  {homoglyphPermutations.map((item, idx) => (
                    <tr key={idx} className="hover:bg-[#151b26]">
                      <td className="py-3 px-4 font-mono font-medium text-slate-300">{item.type}</td>
                      <td className="py-3 px-4 font-mono text-[#fb7185] font-semibold">{item.spoof}</td>
                      <td className="py-3 px-4 font-mono text-[#94a3b8]">{item.punycode}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase font-semibold ${
                            item.risk === 'Critical'
                              ? 'bg-[#e11d48]/20 text-[#fb7185]'
                              : item.risk === 'High'
                              ? 'bg-[#d97706]/20 text-[#fbbf24]'
                              : 'bg-[#2563eb]/20 text-[#60a5fa]'
                          }`}
                        >
                          {item.risk}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[#94a3b8] text-[11px]">{item.vector}</td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => copySnippet(item.spoof, `homo-${idx}`)}
                          className="px-2 py-1 rounded bg-[#1a2332] hover:bg-[#222e42] border border-[#2d3a50] text-[11px] text-slate-200 transition cursor-pointer"
                        >
                          {copiedKey === `homo-${idx}` ? 'Copied' : 'Copy'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* --- SUB-TOOL 3: RULE FORGE (SIEM & FIREWALL) --- */}
      {activeSubTool === 'ruleforge' && (
        <div className="space-y-6">
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-4">
            <h3 className="text-xs font-semibold text-slate-100 uppercase tracking-wider font-mono">
              Detection & Defense Rule Parameters
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-[11px] font-mono text-[#64748b] block mb-1">Target Host IP:</label>
                <input
                  type="text"
                  value={forgeTargetIp}
                  onChange={(e) => setForgeTargetIp(e.target.value)}
                  className="w-full px-3 py-2 rounded-md bg-[#0e121a] border border-[#242e40] text-xs font-mono text-slate-100 focus:outline-none focus:border-[#3b82f6]"
                />
              </div>

              <div>
                <label className="text-[11px] font-mono text-[#64748b] block mb-1">Target Host Domain:</label>
                <input
                  type="text"
                  value={forgeTargetDomain}
                  onChange={(e) => setForgeTargetDomain(e.target.value)}
                  className="w-full px-3 py-2 rounded-md bg-[#0e121a] border border-[#242e40] text-xs font-mono text-slate-100 focus:outline-none focus:border-[#3b82f6]"
                />
              </div>

              <div>
                <label className="text-[11px] font-mono text-[#64748b] block mb-1">Lure Keyword / Subject:</label>
                <input
                  type="text"
                  value={forgeKeyword}
                  onChange={(e) => setForgeKeyword(e.target.value)}
                  className="w-full px-3 py-2 rounded-md bg-[#0e121a] border border-[#242e40] text-xs font-mono text-slate-100 focus:outline-none focus:border-[#3b82f6]"
                />
              </div>
            </div>

            {/* Target platform selector */}
            <div className="pt-2">
              <div className="text-[11px] font-mono text-[#64748b] mb-2">Target Security Engine / Format:</div>
              <div className="flex flex-wrap gap-1.5">
                {[
                  { id: 'splunk', label: 'Splunk (SPL)' },
                  { id: 'sentinel', label: 'Microsoft Sentinel (KQL)' },
                  { id: 'elastic', label: 'Elasticsearch (EQL/KQL)' },
                  { id: 'iptables', label: 'Linux iptables' },
                  { id: 'paloAlto', label: 'Palo Alto Networks CLI' },
                  { id: 'suricata', label: 'Suricata / Snort' },
                  { id: 'sigma', label: 'Sigma Rule (YAML)' },
                  { id: 'yara', label: 'YARA Signature' }
                ].map((fmt) => (
                  <button
                    key={fmt.id}
                    onClick={() => setRuleFormat(fmt.id as any)}
                    className={`px-3 py-1.5 rounded text-xs font-mono transition cursor-pointer border ${
                      ruleFormat === fmt.id
                        ? 'bg-[#2563eb] border-[#3b82f6] text-white font-medium'
                        : 'bg-[#111622] border-[#242e40] text-[#94a3b8] hover:text-white hover:border-[#334158]'
                    }`}
                  >
                    {fmt.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Generated Code Window */}
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg overflow-hidden">
            <div className="p-3 border-b border-[#242e40] bg-[#111622] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#38bdf8]" />
                <span className="font-mono text-xs text-slate-200 uppercase font-semibold">
                  Generated {ruleFormat.toUpperCase()} Rule
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => copySnippet(forgedRuleCode, 'rule-code')}
                  className="px-2.5 py-1 rounded bg-[#1a2332] hover:bg-[#222e42] border border-[#2d3a50] text-xs text-slate-200 flex items-center gap-1.5 transition cursor-pointer"
                >
                  {copiedKey === 'rule-code' ? <Check className="w-3.5 h-3.5 text-[#4ade80]" /> : <Copy className="w-3.5 h-3.5 text-[#94a3b8]" />}
                  <span>{copiedKey === 'rule-code' ? 'Copied' : 'Copy Query'}</span>
                </button>

                <button
                  onClick={() => downloadFile(forgedRuleCode, `rule-${ruleFormat}-${Date.now()}.txt`)}
                  className="px-2.5 py-1 rounded bg-[#2563eb] hover:bg-[#1d4ed8] text-xs text-white flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download</span>
                </button>
              </div>
            </div>

            <pre className="p-4 bg-[#0a0d14] font-mono text-xs text-[#38bdf8] overflow-x-auto whitespace-pre selection:bg-[#2563eb]/30">
              {forgedRuleCode}
            </pre>
          </div>
        </div>
      )}

      {/* --- SUB-TOOL 4: CTI EXPORTER (STIX 2.1 & MISP) --- */}
      {activeSubTool === 'cti' && (
        <div className="space-y-6">
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-3">
            <h3 className="text-xs font-semibold text-slate-100 uppercase tracking-wider font-mono">
              Cyber Threat Intelligence (CTI) Bundle Exporter
            </h3>
            <p className="text-[11px] text-[#94a3b8]">
              Standardized machine-readable threat packages complying with OASIS STIX 2.1 and MISP JSON schemas. Ready to import directly into OpenCTI, MISP, or commercial TIPs.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* STIX 2.1 */}
            <div className="bg-[#151b26] border border-[#242e40] rounded-lg overflow-hidden flex flex-col">
              <div className="p-3 border-b border-[#242e40] bg-[#111622] flex items-center justify-between">
                <span className="font-mono text-xs font-semibold text-slate-200">
                  OASIS STIX 2.1 Bundle
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => copySnippet(sampleStixData.stix, 'stix-json')}
                    className="px-2 py-1 rounded bg-[#1a2332] hover:bg-[#222e42] border border-[#2d3a50] text-[11px] text-slate-200 transition cursor-pointer"
                  >
                    {copiedKey === 'stix-json' ? 'Copied' : 'Copy'}
                  </button>
                  <button
                    onClick={() => downloadFile(sampleStixData.stix, `stix2.1-bundle-${Date.now()}.json`, 'application/json')}
                    className="px-2 py-1 rounded bg-[#2563eb] text-[11px] text-white transition cursor-pointer"
                  >
                    Download
                  </button>
                </div>
              </div>
              <pre className="p-3 bg-[#0a0d14] font-mono text-[11px] text-[#94a3b8] overflow-y-auto max-h-96 whitespace-pre">
                {sampleStixData.stix}
              </pre>
            </div>

            {/* MISP */}
            <div className="bg-[#151b26] border border-[#242e40] rounded-lg overflow-hidden flex flex-col">
              <div className="p-3 border-b border-[#242e40] bg-[#111622] flex items-center justify-between">
                <span className="font-mono text-xs font-semibold text-slate-200">
                  MISP Threat Sharing Event
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => copySnippet(sampleStixData.misp, 'misp-json')}
                    className="px-2 py-1 rounded bg-[#1a2332] hover:bg-[#222e42] border border-[#2d3a50] text-[11px] text-slate-200 transition cursor-pointer"
                  >
                    {copiedKey === 'misp-json' ? 'Copied' : 'Copy'}
                  </button>
                  <button
                    onClick={() => downloadFile(sampleStixData.misp, `misp-event-${Date.now()}.json`, 'application/json')}
                    className="px-2 py-1 rounded bg-[#2563eb] text-[11px] text-white transition cursor-pointer"
                  >
                    Download
                  </button>
                </div>
              </div>
              <pre className="p-3 bg-[#0a0d14] font-mono text-[11px] text-[#94a3b8] overflow-y-auto max-h-96 whitespace-pre">
                {sampleStixData.misp}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* --- SUB-TOOL 5: NIST INCIDENT RESPONSE PLAYBOOK --- */}
      {activeSubTool === 'playbook' && (
        <div className="space-y-6">
          <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xs font-semibold text-slate-100 uppercase tracking-wider font-mono">
                  NIST SP 800-61 Incident Handling Playbook
                </h3>
                <p className="text-[11px] text-[#94a3b8] mt-1">
                  Step-by-step containment, eradication, and response triage checklist for phishing incidents.
                </p>
              </div>

              <div className="text-xs font-mono text-[#38bdf8] bg-[#0e121a] px-3 py-1.5 rounded border border-[#242e40]">
                {playbookSteps.filter((s) => s.done).length} / {playbookSteps.length} Steps Completed
              </div>
            </div>
          </div>

          <div className="space-y-3">
            {playbookSteps.map((step) => (
              <div
                key={step.id}
                onClick={() => {
                  setPlaybookSteps((prev) =>
                    prev.map((s) => (s.id === step.id ? { ...s, done: !s.done } : s))
                  );
                }}
                className={`p-4 rounded-lg border transition cursor-pointer flex items-start gap-3.5 ${
                  step.done
                    ? 'bg-[#151b26]/70 border-[#1e2738] opacity-80'
                    : 'bg-[#151b26] border-[#242e40] hover:border-[#334158]'
                }`}
              >
                <div className="pt-0.5">
                  <div
                    className={`w-4 h-4 rounded border flex items-center justify-center ${
                      step.done
                        ? 'bg-[#16a34a] border-[#16a34a] text-white'
                        : 'border-[#475569] bg-[#0e121a]'
                    }`}
                  >
                    {step.done && <Check className="w-3 h-3 stroke-3" />}
                  </div>
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1f2937] text-[#94a3b8]">
                      {step.phase}
                    </span>
                    <span className={`text-xs font-semibold ${step.done ? 'line-through text-[#64748b]' : 'text-slate-200'}`}>
                      {step.title}
                    </span>
                  </div>
                  <p className="text-xs text-[#94a3b8] leading-relaxed">
                    {step.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
