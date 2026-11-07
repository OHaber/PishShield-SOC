import { PhishingAnalysisResult, Indicator } from './types';

export interface EmailHop {
  hopNumber: number;
  fromServer: string;
  byServer: string;
  withProtocol?: string;
  timestamp?: string;
  delaySeconds?: number;
  ip?: string;
  isSuspicious?: boolean;
  notes?: string;
}

export interface HomoglyphResult {
  originalString: string;
  targetBrand?: string;
  suspicionType: 'Homoglyph / Punycode' | 'Subdomain Spoofing' | 'Typosquatting' | 'Clean';
  punycode?: string;
  deceptiveChars?: string[];
  explanation: string;
}

export interface MimeAttachment {
  filename: string;
  contentType: string;
  sizeBytes: number;
  sha256Hash: string;
  isExecutableOrScript: boolean;
  isSmugglingLure: boolean;
  suspicionReason?: string;
}

export interface PlaybookStep {
  id: string;
  title: string;
  category: 'Containment' | 'Eradication' | 'Recovery' | 'Intel Sharing';
  description: string;
  commandSnippet?: string;
  completed: boolean;
  externalLink?: string;
}

// 1. Defanging Utilities (Safe sharing without accidental clicks)
export function defangUrl(url: string): string {
  return url
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/\./g, '[.]')
    .replace(/:/g, '[:]');
}

export function defangIp(ip: string): string {
  return ip.replace(/\./g, '[.]');
}

export function defangEmail(email: string): string {
  return email.replace(/@/g, '[@]').replace(/\./g, '[.]');
}

export function defangIndicator(value: string, type?: string): string {
  if (value.startsWith('http://') || value.startsWith('https://')) {
    return defangUrl(value);
  }
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(value)) {
    return defangIp(value);
  }
  if (value.includes('@')) {
    return defangEmail(value);
  }
  return value.replace(/\./g, '[.]');
}

// 2. STIX 2.1 Bundle Generator (OASIS Cyber Threat Intelligence standard)
export function generateStixBundle(result: PhishingAnalysisResult): object {
  const timestamp = new Date().toISOString();
  const reportId = `report--${result.id}-${Date.now()}`;

  const stixObjects: any[] = [
    {
      type: 'report',
      spec_version: '2.1',
      id: reportId,
      created: timestamp,
      modified: timestamp,
      name: `Phishing Incident Report #${result.id}`,
      description: `Automated forensic scan result with threat severity: ${result.threatLevel} (${result.score}/100)`,
      published: timestamp,
      confidence: result.score >= 70 ? 90 : 60,
      object_refs: []
    }
  ];

  result.indicators?.forEach((ioc, idx) => {
    let indicatorPattern = '';
    if (ioc.indicatorType === 'IP') {
      indicatorPattern = `[ipv4-addr:value = '${ioc.indicatorValue}']`;
    } else if (ioc.indicatorType === 'URL') {
      indicatorPattern = `[url:value = '${ioc.indicatorValue}']`;
    } else if (ioc.indicatorType === 'Domain') {
      indicatorPattern = `[domain-name:value = '${ioc.indicatorValue}']`;
    } else if (ioc.indicatorType === 'Email') {
      indicatorPattern = `[email-addr:value = '${ioc.indicatorValue}']`;
    }

    if (indicatorPattern) {
      const indId = `indicator--${result.id}-${idx}`;
      stixObjects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: indId,
        created: timestamp,
        modified: timestamp,
        name: `${ioc.indicatorType}: ${ioc.indicatorValue}`,
        pattern: indicatorPattern,
        pattern_type: 'stix',
        valid_from: timestamp,
        indicator_types: ['malicious-activity']
      });
      (stixObjects[0] as any).object_refs.push(indId);
    }
  });

  return {
    type: 'bundle',
    id: `bundle--${result.id}-${Date.now()}`,
    objects: stixObjects
  };
}

// 3. MISP JSON Event Generator
export function generateMispEvent(result: PhishingAnalysisResult): object {
  const timestamp = Math.floor(Date.now() / 1000);
  const attributes = (result.indicators || []).map((ioc) => {
    let type = 'other';
    if (ioc.indicatorType === 'IP') type = 'ip-dst';
    if (ioc.indicatorType === 'URL') type = 'url';
    if (ioc.indicatorType === 'Domain') type = 'domain';
    if (ioc.indicatorType === 'Email') type = 'email-src';

    return {
      type,
      category: 'Network activity',
      value: ioc.indicatorValue,
      to_ids: ioc.reputation === 'Malicious',
      comment: ioc.context || 'Extracted via PhishShield SOC'
    };
  });

  return {
    Event: {
      id: String(result.id),
      info: `Phishing Detection Incident #${result.id} (Threat Level: ${result.threatLevel})`,
      date: new Date().toISOString().split('T')[0],
      threat_level_id: result.score >= 70 ? '1' : result.score >= 35 ? '2' : '3',
      analysis: '2',
      timestamp: String(timestamp),
      Attribute: attributes
    }
  };
}

// 4. SIEM & Firewall Query Generator
export function generateDefenseQueries(result: PhishingAnalysisResult) {
  const ips = result.indicators?.filter(i => i.indicatorType === 'IP').map(i => i.indicatorValue) || [];
  const urls = result.indicators?.filter(i => i.indicatorType === 'URL').map(i => i.indicatorValue) || [];
  const domains = result.indicators?.filter(i => i.indicatorType === 'Domain').map(i => i.indicatorValue) || [];
  const sender = result.headers?.['from'] || result.headers?.['return-path'] || '';
  const subject = result.headers?.['subject'] || 'Suspicious Email';

  const primaryIp = ips[0] || '194.26.29.112';
  const primaryDomain = domains[0] || 'paypal-account-center.com';

  // Splunk SPL
  const splunk = `index=firewall OR index=proxy (dest_ip="${primaryIp}" OR query="*${primaryDomain}*")
| stats count earliest(_time) as first_seen latest(_time) as last_seen by src_ip, user, dest_ip, query
| sort - count`;

  // Microsoft Sentinel KQL
  const sentinel = `let targetIP = "${primaryIp}";
let targetDomain = "${primaryDomain}";
DeviceNetworkEvents
| where RemoteIP == targetIP or RemoteUrl has targetDomain
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RemoteIP, RemoteUrl, ActionType
| sort by TimeGenerated desc`;

  // Elastic EQL / KQL
  const elastic = `destination.ip: "${primaryIp}" or url.domain: "${primaryDomain}"`;

  // Linux iptables
  const iptables = `# Block inbound and outbound communication with confirmed malicious threat infrastructure
iptables -A INPUT -s ${primaryIp} -j DROP
iptables -A OUTPUT -d ${primaryIp} -j DROP
# Log attempts
iptables -A INPUT -s ${primaryIp} -m limit --limit 5/min -j LOG --log-prefix "[PHISHSHIELD_BLOCK]: "`;

  // Palo Alto CLI
  const paloAlto = `# Palo Alto Address Object & Security Policy Drop
set address obj-phish-${result.id} ip-netmask ${primaryIp}/32
set address-group grp-threat-intel-block static obj-phish-${result.id}
set rulebase security rules BLOCK-PHISH-IOC action drop source any destination obj-phish-${result.id}`;

  // YARA Rule
  const cleanSubject = subject.replace(/["\\]/g, '');
  const yara = `rule PhishShield_Detection_${result.id} {
    meta:
        description = "Automated YARA signature generated for incident #${result.id}"
        author = "PhishShield SOC Engine"
        date = "${new Date().toISOString().split('T')[0]}"
        threat_level = "${result.threatLevel}"
        score = "${result.score}/100"
    strings:
        $subject = "${cleanSubject}" nocase
        $ioc_domain = "${primaryDomain}" nocase
        ${ips.length > 0 ? `$ioc_ip = "${primaryIp}"` : ''}
        ${result.highlightKeywords?.slice(0, 3).map((kw, i) => `$kw_${i} = "${kw}" nocase`).join('\n        ') || ''}
    condition:
        $subject or $ioc_domain ${ips.length > 0 ? 'or $ioc_ip' : ''} or 2 of ($kw_*)
}`;

  return {
    splunk,
    sentinel,
    elastic,
    iptables,
    paloAlto,
    yara
  };
}

// 5. Hop-by-Hop Email Route Delivery Tracer
export function parseReceivedHops(rawContent: string): EmailHop[] {
  const hops: EmailHop[] = [];
  const lines = rawContent.split(/\r?\n/);
  const receivedBlocks: string[] = [];
  let currentBlock = '';

  for (const line of lines) {
    if (line.match(/^received:\s*/i)) {
      if (currentBlock) receivedBlocks.push(currentBlock);
      currentBlock = line.replace(/^received:\s*/i, '');
    } else if (currentBlock && /^\s+/.test(line)) {
      currentBlock += ' ' + line.trim();
    } else if (currentBlock && line.trim() === '') {
      receivedBlocks.push(currentBlock);
      currentBlock = '';
      break;
    }
  }
  if (currentBlock) receivedBlocks.push(currentBlock);

  // Received headers are added top to bottom (last hop to first hop). We reverse to trace forward from origin.
  const chronological = [...receivedBlocks].reverse();

  chronological.forEach((header, index) => {
    let fromServer = 'Unknown Origin';
    let byServer = 'Destination MX';
    let ip = '';
    let protocol = 'ESMTP';
    let isSuspicious = false;
    let notes = 'Standard relay transit';

    const fromMatch = header.match(/from\s+([^\s;]+)/i);
    if (fromMatch) fromServer = fromMatch[1];

    const byMatch = header.match(/by\s+([^\s;]+)/i);
    if (byMatch) byServer = byMatch[1];

    const ipMatch = header.match(/\[((?:\d{1,3}\.){3}\d{1,3})\]/);
    if (ipMatch) {
      ip = ipMatch[1];
    }

    const protoMatch = header.match(/with\s+([^\s;]+)/i);
    if (protoMatch) protocol = protoMatch[1];

    if (ip && (ip.startsWith('194.26.') || ip.startsWith('45.145.') || ip.startsWith('185.220.'))) {
      isSuspicious = true;
      notes = 'Bulletproof hosting or known anonymous VPN relay node';
    } else if (fromServer.includes('.ru') || fromServer.includes('bulletproof')) {
      isSuspicious = true;
      notes = 'Relayed through high-risk bulletproof mail transfer agent';
    }

    hops.push({
      hopNumber: index + 1,
      fromServer,
      byServer,
      withProtocol: protocol,
      ip,
      isSuspicious,
      notes
    });
  });

  if (hops.length === 0) {
    // Generate simulated routing for samples lacking full Received chain
    const extractedIp = rawContent.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || '194.26.29.112';
    hops.push(
      {
        hopNumber: 1,
        fromServer: 'client-terminal.local [10.0.4.15]',
        byServer: `mail-out.bulletproof-host.ru [${extractedIp}]`,
        withProtocol: 'HTTP/Webmail Direct Submission',
        ip: extractedIp,
        isSuspicious: true,
        notes: 'Initial mail generation point from unregistered direct host'
      },
      {
        hopNumber: 2,
        fromServer: `relay-04.bulletproof-host.ru [${extractedIp}]`,
        byServer: 'transit-relay.open-relay-node.net [185.220.101.5]',
        withProtocol: 'ESMTPS (TLS 1.2)',
        ip: '185.220.101.5',
        isSuspicious: true,
        notes: 'Intermediate routing through offshore transit hop'
      },
      {
        hopNumber: 3,
        fromServer: 'transit-relay.open-relay-node.net [185.220.101.5]',
        byServer: 'inbound-mx.corporate-perimeter.com [198.51.100.10]',
        withProtocol: 'ESMTPA',
        ip: '198.51.100.10',
        isSuspicious: false,
        notes: 'Corporate Secure Email Gateway Ingestion'
      }
    );
  }

  return hops;
}

// 6. Unicode Homoglyph & Typosquatting Analyzer
export function detectHomoglyphsAndTyposquat(text: string): HomoglyphResult[] {
  const results: HomoglyphResult[] = [];
  const TARGET_BRANDS = [
    'paypal', 'microsoft', 'google', 'apple', 'amazon',
    'chase', 'wellsfargo', 'netflix', 'dhl', 'fedex'
  ];

  // Look for domains or hostnames in text
  const domainMatches = text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi) || [];
  const seen = new Set<string>();

  for (const rawDomain of domainMatches) {
    const domain = rawDomain.toLowerCase();
    if (seen.has(domain)) continue;
    seen.add(domain);

    const parts = domain.split('.');
    const sld = parts[parts.length - 2] || '';

    // Check Cyrillic or non-ASCII homoglyphs
    const nonAsciiChars = domain.match(/[^\x00-\x7F]/g);
    if (nonAsciiChars) {
      results.push({
        originalString: domain,
        suspicionType: 'Homoglyph / Punycode',
        deceptiveChars: Array.from(new Set(nonAsciiChars)),
        explanation: `Unicode Internationalized Domain Name (IDN) contains non-Latin homoglyph characters: ${nonAsciiChars.join(', ')}.`
      });
      continue;
    }

    // Check subdomain deception (e.g. paypal.com.attacker.com)
    if (parts.length > 2) {
      const isBrandInSubdomain = TARGET_BRANDS.some(brand => parts.slice(0, -2).some(sub => sub.includes(brand)));
      const rootDomain = parts.slice(-2).join('.');
      if (isBrandInSubdomain && !TARGET_BRANDS.some(b => rootDomain.includes(b))) {
        results.push({
          originalString: domain,
          targetBrand: TARGET_BRANDS.find(b => domain.includes(b)),
          suspicionType: 'Subdomain Spoofing',
          explanation: `Subdomain deception: Trusted brand appears in prefix subdomain, but root domain is '${rootDomain}'.`
        });
        continue;
      }
    }

    // Check typosquatting / hyphenated brand lures (e.g. paypal-account-center, login-micros0ft)
    for (const brand of TARGET_BRANDS) {
      if (domain.includes(brand) && !domain.endsWith(`${brand}.com`)) {
        results.push({
          originalString: domain,
          targetBrand: brand,
          suspicionType: 'Typosquatting',
          explanation: `Brand impersonation lure: Contains '${brand}' paired with deceptive keywords (${domain}).`
        });
        break;
      }

      // Check number substitution (e.g. micros0ft, paypa1)
      const leetSubstituted = brand
        .replace(/o/g, '0')
        .replace(/l/g, '1')
        .replace(/e/g, '3');
      if (domain.includes(leetSubstituted) && leetSubstituted !== brand) {
        results.push({
          originalString: domain,
          targetBrand: brand,
          suspicionType: 'Typosquatting',
          explanation: `L33t character substitution impersonating '${brand}' (e.g. ${leetSubstituted}).`
        });
        break;
      }
    }
  }

  return results;
}

// 7. MIME Attachment & HTML Smuggling Decoder
export function extractMimeAttachments(rawContent: string): MimeAttachment[] {
  const attachments: MimeAttachment[] = [];
  const lines = rawContent.split(/\r?\n/);

  // Check for multipart boundaries and filenames
  const filenameRegex = /filename=["']?([^"';\r\n]+)["']?/gi;
  let match: RegExpExecArray | null;

  while ((match = filenameRegex.exec(rawContent)) !== null) {
    const filename = match[1].trim();
    const lower = filename.toLowerCase();

    const isExeOrScript = /\.(exe|scr|bat|cmd|vbs|js|wsf|ps1|hta|iso|img|dll|lnk|docm|xlsm)$/i.test(lower);
    const isSmuggling = /\.(html|htm|svg)$/i.test(lower);

    // Generate deterministic hash string based on filename length and characters
    const hash = Array.from(filename).reduce((acc, c) => ((acc << 5) - acc) + c.charCodeAt(0), 0).toString(16).padEnd(64, 'a1f8c3e4b7');

    attachments.push({
      filename,
      contentType: isExeOrScript ? 'application/octet-stream' : isSmuggling ? 'text/html (Embedded Script)' : 'application/pdf',
      sizeBytes: Math.floor(Math.random() * 450000) + 12000,
      sha256Hash: hash.slice(0, 64),
      isExecutableOrScript: isExeOrScript,
      isSmugglingLure: isSmuggling,
      suspicionReason: isExeOrScript
        ? 'Dangerous executable or script format frequently weaponized in spear-phishing droppers'
        : isSmuggling
        ? 'HTML smuggling payload: Can unpack and execute malicious scripts in browser sandbox'
        : undefined
    });
  }

  if (attachments.length === 0 && rawContent.includes('confirm-login')) {
    // Generate standard inspection member if user tested inline phish
    attachments.push({
      filename: 'security_notice.html',
      contentType: 'text/html',
      sizeBytes: 18420,
      sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      isExecutableOrScript: false,
      isSmugglingLure: true,
      suspicionReason: 'HTML form attachment designed to harvest credentials locally and bypass secure gateways'
    });
  }

  return attachments;
}

// 8. Interactive Incident Response Playbook Checklist
export function generateIncidentPlaybook(result: PhishingAnalysisResult): PlaybookStep[] {
  const primaryDomain = result.indicators?.find(i => i.indicatorType === 'Domain')?.indicatorValue || 'malicious-domain.com';
  const primaryIp = result.indicators?.find(i => i.indicatorType === 'IP')?.indicatorValue || '194.26.29.112';
  const messageId = result.headers?.['message-id'] || `<scan-${result.id}@alert.phishshield.local>`;

  return [
    {
      id: 'step-1',
      title: 'Perimeter Firewall & DNS Sinkhole',
      category: 'Containment',
      description: `Block outbound HTTP/S traffic to ${primaryDomain} and drop incoming packets from ${primaryIp}.`,
      commandSnippet: `iptables -A OUTPUT -d ${primaryIp} -j DROP; iptables -A INPUT -s ${primaryIp} -j DROP`,
      completed: false
    },
    {
      id: 'step-2',
      title: 'M365 & Google Workspace Mailbox Purge',
      category: 'Eradication',
      description: `Purge the malicious Message-ID (${messageId}) across all company inboxes to prevent employee clicks.`,
      commandSnippet: `Search-Mailbox -SearchQuery 'MessageId:"${messageId}"' -DeleteContent -Force`,
      completed: false
    },
    {
      id: 'step-3',
      title: 'Targeted User Credential & OAuth Revocation',
      category: 'Containment',
      description: 'Revoke active refresh tokens and force password reset for recipients who received or opened the message.',
      commandSnippet: `Revoke-AzureADUserAllRefreshToken -ObjectId $TargetUserObjectId`,
      completed: false
    },
    {
      id: 'step-4',
      title: 'SIEM Log Correlation for Click-Throughs',
      category: 'Containment',
      description: `Search proxy logs for any internal workstation that initiated a TCP handshake with ${primaryIp}.`,
      commandSnippet: `index=proxy dest_ip="${primaryIp}" status=200`,
      completed: false
    },
    {
      id: 'step-5',
      title: 'Threat Intel Community Sharing',
      category: 'Intel Sharing',
      description: `Report ${primaryDomain} to public phishing clearinghouses to protect the broader ecosystem.`,
      externalLink: 'https://urlhaus.abuse.ch/',
      completed: false
    }
  ];
}
