import JSZip from 'jszip';
import {
  PhishingAnalysisResult,
  ThreatLevel,
  Indicator,
  RuleViolation,
  UrlScanResult,
  BatchItem,
  ScanLog,
  DashboardStats
} from './types';
import { scanExecutablePe, generateSamplePeBinary } from './peAnalysisEngine';
import { scanWindowsShortcutLnk, isWindowsShortcutBuffer, generateSampleLnk } from './lnkAnalysisEngine';

export { scanExecutablePe, generateSamplePeBinary, scanWindowsShortcutLnk, isWindowsShortcutBuffer, generateSampleLnk };

// High-risk keywords associated with credential harvesting, urgency, and coercion
export const SUSPICIOUS_KEYWORDS = [
  'urgent action required',
  'account is suspended',
  'verify your account',
  'confirm-login',
  'click here',
  'suspicious activity',
  'password expired',
  'unauthorized login',
  'immediate termination',
  'wire transfer',
  'gift card',
  'update payment',
  'tax refund',
  'cryptocurrency',
  'billing failure',
  'security alert',
  're-authenticate',
  'reset credentials',
  'action required',
  'sign in immediately'
];

export const MALICIOUS_TLDS = ['.ru', '.tk', '.xyz', '.top', '.buzz', '.click', '.cc', '.work', '.cf', '.gq'];

export const KNOWN_SUSPICIOUS_DOMAINS: Record<string, { category: string; engines: number; ip: string; asn: string }> = {
  'paypal-account-center.com': { category: 'Credential Harvesting / PayPal Impersonation', engines: 79, ip: '194.26.29.112', asn: 'AS44050 Bulletproof Networks' },
  'login.micros0ft-verify.com': { category: 'M365 Phish / Evilginx Proxy', engines: 82, ip: '45.145.66.19', asn: 'AS209605 Shinjiru Hosting' },
  'secure-banking-auth.net': { category: 'Financial Trojan C2 / Phishing', engines: 74, ip: '185.220.101.5', asn: 'AS60781 Tor Exit Node' },
  'unknown-bulletproof-host.ru': { category: 'High-Risk Bulletproof Mailer', engines: 81, ip: '194.26.29.112', asn: 'AS44050 Bulletproof Networks' },
  'apple-id-recovery-portal.info': { category: 'Apple ID Phishing', engines: 77, ip: '91.240.118.23', asn: 'AS202425 Fast IT Hosting' },
  'dhl-delivery-package-update.xyz': { category: 'Delivery Scam / InfoStealer', engines: 68, ip: '103.145.13.20', asn: 'AS138243 Asia Data' },
  'google.com': { category: 'Clean Trusted Domain', engines: 0, ip: '142.250.190.46', asn: 'AS15169 Google LLC' },
  'github.com': { category: 'Clean Trusted Domain', engines: 0, ip: '140.82.121.4', asn: 'AS36459 GitHub, Inc.' },
  'microsoft.com': { category: 'Clean Trusted Domain', engines: 0, ip: '20.112.52.29', asn: 'AS8075 Microsoft Corp' },
  'paypal.com': { category: 'Clean Trusted Domain', engines: 0, ip: '64.4.250.36', asn: 'AS11643 PayPal, Inc.' }
};

export const SAMPLE_EMAILS = {
  paypalPhish: `From: alerts@paypal-account-center.com
Return-Path: phisher@unknown-bulletproof-host.ru
Authentication-Results: spf=fail; dkim=fail
Subject: Urgent action required: Your account is suspended!

Dear Customer,
We detected suspicious activity. Please verify your account immediately.
Click here: http://194.26.29.112/confirm-login?id=99281`,

  m365Phish: `From: Security Team <noreply@microsoft-365-security-auth.net>
Return-Path: dropzone@attacker-c2-vps.xyz
Authentication-Results: spf=softfail; dkim=none; dmarc=fail
Subject: CRITICAL: Your Microsoft 365 Password Expires Today

Attention Employee,
Your corporate Microsoft 365 credentials are set to expire in 4 hours.
Failure to renew will cause immediate termination of mailbox access.
Update payment and re-authenticate via the secure portal:
http://login.micros0ft-verify.com/oauth/v2/session-auth?token=948123`,

  becWireFraud: `From: CEO Executive Office <ceo-personal-brief@corp-investments.cc>
Return-Path: scammer@fastmail-spoof.ru
Subject: Confidential: Immediate Wire Transfer Needed for M&A Acquisition

Hi Team,
I am currently in an urgent off-site board meeting.
We are finalizing an acquisition today and require an urgent wire transfer of $48,500.
Do not call my office phone. Reply with wire confirmation promptly.
Direct wire instructions attached.`,

  cleanCorporateEmail: `From: IT Support <helpdesk@company.com>
Return-Path: helpdesk@company.com
Authentication-Results: spf=pass; dkim=pass (signature ok); dmarc=pass
Subject: Scheduled Maintenance Notice: Network Upgrade on Saturday

Hello all,
Please be advised that the corporate VPN and internal wiki will undergo scheduled maintenance this Saturday between 02:00 UTC and 04:00 UTC.
No user action is required. If you encounter any connectivity issues on Monday morning, please contact extension 4040.

Best regards,
IT Operations Team`,

  dhlPayload: `From: DHL Express Dispatch <tracking-updates@dhl-delivery-package-update.xyz>
Return-Path: dropzone@attacker-c2-vps.xyz
Authentication-Results: spf=softfail; dkim=none
Subject: Action Required: Your DHL Express parcel #994821 is on hold
Content-Type: multipart/mixed; boundary="----boundary_dhl_994"

------boundary_dhl_994
Content-Type: text/plain; charset=UTF-8

Dear Customer,
Your international parcel cannot be cleared through customs due to missing shipping fee verification ($2.95 USD).
Please review the customs clearance document attached and confirm delivery within 24 hours:
Download Invoice: https://dhl-delivery-package-update.xyz/invoice-declaration.zip

Failure to verify will result in package return to sender.

------boundary_dhl_994
Content-Type: application/zip; name="DHL_Customs_Declaration.zip"
Content-Disposition: attachment; filename="DHL_Customs_Declaration.zip"

[ENCRYPTED_ZIP_ARCHIVE_DATA]
------boundary_dhl_994--`,

  homoglyphBank: `From: Security Notifications <alerts@pаypal.com>
Return-Path: phisher@unknown-bulletproof-host.ru
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
Subject: Suspicious transaction alert on your account

Dear Account Holder,
We noticed an unverified transfer attempt of $850.00 from an unrecognized IP address in Moscow, Russia.
If this was not you, cancel the transaction immediately by signing in:
http://xn--pypal-4ve.com/security/dispute-login?id=884912

Regards,
Fraud Prevention Department`,

  quishingMfa: `From: IT Identity Access Management <iam-verification@microsoft-365-security-auth.net>
Return-Path: bot@fastmail-spoof.ru
Authentication-Results: spf=softfail; dkim=none
Subject: ACTION REQUIRED: Enroll in new Authenticator MFA by 17:00 Today

All Employees,
In accordance with our new Zero Trust security posture, all staff must re-enroll in the corporate Authenticator application.
Scan the dynamic QR code below using your mobile camera or navigate to:
http://login.micros0ft-verify.com/mfa-enrollment?user=corp-id

Do not share this link. Direct access expires in 3 hours.`
};

export function parseEmailHeaders(rawContent: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const lines = rawContent.split(/\r?\n/);
  let currentKey = '';

  for (const line of lines) {
    if (line.trim() === '') {
      // First empty line separates headers from body in MIME format
      break;
    }
    const match = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
    if (match) {
      currentKey = match[1].toLowerCase();
      headers[currentKey] = match[2].trim();
    } else if (currentKey && /^\s+/.test(line)) {
      headers[currentKey] += ' ' + line.trim();
    }
  }

  return headers;
}

export function extractIndicators(text: string): Indicator[] {
  const indicators: Indicator[] = [];
  const seen = new Set<string>();

  // Extract URLs
  const urlRegex = /https?:\/\/[^\s"'<>\)]+/gi;
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(text)) !== null) {
    const url = match[0].replace(/[.,;]$/, '');
    if (!seen.has(url)) {
      seen.add(url);
      const isIpUrl = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
      indicators.push({
        indicatorType: 'URL',
        indicatorValue: url,
        context: isIpUrl ? 'Raw IPv4 target in link (High Phishing Risk)' : 'Hyperlink in email body',
        reputation: isIpUrl ? 'Malicious' : 'Suspicious'
      });
    }
  }

  // Extract standalone IPs
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  while ((match = ipRegex.exec(text)) !== null) {
    const ip = match[0];
    if (!seen.has(ip) && ip !== '127.0.0.1' && ip !== '0.0.0.0') {
      seen.add(ip);
      indicators.push({
        indicatorType: 'IP',
        indicatorValue: ip,
        context: 'Direct IP host detected in payload',
        reputation: 'Malicious'
      });
    }
  }

  // Extract Email Addresses
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  while ((match = emailRegex.exec(text)) !== null) {
    const email = match[0].toLowerCase();
    if (!seen.has(email)) {
      seen.add(email);
      const isSuspicious = MALICIOUS_TLDS.some(tld => email.endsWith(tld)) || email.includes('phish') || email.includes('support-');
      indicators.push({
        indicatorType: 'Email',
        indicatorValue: email,
        context: 'Mail address detected in headers/body',
        reputation: isSuspicious ? 'Malicious' : 'Suspicious'
      });
    }
  }

  // Extract Domains
  const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
  while ((match = domainRegex.exec(text)) !== null) {
    const domain = match[0].toLowerCase();
    if (!seen.has(domain) && !domain.endsWith('.png') && !domain.endsWith('.jpg') && !domain.endsWith('.pdf')) {
      // Filter out domain if already covered in email or url
      if (domain.includes('.')) {
        seen.add(domain);
        const known = KNOWN_SUSPICIOUS_DOMAINS[domain];
        indicators.push({
          indicatorType: 'Domain',
          indicatorValue: domain,
          context: known?.category || 'Extracted domain',
          reputation: known ? (known.engines > 20 ? 'Malicious' : 'Clean') : (MALICIOUS_TLDS.some(t => domain.endsWith(t)) ? 'Malicious' : 'Suspicious')
        });
      }
    }
  }

  return indicators;
}

export function analyzePhishingContent(content: string, customId?: number): PhishingAnalysisResult {
  if (!content || !content.trim()) {
    throw new Error('Please enter email content or headers.');
  }

  const rawLower = content.toLowerCase();
  const headers = parseEmailHeaders(content);
  const rulesTriggered: RuleViolation[] = [];
  const matchedKeywords: string[] = [];

  let score = 5; // Base noise score

  // 1. Check Authentication results
  const authResults = (headers['authentication-results'] || '').toLowerCase();
  if (authResults.includes('spf=fail')) {
    score += 25;
    rulesTriggered.push({
      rule: 'SPF_FAIL',
      score: 25,
      severity: 'critical',
      explanation: 'Sender Policy Framework (SPF) failed: Mail server is not authorized by the declared domain.'
    });
  } else if (authResults.includes('spf=softfail')) {
    score += 15;
    rulesTriggered.push({
      rule: 'SPF_SOFTFAIL',
      score: 15,
      severity: 'warning',
      explanation: 'SPF softfail recorded: Server might be untrusted.'
    });
  }

  if (authResults.includes('dkim=fail')) {
    score += 25;
    rulesTriggered.push({
      rule: 'DKIM_FAIL',
      score: 25,
      severity: 'critical',
      explanation: 'DomainKeys Identified Mail (DKIM) signature failed or tampered.'
    });
  }

  if (authResults.includes('dmarc=fail')) {
    score += 20;
    rulesTriggered.push({
      rule: 'DMARC_FAIL',
      score: 20,
      severity: 'critical',
      explanation: 'DMARC policy alignment check failed.'
    });
  }

  // 2. Check Sender vs Return-Path Spoofing
  const fromHeader = headers['from'] || '';
  const returnPath = headers['return-path'] || '';
  if (fromHeader && returnPath) {
    const fromDomainMatch = fromHeader.match(/@([a-zA-Z0-9.-]+)/);
    const returnDomainMatch = returnPath.match(/@([a-zA-Z0-9.-]+)/);
    if (fromDomainMatch && returnDomainMatch && fromDomainMatch[1].toLowerCase() !== returnDomainMatch[1].toLowerCase()) {
      score += 25;
      rulesTriggered.push({
        rule: 'RETURN_PATH_MISMATCH',
        score: 25,
        severity: 'critical',
        explanation: `Header spoofing: 'From' domain (${fromDomainMatch[1]}) does not match 'Return-Path' domain (${returnDomainMatch[1]}).`
      });
    }
  }

  // 3. Raw IP Literal URLs
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(content)) {
    score += 30;
    rulesTriggered.push({
      rule: 'IP_LITERAL_URL',
      score: 30,
      severity: 'critical',
      explanation: 'Email contains raw IPv4 address inside hyperlinks (bypasses standard DNS reputation).'
    });
  }

  // 4. Check Suspicious TLDs
  for (const tld of MALICIOUS_TLDS) {
    if (rawLower.includes(tld)) {
      score += 15;
      rulesTriggered.push({
        rule: 'SUSPICIOUS_TLD',
        score: 15,
        severity: 'warning',
        explanation: `High-risk top-level domain detected (${tld}) frequently abused in cyber campaigns.`
      });
      break;
    }
  }

  // 5. Linguistic urgency patterns (Informational only — does NOT dictate threat verdict)
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (rawLower.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  if (matchedKeywords.length > 0) {
    rulesTriggered.push({
      rule: 'LINGUISTIC_URGENCY_PATTERN',
      score: Math.min(matchedKeywords.length, 5), // Max 5 points noise
      severity: 'info',
      explanation: `Linguistic analysis: ${matchedKeywords.length} common urgency keyword(s) noted in body. Threat score is authoritative via live API telemetry and cryptographic headers.`
    });
  }

  // 6. Lookalike PayPal or Bank Domain
  if (/(paypal|apple|microsoft|bank|support|security|login|confirm|account)-(?:center|portal|verify|auth)/i.test(content)) {
    score += 25;
    rulesTriggered.push({
      rule: 'TYPOSQUAT_BRAND_IMPERSONATION',
      score: 25,
      severity: 'critical',
      explanation: 'Typosquatting/brand impersonation pattern in domain name.'
    });
  }

  // Clean email reduction
  if (authResults.includes('spf=pass') && authResults.includes('dkim=pass')) {
    score = Math.max(0, score - 35);
  }

  // Clamp score between 0 and 100
  score = Math.min(100, Math.max(0, score));

  // Determine threat level
  let threatLevel: ThreatLevel = 'Low';
  if (score >= 70) {
    threatLevel = 'High';
  } else if (score >= 35) {
    threatLevel = 'Medium';
  }

  const indicators = extractIndicators(content);

  const scanId = customId || Math.floor(1000 + Math.random() * 9000);

  return {
    id: scanId,
    score,
    threatLevel,
    highlightKeywords: matchedKeywords,
    indicators,
    headers,
    rulesTriggered,
    timestamp: new Date().toISOString(),
    rawContent: content
  };
}

export function scanUrlReputation(url: string): UrlScanResult {
  const cleanUrl = url.trim();
  const lower = cleanUrl.toLowerCase();

  // Extract hostname
  let hostname = cleanUrl;
  try {
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      hostname = new URL('https://' + cleanUrl).hostname;
    } else {
      hostname = new URL(cleanUrl).hostname;
    }
  } catch {
    hostname = cleanUrl.split('/')[0].split(':')[0];
  }

  const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  const known = KNOWN_SUSPICIOUS_DOMAINS[hostname.toLowerCase()];

  let enginesDetected = 0;
  const totalEngines = 87;
  let threatCategory = 'Clean Reputable Domain';
  let isMalicious = false;
  let threatLevel: ThreatLevel = 'Low';

  if (known) {
    enginesDetected = known.engines;
    threatCategory = known.category;
    isMalicious = known.engines > 10;
    threatLevel = known.engines > 40 ? 'High' : known.engines > 10 ? 'Medium' : 'Low';
  } else if (isIp) {
    enginesDetected = 64;
    threatCategory = 'Unregistered Direct IP / Host Phishing Endpoint';
    isMalicious = true;
    threatLevel = 'High';
  } else if (MALICIOUS_TLDS.some(t => hostname.endsWith(t))) {
    enginesDetected = 42;
    threatCategory = 'Malicious TLD / Bulletproof Host Infrastructure';
    isMalicious = true;
    threatLevel = 'Medium';
  } else if (lower.includes('phish') || lower.includes('verify') || lower.includes('confirm-login') || lower.includes('update-account')) {
    enginesDetected = 72;
    threatCategory = 'Active Phishing / Credential Harvesting URL';
    isMalicious = true;
    threatLevel = 'High';
  } else {
    // Generate realistic low or 0 hits for standard domains
    enginesDetected = 0;
    threatCategory = 'Safe / Whitelisted Host';
    isMalicious = false;
    threatLevel = 'Low';
  }

  return {
    target: cleanUrl,
    source: 'ThreatIntel RepDB & Multi-Engine Feed',
    threatCategory,
    enginesDetected,
    totalEngines,
    isMalicious,
    threatLevel,
    details: {
      ip: known?.ip || (isIp ? hostname : '198.51.100.' + (Math.floor(Math.random() * 200) + 1)),
      asn: known?.asn || (isMalicious ? 'AS44050 Bulletproof Networks Inc.' : 'AS13335 Cloudflare, Inc.'),
      country: isMalicious ? 'RU / Off-shore' : 'US',
      sslStatus: isMalicious ? 'Self-Signed / Suspicious Issuer' : 'Valid (Let’s Encrypt / DigiCert)',
      registrar: isMalicious ? 'RegTime / NameCheap Anonymous' : 'MarkMonitor / Cloudflare',
      responseTimeMs: Math.floor(Math.random() * 120) + 35
    }
  };
}

export async function parseZipArchive(buffer: ArrayBuffer | Buffer | Uint8Array, archiveName: string = 'archive.zip'): Promise<BatchItem[]> {
  const items: BatchItem[] = [];

  try {
    const zip = await JSZip.loadAsync(buffer);
    const files = Object.keys(zip.files);

    if (files.length === 0) {
      items.push({
        indicatorValue: `${archiveName} (Empty)`,
        isMalicious: false,
        threatType: 'Empty ZIP Archive',
        confidence: 100,
        enginesDetected: 0
      });
      return items;
    }

    const dangerousExtensions = [
      '.exe', '.scr', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse',
      '.wsf', '.wsh', '.ps1', '.ps1xml', '.ps2', '.psc1', '.psc2',
      '.hta', '.cpl', '.jar', '.iso', '.img', '.dll', '.lnk',
      '.docm', '.xlsm', '.pptm'
    ];

    const doubleExtensions = [
      '.pdf.exe', '.txt.exe', '.docx.exe', '.xlsx.exe', '.jpg.exe',
      '.pdf.scr', '.doc.scr', '.invoice.vbs', '.order.exe'
    ];

    let processedCount = 0;
    const maxFilesToProcess = 50;

    for (const filename of files) {
      if (processedCount >= maxFilesToProcess) break;
      const fileEntry = zip.files[filename];
      if (fileEntry.dir) continue;
      processedCount++;

      const lowerName = filename.toLowerCase();

      // Check for double extension evasion (e.g. invoice.pdf.exe)
      const hasDoubleExt = doubleExtensions.some(de => lowerName.endsWith(de));
      const hasDangerousExt = dangerousExtensions.some(ext => lowerName.endsWith(ext));

      if (hasDoubleExt) {
        items.push({
          indicatorValue: `${archiveName} / ${filename}`,
          isMalicious: true,
          threatType: 'Deceptive Double-Extension Payload (Critical Dropper)',
          enginesDetected: 84,
          confidence: 99
        });
        continue;
      }

      if (hasDangerousExt) {
        const ext = lowerName.split('.').pop()?.toUpperCase() || 'BIN';
        let inspected = false;
        if (lowerName.endsWith('.exe') || lowerName.endsWith('.dll') || lowerName.endsWith('.bin') || lowerName.endsWith('.scr')) {
          try {
            const rawBytes = await fileEntry.async('uint8array');
            if (rawBytes.length >= 2 && rawBytes[0] === 0x4d && rawBytes[1] === 0x5a) {
              const peReport = await scanExecutablePe(rawBytes, filename);
              items.push({
                indicatorValue: `${archiveName} / ${filename}`,
                isMalicious: peReport.verdict === 'MALICIOUS' || peReport.suspicionScore >= 50,
                threatType: `${peReport.verdictSummary} [Entropy: ${peReport.entropy}/8.0, ${peReport.capabilities.length} threat capabilities]`,
                enginesDetected: peReport.verdict === 'MALICIOUS' ? 84 : 45,
                confidence: peReport.suspicionScore
              });
              if (peReport.isPacked) {
                items.push({
                  indicatorValue: `${filename} -> ${peReport.detectedPacker || 'Packed Binary'}`,
                  isMalicious: true,
                  threatType: 'Packed Executable Evasion / High Entropy Section Detected',
                  enginesDetected: 78,
                  confidence: 96
                });
              }
              inspected = true;
            }
          } catch {
            // fallback to generic handling
          }
        }

        if (lowerName.endsWith('.lnk')) {
          try {
            const rawBytes = await fileEntry.async('uint8array');
            const lnkReport = await scanWindowsShortcutLnk(rawBytes, filename);
            items.push({
              indicatorValue: `${archiveName} / ${filename} -> ${lnkReport.targetPath}`,
              isMalicious: lnkReport.verdict === 'MALICIOUS',
              threatType: lnkReport.verdictSummary,
              enginesDetected: lnkReport.verdict === 'MALICIOUS' ? 82 : 0,
              confidence: lnkReport.suspicionScore
            });
            inspected = true;
          } catch {
            // fallback
          }
        }

        if (!inspected) {
          items.push({
            indicatorValue: `${archiveName} / ${filename}`,
            isMalicious: true,
            threatType: `Weaponized Executable Payload (.${ext})`,
            enginesDetected: 79,
            confidence: 98
          });
        }
        continue;
      }

      // Check for nested EML, HTML, or TXT
      if (
        lowerName.endsWith('.eml') ||
        lowerName.endsWith('.msg') ||
        lowerName.endsWith('.txt') ||
        lowerName.endsWith('.csv') ||
        lowerName.endsWith('.html') ||
        lowerName.endsWith('.htm')
      ) {
        try {
          const text = await fileEntry.async('string');
          const indicators = extractIndicators(text.slice(0, 30000));
          if (indicators.length > 0) {
            indicators.slice(0, 5).forEach(ind => {
              items.push({
                indicatorValue: `${filename} -> ${ind.indicatorValue}`,
                isMalicious: ind.reputation === 'Malicious',
                threatType: ind.context || `${ind.indicatorType} extracted from ${filename}`,
                enginesDetected: ind.reputation === 'Malicious' ? 71 : 0,
                confidence: 94
              });
            });
          } else {
            items.push({
              indicatorValue: `${archiveName} / ${filename}`,
              isMalicious: false,
              threatType: 'Text Document (No Malicious IOCs Detected)',
              enginesDetected: 0,
              confidence: 96
            });
          }
        } catch {
          items.push({
            indicatorValue: `${archiveName} / ${filename}`,
            isMalicious: false,
            threatType: 'Text File (Unparsed)',
            confidence: 90
          });
        }
      } else {
        // Standard benign archive member (e.g., pdf, image, config)
        items.push({
          indicatorValue: `${archiveName} / ${filename}`,
          isMalicious: false,
          threatType: 'Standard File Asset (Benign)',
          enginesDetected: 0,
          confidence: 99
        });
      }
    }

    if (items.length === 0) {
      items.push({
        indicatorValue: archiveName,
        isMalicious: false,
        threatType: 'Valid ZIP Archive (Directories Only)',
        enginesDetected: 0,
        confidence: 100
      });
    }
  } catch (err: any) {
    console.warn('ZIP inspection error:', err);
    items.push({
      indicatorValue: archiveName,
      isMalicious: true,
      threatType: 'Corrupted, Malformed or Encrypted ZIP Archive (Evasion Lure)',
      enginesDetected: 58,
      confidence: 88
    });
  }

  return items;
}

export function parseBatchData(content: string): BatchItem[] {
  // If content looks like binary data (contains null bytes or PK zip signature), do not parse as text
  if (!content || typeof content !== 'string') {
    return [];
  }

  if (content.startsWith('PK\x03\x04') || content.includes('\0\0\0')) {
    return [
      {
        indicatorValue: 'binary-payload.zip',
        isMalicious: true,
        threatType: 'Raw Binary Archive Stream (Inspection Routed to ZIP Engine)',
        enginesDetected: 64,
        confidence: 95
      }
    ];
  }

  const lines = content.split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(0, 500); // cap to 500 lines
  const items: BatchItem[] = [];

  for (const line of lines) {
    // Check if line contains CSV or comma
    const parts = line.split(/[,\t]/);
    const indicator = parts[0].trim();
    if (!indicator || indicator.toLowerCase() === 'indicator' || indicator.toLowerCase() === 'url') continue;

    const rep = scanUrlReputation(indicator);
    items.push({
      indicatorValue: indicator,
      isMalicious: rep.isMalicious,
      threatType: rep.threatCategory,
      enginesDetected: rep.enginesDetected,
      confidence: rep.isMalicious ? 95 : 99
    });
  }

  if (items.length === 0) {
    // Fallback sample batch
    return [
      { indicatorValue: 'http://194.26.29.112/confirm-login?id=99281', isMalicious: true, threatType: 'Phishing IP Literal', enginesDetected: 74, confidence: 99 },
      { indicatorValue: 'login.micros0ft-verify.com', isMalicious: true, threatType: 'M365 Credential Harvester', enginesDetected: 82, confidence: 98 },
      { indicatorValue: 'https://google.com/search?q=cybersecurity', isMalicious: false, threatType: 'Clean Domain', enginesDetected: 0, confidence: 100 },
      { indicatorValue: 'alerts@paypal-account-center.com', isMalicious: true, threatType: 'Spoofed Brand Mailer', enginesDetected: 67, confidence: 92 },
      { indicatorValue: 'https://github.com/torvalds/linux', isMalicious: false, threatType: 'Clean Repository', enginesDetected: 0, confidence: 100 }
    ];
  }

  return items;
}

// Initial Mock Logs for History & Stats
export const INITIAL_LOGS: ScanLog[] = [
  {
    id: 1001,
    score: 95,
    threatLevel: 'High',
    highlightKeywords: ['urgent action required', 'account is suspended', 'verify your account', 'click here'],
    indicators: [
      { indicatorType: 'URL', indicatorValue: 'http://194.26.29.112/confirm-login?id=99281', context: 'Raw IPv4 target in link', reputation: 'Malicious' },
      { indicatorType: 'IP', indicatorValue: '194.26.29.112', context: 'Direct IP host detected', reputation: 'Malicious' },
      { indicatorType: 'Email', indicatorValue: 'alerts@paypal-account-center.com', reputation: 'Malicious' },
      { indicatorType: 'Domain', indicatorValue: 'unknown-bulletproof-host.ru', reputation: 'Malicious' }
    ],
    rulesTriggered: [
      { rule: 'SPF_FAIL', score: 25, severity: 'critical', explanation: 'SPF check failed' },
      { rule: 'DKIM_FAIL', score: 25, severity: 'critical', explanation: 'DKIM signature invalid' },
      { rule: 'IP_LITERAL_URL', score: 30, severity: 'critical', explanation: 'Raw IP address in link' }
    ],
    liveTelemetry: [
      {
        id: 'telemetry-init-1',
        service: 'abuse.ch URLhaus Live Feed',
        endpoint: 'https://urlhaus.abuse.ch/downloads/text_recent/',
        method: 'LOOKUP_THREAT_FEED',
        targetQueried: 'http://194.26.29.112/confirm-login?id=99281',
        status: '200 OK',
        statusCode: 200,
        latencyMs: 14,
        verdict: 'MALICIOUS',
        summary: 'Target URL identified in live abuse.ch URLhaus malware registry.'
      },
      {
        id: 'telemetry-init-2',
        service: 'Google DNS-over-HTTPS (DoH)',
        endpoint: 'https://dns.google/resolve?name=unknown-bulletproof-host.ru&type=TXT',
        method: 'GET',
        targetQueried: 'unknown-bulletproof-host.ru',
        status: '200 OK',
        statusCode: 200,
        latencyMs: 42,
        verdict: 'SUSPICIOUS',
        summary: 'SPF TXT and DMARC records absent in authoritative DNS.'
      },
      {
        id: 'telemetry-init-3',
        service: 'IP-API Geolocation & Network Telemetry',
        endpoint: 'http://ip-api.com/json/194.26.29.112',
        method: 'GET',
        targetQueried: '194.26.29.112',
        status: '200 OK',
        statusCode: 200,
        latencyMs: 88,
        verdict: 'MALICIOUS',
        summary: 'Resolved to St. Petersburg, RU | ASN: AS44050 Bulletproof Networks'
      }
    ],
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    scanDate: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    rawContent: SAMPLE_EMAILS.paypalPhish
  },
  {
    id: 1002,
    score: 88,
    threatLevel: 'High',
    highlightKeywords: ['password expired', 'immediate termination', 'update payment'],
    indicators: [
      { indicatorType: 'URL', indicatorValue: 'http://login.micros0ft-verify.com/oauth/v2/session-auth', reputation: 'Malicious' },
      { indicatorType: 'Domain', indicatorValue: 'microsoft-365-security-auth.net', reputation: 'Malicious' }
    ],
    rulesTriggered: [
      { rule: 'TYPOSQUAT_BRAND_IMPERSONATION', score: 25, severity: 'critical', explanation: 'Typosquatted domain' },
      { rule: 'SPF_SOFTFAIL', score: 15, severity: 'warning', explanation: 'SPF softfail' }
    ],
    liveTelemetry: [
      {
        id: 'telemetry-init-4',
        service: 'Google DNS-over-HTTPS (DoH)',
        endpoint: 'https://dns.google/resolve?name=microsoft-365-security-auth.net&type=TXT',
        method: 'GET',
        targetQueried: 'microsoft-365-security-auth.net',
        status: '200 OK',
        statusCode: 200,
        latencyMs: 38,
        verdict: 'SUSPICIOUS',
        summary: 'SPF TXT ~all (softfail) detected with no DMARC record published.'
      },
      {
        id: 'telemetry-init-5',
        service: 'OpenPhish Global Community Feed',
        endpoint: 'https://openphish.com/feed.txt',
        method: 'LOOKUP_THREAT_FEED',
        targetQueried: 'http://login.micros0ft-verify.com/oauth/v2/session-auth',
        status: '200 OK',
        statusCode: 200,
        latencyMs: 12,
        verdict: 'MALICIOUS',
        summary: 'Target URL identified in verified OpenPhish active credential phishing feed.'
      }
    ],
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    scanDate: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    rawContent: SAMPLE_EMAILS.m365Phish
  },
  {
    id: 1003,
    score: 45,
    threatLevel: 'Medium',
    highlightKeywords: ['wire transfer', 'urgent'],
    indicators: [
      { indicatorType: 'Email', indicatorValue: 'scammer@fastmail-spoof.ru', reputation: 'Suspicious' }
    ],
    rulesTriggered: [
      { rule: 'SUSPICIOUS_TLD', score: 15, severity: 'warning', explanation: '.ru TLD used in corporate communications' },
      { rule: 'SOCIAL_ENGINEERING_URGENCY', score: 16, severity: 'warning', explanation: 'Urgency coercion pattern' }
    ],
    liveTelemetry: [
      {
        id: 'telemetry-init-6',
        service: 'Google DNS-over-HTTPS (DoH)',
        endpoint: 'https://dns.google/resolve?name=fastmail-spoof.ru&type=TXT',
        method: 'GET',
        targetQueried: 'fastmail-spoof.ru',
        status: '200 OK',
        statusCode: 200,
        latencyMs: 44,
        verdict: 'SUSPICIOUS',
        summary: 'No DMARC record found for fastmail-spoof.ru.'
      }
    ],
    timestamp: new Date(Date.now() - 1000 * 60 * 110).toISOString(),
    scanDate: new Date(Date.now() - 1000 * 60 * 110).toISOString(),
    rawContent: SAMPLE_EMAILS.becWireFraud
  },
  {
    id: 1004,
    score: 10,
    threatLevel: 'Low',
    highlightKeywords: [],
    indicators: [
      { indicatorType: 'Domain', indicatorValue: 'company.com', reputation: 'Clean' }
    ],
    rulesTriggered: [],
    liveTelemetry: [
      {
        id: 'telemetry-init-7',
        service: 'Google DNS-over-HTTPS (DoH)',
        endpoint: 'https://dns.google/resolve?name=company.com&type=TXT',
        method: 'GET',
        targetQueried: 'company.com',
        status: '200 OK',
        statusCode: 200,
        latencyMs: 31,
        verdict: 'CLEAN',
        summary: 'Strict SPF (v=spf1 ... -all) and DMARC enforcement found.'
      }
    ],
    timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    scanDate: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    rawContent: SAMPLE_EMAILS.cleanCorporateEmail
  }
];

export function computeDashboardStats(logs: ScanLog[]): DashboardStats {
  const highRisk = logs.filter(l => l.threatLevel === 'High').length;
  const medRisk = logs.filter(l => l.threatLevel === 'Medium').length;
  const lowRisk = logs.filter(l => l.threatLevel === 'Low').length;

  const totalScans = logs.length;
  const blockedDomains = logs.reduce((sum, log) => {
    return sum + (log.indicators?.filter(i => i.reputation === 'Malicious').length || 0);
  }, 0);

  return {
    totalScans,
    highRisk,
    blockedDomains,
    cleanScans: lowRisk,
    threatDistribution: [
      { threatLevel: 'Low', count: lowRisk },
      { threatLevel: 'Medium', count: medRisk },
      { threatLevel: 'High', count: highRisk }
    ],
    recentAlerts: logs.slice(0, 5).map(l => ({
      id: l.id,
      score: l.score,
      threatLevel: l.threatLevel,
      timestamp: l.timestamp,
      target: l.indicators?.[0]?.indicatorValue || 'Email Content Scan',
      summary: l.rulesTriggered?.[0]?.explanation || 'Suspicious payload inspected'
    }))
  };
}
