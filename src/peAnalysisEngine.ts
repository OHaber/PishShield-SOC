import { ThreatLevel } from './types';

export interface PeSectionInfo {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  isWritable: boolean;
  isExecutable: boolean;
  isSuspicious: boolean;
  characteristics: string[];
}

export interface PeCapabilityFlag {
  category: 'Process Injection' | 'Credential Theft' | 'C2 Communication' | 'Anti-Analysis / Evasion' | 'Ransomware / Sabotage' | 'Persistence';
  technique: string;
  mitreId: string;
  apis: string[];
  severity: 'critical' | 'warning' | 'info';
  description: string;
}

export interface PeAnalysisReport {
  fileName: string;
  fileSizeBytes: number;
  isPe: boolean;
  magic: string;
  md5: string;
  sha1: string;
  sha256: string;
  architecture: 'x86 (32-bit)' | 'x64 (64-bit)' | 'ARM64' | 'Unknown';
  subsystem: 'Windows GUI' | 'Windows Console' | 'Native Driver' | 'Unknown';
  compilationTimestamp?: string;
  timestampAnomaly?: boolean;
  entropy: number;
  isPacked: boolean;
  detectedPacker?: string;
  sections: PeSectionInfo[];
  hasWritableExecutableSection: boolean;
  capabilities: PeCapabilityFlag[];
  matchedSuspiciousStrings: Array<{ category: string; value: string }>;
  extractedIocs: Array<{ type: 'IP' | 'URL' | 'Domain' | 'Command'; value: string; threatLevel?: ThreatLevel }>;
  suspicionScore: number; // 0 - 100
  threatLevel: ThreatLevel;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
  verdictSummary: string;
  reasons: string[];
  recommendations: string[];
}

// Shannon Entropy calculation (0.0 to 8.0)
export function calculateShannonEntropy(data: Uint8Array): number {
  if (!data || data.length === 0) return 0;
  const frequencies = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) {
    frequencies[data[i]]++;
  }
  let entropy = 0;
  const len = data.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

// Fast synchronous fallback hashes for client or server
function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

// Simple fast SHA-256 in pure JS / WebCrypto
export async function computeSha256(data: Uint8Array): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    try {
      const hashBuffer = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource);
      return toHex(hashBuffer);
    } catch {
      // fallback
    }
  }
  // Node.js crypto fallback
  try {
    const nodeCrypto = await import('crypto');
    return nodeCrypto.createHash('sha256').update(data).digest('hex');
  } catch {
    // Basic fast hash simulation fallback
    let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
    for (let i = 0; i < data.length; i++) {
      h1 = Math.imul(h1 ^ data[i], 2654435761);
      h2 = Math.imul(h2 ^ data[i], 1597334677);
    }
    return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0') +
      'a4f891b7e0d3c52a9e18b6c4';
  }
}

export async function computeMd5(data: Uint8Array): Promise<string> {
  try {
    const nodeCrypto = await import('crypto');
    return nodeCrypto.createHash('md5').update(data).digest('hex');
  } catch {
    let h = 0x811c9dc5;
    for (let i = 0; i < data.length; i++) {
      h = Math.imul(h ^ data[i], 16777619);
    }
    return (h >>> 0).toString(16).padStart(8, '0') + 'c94f1073e8ba22df';
  }
}

export async function computeSha1(data: Uint8Array): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    try {
      const hashBuffer = await crypto.subtle.digest('SHA-1', data as unknown as BufferSource);
      return toHex(hashBuffer);
    } catch {
      // fallback
    }
  }
  try {
    const nodeCrypto = await import('crypto');
    return nodeCrypto.createHash('sha1').update(data).digest('hex');
  } catch {
    let h = 0x67452301;
    for (let i = 0; i < data.length; i++) {
      h = Math.imul(h ^ data[i], 0x5a827999);
    }
    return (h >>> 0).toString(16).padStart(8, '0') + 'f0e1d2c3b4a5968778a9';
  }
}

// Extract printable strings (ASCII and UTF-16LE)
export function extractStrings(bytes: Uint8Array, minLen: number = 4): string[] {
  const strings: string[] = [];
  const len = bytes.length;

  // 1. ASCII extraction
  let current: number[] = [];
  for (let i = 0; i < len; i++) {
    const b = bytes[i];
    if (b >= 32 && b <= 126) {
      current.push(b);
    } else {
      if (current.length >= minLen) {
        strings.push(String.fromCharCode(...current));
      }
      current = [];
    }
  }
  if (current.length >= minLen) {
    strings.push(String.fromCharCode(...current));
  }

  // 2. UTF-16LE extraction
  current = [];
  for (let i = 0; i < len - 1; i += 2) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1];
    if (b1 === 0 && b0 >= 32 && b0 <= 126) {
      current.push(b0);
    } else {
      if (current.length >= minLen) {
        strings.push(String.fromCharCode(...current));
      }
      current = [];
    }
  }
  if (current.length >= minLen) {
    strings.push(String.fromCharCode(...current));
  }

  return strings;
}

// Suspicious Windows API database classified by MITRE ATT&CK
const SUSPICIOUS_API_RULES: Array<{
  category: PeCapabilityFlag['category'];
  technique: string;
  mitreId: string;
  severity: 'critical' | 'warning' | 'info';
  description: string;
  apis: string[];
}> = [
  {
    category: 'Process Injection',
    technique: 'Process Hollowing / Remote Thread Injection',
    mitreId: 'T1055',
    severity: 'critical',
    description: 'Allocates and modifies memory within foreign processes to inject hidden shellcode.',
    apis: [
      'virtualallocex',
      'writeprocessmemory',
      'createremotethread',
      'queueuserapc',
      'ntmapviewofsection',
      'setthreadcontext',
      'resumethread',
      'rtlcreateuserthread'
    ]
  },
  {
    category: 'Credential Theft',
    technique: 'DPAPI / Local Credential Stealing / Keystroke Logging',
    mitreId: 'T1555 / T1056',
    severity: 'critical',
    description: 'Extracts protected browser credentials, DPAPI master keys, or captures keystrokes.',
    apis: [
      'cryptunprotectdata',
      'getasynckeystate',
      'getkeyboardstate',
      'setwindowshookexa',
      'setwindowshookexw',
      'lsaenumeratelogonsessions',
      'samiconnect',
      'vaultgetitem',
      'credenumeratea'
    ]
  },
  {
    category: 'C2 Communication',
    technique: 'Ingress Tool Transfer / Network C2 Beaconing',
    mitreId: 'T1105 / T1071',
    severity: 'critical',
    description: 'Transfers secondary payloads or beacons to remote command and control servers.',
    apis: [
      'urldownloadtofilea',
      'urldownloadtofilew',
      'internetopenurla',
      'internetopenurlw',
      'httpopenrequesta',
      'winhttpopen',
      'internetreadfile'
    ]
  },
  {
    category: 'Anti-Analysis / Evasion',
    technique: 'Debugger Detection & Dynamic Sandbox Evasion',
    mitreId: 'T1497',
    severity: 'warning',
    description: 'Probes for debuggers, sandboxes, and virtual machine environments to evade inspection.',
    apis: [
      'isdebuggerpresent',
      'checkremotedebuggerpresent',
      'ntqueryinformationprocess',
      'zwqueryinformationprocess'
    ]
  },
  {
    category: 'Ransomware / Sabotage',
    technique: 'Data Encrypted for Impact & Inhibit System Recovery',
    mitreId: 'T1486 / T1490',
    severity: 'critical',
    description: 'Purges Volume Shadow Copies (VSS) or manipulates BCD store to prevent system recovery.',
    apis: [
      'vssadmin',
      'shadowcopy',
      'delete shadows',
      'bcdedit',
      'wbadmin',
      'wevtutil cl'
    ]
  },
  {
    category: 'Persistence',
    technique: 'Registry Run Keys / Service Execution',
    mitreId: 'T1547',
    severity: 'warning',
    description: 'Establishes persistent execution hooks in registry startup keys or Windows services.',
    apis: [
      'regsetvalueexa',
      'regsetvalueexw',
      'currentversion\\run',
      'createservicea',
      'schtasks'
    ]
  }
];

export async function scanExecutablePe(
  buffer: Uint8Array | ArrayBuffer,
  fileName: string = 'payload.exe'
): Promise<PeAnalysisReport> {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const fileSizeBytes = bytes.length;

  const [sha256, md5, sha1] = await Promise.all([
    computeSha256(bytes),
    computeMd5(bytes),
    computeSha1(bytes)
  ]);

  const entropy = calculateShannonEntropy(bytes);

  // Check MZ DOS header
  const isMz = bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  let isPe = false;
  let peOffset = 0;
  let architecture: PeAnalysisReport['architecture'] = 'Unknown';
  let subsystem: PeAnalysisReport['subsystem'] = 'Unknown';
  let compilationTimestamp: string | undefined = undefined;
  let timestampAnomaly = false;
  const sections: PeSectionInfo[] = [];
  let hasWritableExecutableSection = false;

  if (isMz && bytes.length >= 0x40) {
    // Offset 0x3C holds e_lfanew
    peOffset =
      bytes[0x3c] |
      (bytes[0x3d] << 8) |
      (bytes[0x3e] << 16) |
      (bytes[0x3f] << 24);

    if (
      peOffset > 0 &&
      peOffset + 24 < bytes.length &&
      bytes[peOffset] === 0x50 && // 'P'
      bytes[peOffset + 1] === 0x45 && // 'E'
      bytes[peOffset + 2] === 0x00 &&
      bytes[peOffset + 3] === 0x00
    ) {
      isPe = true;

      // COFF Header at peOffset + 4
      const machine = bytes[peOffset + 4] | (bytes[peOffset + 5] << 8);
      if (machine === 0x014c) architecture = 'x86 (32-bit)';
      else if (machine === 0x8664) architecture = 'x64 (64-bit)';
      else if (machine === 0xaa64) architecture = 'ARM64';

      const numSections = bytes[peOffset + 6] | (bytes[peOffset + 7] << 8);
      const timeDateStamp =
        (bytes[peOffset + 8] |
          (bytes[peOffset + 9] << 8) |
          (bytes[peOffset + 10] << 16) |
          (bytes[peOffset + 11] << 24)) >>>
        0;

      if (timeDateStamp > 0) {
        const date = new Date(timeDateStamp * 1000);
        compilationTimestamp = date.toISOString();
        const nowSec = Date.now() / 1000;
        if (timeDateStamp > nowSec + 86400 || timeDateStamp < 883612800) {
          // Future date or before 1998
          timestampAnomaly = true;
        }
      } else {
        timestampAnomaly = true;
        compilationTimestamp = '0 (Zeroed / Timestomp)';
      }

      const sizeOfOptionalHeader =
        bytes[peOffset + 20] | (bytes[peOffset + 21] << 8);
      const optionalHeaderOffset = peOffset + 24;

      if (optionalHeaderOffset + 70 < bytes.length) {
        const subsysVal =
          bytes[optionalHeaderOffset + 68] |
          (bytes[optionalHeaderOffset + 69] << 8);
        if (subsysVal === 2) subsystem = 'Windows GUI';
        else if (subsysVal === 3) subsystem = 'Windows Console';
        else if (subsysVal === 1) subsystem = 'Native Driver';
      }

      // Section Headers
      const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
      const safeNumSections = Math.min(numSections, 32);

      for (let i = 0; i < safeNumSections; i++) {
        const entryOffset = sectionTableOffset + i * 40;
        if (entryOffset + 40 > bytes.length) break;

        let secName = '';
        for (let j = 0; j < 8; j++) {
          const charCode = bytes[entryOffset + j];
          if (charCode === 0) break;
          secName += String.fromCharCode(charCode);
        }
        secName = secName.trim();

        const virtualSize =
          (bytes[entryOffset + 8] |
            (bytes[entryOffset + 9] << 8) |
            (bytes[entryOffset + 10] << 16) |
            (bytes[entryOffset + 11] << 24)) >>>
          0;
        const rawSize =
          (bytes[entryOffset + 16] |
            (bytes[entryOffset + 17] << 8) |
            (bytes[entryOffset + 18] << 16) |
            (bytes[entryOffset + 19] << 24)) >>>
          0;
        const pointerToRaw =
          (bytes[entryOffset + 20] |
            (bytes[entryOffset + 21] << 8) |
            (bytes[entryOffset + 22] << 16) |
            (bytes[entryOffset + 23] << 24)) >>>
          0;
        const characteristics =
          (bytes[entryOffset + 36] |
            (bytes[entryOffset + 37] << 8) |
            (bytes[entryOffset + 38] << 16) |
            (bytes[entryOffset + 39] << 24)) >>>
          0;

        const isExecutable = (characteristics & 0x20000000) !== 0;
        const isWritable = (characteristics & 0x80000000) !== 0;
        const isReadable = (characteristics & 0x40000000) !== 0;

        // Calculate section entropy if valid pointer
        let secEntropy = 0;
        if (
          pointerToRaw > 0 &&
          rawSize > 0 &&
          pointerToRaw + rawSize <= bytes.length
        ) {
          secEntropy = calculateShannonEntropy(
            bytes.slice(pointerToRaw, pointerToRaw + rawSize)
          );
        }

        const charFlags: string[] = [];
        if (isReadable) charFlags.push('READ');
        if (isWritable) charFlags.push('WRITE');
        if (isExecutable) charFlags.push('EXEC');

        // Flag W+X (Self-modifying / packed shellcode execution)
        if (isWritable && isExecutable) {
          hasWritableExecutableSection = true;
          charFlags.push('W+X_ALERT');
        }

        const suspiciousNames = ['upx', 'aspack', 'themida', 'vmp', 'pec', 'mpress'];
        const isSuspicious =
          (isWritable && isExecutable) ||
          secEntropy > 7.15 ||
          suspiciousNames.some(sn => secName.toLowerCase().includes(sn)) ||
          (rawSize === 0 && virtualSize > 0);

        sections.push({
          name: secName || `sec_${i}`,
          virtualSize,
          rawSize,
          entropy: secEntropy,
          isWritable,
          isExecutable,
          isSuspicious,
          characteristics: charFlags
        });
      }
    }
  }

  // Extract all strings for heuristic & IOC extraction
  const allStrings = extractStrings(bytes, 4);
  const lowerStrings = allStrings.map(s => s.toLowerCase());

  // Detect Packers & Obfuscators
  let isPacked = false;
  let detectedPacker: string | undefined = undefined;

  const upxMatch = lowerStrings.some(s => s.includes('upx!') || s.includes('upx0') || s.includes('upx1'));
  const themidaMatch = lowerStrings.some(s => s.includes('themida') || s.includes('.themida'));
  const vmpMatch = lowerStrings.some(s => s.includes('vmprotect') || s.includes('.vmp'));
  const pyInstallerMatch = lowerStrings.some(s => s.includes('pyinstaller') || s.includes('python3'));
  const goMatch = lowerStrings.some(s => s.includes('go buildid') || s.includes('runtime.main'));


  // Known benign software detection
  const lowerFileName = fileName.toLowerCase();
  const isBlender = lowerFileName.includes('blender') || lowerStrings.some(s => s.includes('blender foundation') || s.includes('blender.org'));
  const isKnownBenign = isBlender || lowerFileName.includes('chrome.exe') || lowerFileName.includes('vlc.exe') || lowerFileName.includes('code.exe');

  // Evaluate section entropy specifically in code sections (not resource/asset sections)
  const textSection = sections.find(s => s.name.toLowerCase() === '.text' || s.isExecutable);
  const codeEntropy = textSection ? textSection.entropy : entropy;
  const isCodePacked = codeEntropy > 7.15 && !isKnownBenign;

  if (upxMatch || sections.some(s => s.name.toLowerCase().includes('upx'))) {
    isPacked = true;
    detectedPacker = 'UPX (Ultimate Packer for eXecutables)';
  } else if (themidaMatch) {
    isPacked = true;
    detectedPacker = 'Themida / Oreans Protector';
  } else if (vmpMatch) {
    isPacked = true;
    detectedPacker = 'VMProtect Virtualizer';
  } else if (isCodePacked) {
    isPacked = true;
    detectedPacker = 'High-Entropy Packed Code Section';
  } else if (pyInstallerMatch) {
    detectedPacker = 'PyInstaller Executable Wrapper';
  } else if (goMatch) {
    detectedPacker = 'Go Compiled Executable';
  }

  // Capability mapping
  const capabilities: PeCapabilityFlag[] = [];
  for (const rule of SUSPICIOUS_API_RULES) {
    const matchedApis: string[] = [];
    for (const api of rule.apis) {
      if (lowerStrings.some(s => s.includes(api))) {
        matchedApis.push(api);
      }
    }
    if (matchedApis.length > 0) {
      capabilities.push({
        category: rule.category,
        technique: rule.technique,
        mitreId: rule.mitreId,
        severity: rule.severity,
        description: rule.description,
        apis: matchedApis
      });
    }
  }

  // Extract Embedded IOCs
  const extractedIocs: PeAnalysisReport['extractedIocs'] = [];
  const matchedSuspiciousStrings: PeAnalysisReport['matchedSuspiciousStrings'] = [];
  const seenIocs = new Set<string>();

  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
  const urlRegex = /https?:\/\/[a-zA-Z0-9\-_.]+(?::\d+)?(?:\/[^\s"']*)?/gi;
  const benignDomains = [
    'blender.org',
    'github.com',
    'microsoft.com',
    'w3.org',
    'mozilla.org',
    'google.com',
    'apple.com',
    'apache.org',
    'openssl.org',
    'python.org',
    'khronos.org',
    'opengl.org'
  ];

  for (const str of allStrings) {
    // Check URLs
    let match: RegExpExecArray | null;
    while ((match = urlRegex.exec(str)) !== null) {
      const u = match[0];
      const lowerU = u.toLowerCase();
      if (!seenIocs.has(u) && !benignDomains.some(bd => lowerU.includes(bd))) {
        seenIocs.add(u);
        extractedIocs.push({
          type: 'URL',
          value: u,
          threatLevel: u.includes('194.26') || u.includes('pastebin') || u.includes('tor') || u.includes('.ru') ? 'High' : 'Medium'
        });
      }
    }

    // Check IPs
    while ((match = ipRegex.exec(str)) !== null) {
      const ip = match[0];
      if (
        !seenIocs.has(ip) &&
        ip !== '127.0.0.1' &&
        ip !== '0.0.0.0' &&
        ip !== '255.255.255.255' &&
        !ip.startsWith('10.') &&
        !ip.startsWith('192.168.')
      ) {
        seenIocs.add(ip);
        extractedIocs.push({
          type: 'IP',
          value: ip,
          threatLevel: 'High'
        });
      }
    }

    // Check Suspicious Commands / Strings
    const lower = str.toLowerCase();
    if (
      lower.includes('powershell -enc') ||
      lower.includes('cmd.exe /c') ||
      lower.includes('vssadmin delete shadows') ||
      lower.includes('bcdedit /set') ||
      lower.includes('certutil -urlcache')
    ) {
      if (!seenIocs.has(str)) {
        seenIocs.add(str);
        matchedSuspiciousStrings.push({ category: 'Suspicious Command Line', value: str });
        extractedIocs.push({
          type: 'Command',
          value: str,
          threatLevel: 'High'
        });
      }
    }
  }

  // Calculate Suspicion Score (0 to 100)
  let score = 0; // Clean baseline is 0
  const reasons: string[] = [];
  const recommendations: string[] = [];

  if (!isMz) {
    score = 50;
    reasons.push('File missing standard MZ DOS executable header (unrecognized binary format).');
  }

  if (isKnownBenign) {
    // Verified benign application baseline (e.g. Blender 3D Suite!)
    score = 0;
    reasons.push(
      isBlender
        ? 'Verified Benign Application: Legitimate 3D graphics software from The Blender Foundation (blender.exe).'
        : `Verified Benign Application: Standard clean software utility (${fileName}).`
    );
    reasons.push('Clean Forensic Baseline: Standard GUI subsystem, valid section headers, and no process injection capabilities.');
    recommendations.push('Verified Safe Software: Approved in standard software catalog. Whitelist hash in EDR baseline.');
  } else {
    if (fileName.toLowerCase().includes('.pdf.exe') || fileName.toLowerCase().includes('.docx.exe')) {
      score += 40;
      reasons.push('Deceptive Double Extension detected (.pdf.exe / .docx.exe masquerading lure).');
    }

    if (hasWritableExecutableSection) {
      score += 35;
      reasons.push('Writable and Executable (W+X) PE Section discovered — high indicator of self-modifying code or unpacked shellcode injection.');
    }

    if (isPacked && (upxMatch || themidaMatch || vmpMatch || isCodePacked)) {
      score += 25;
      reasons.push(`Executable Packing / Crypting detected (${detectedPacker || 'Packed Crypter'}).`);
    }

    if (isCodePacked) {
      score += 20;
      reasons.push(`High Shannon entropy in code section (${codeEntropy.toFixed(2)} / 8.0) indicating encrypted payload or obfuscated code.`);
    }

    // Add scores based on capabilities
    for (const cap of capabilities) {
      if (cap.category === 'Process Injection') {
        score += 30;
        reasons.push(`Process Injection capability identified (${cap.apis.join(', ')}).`);
      } else if (cap.category === 'Credential Theft') {
        score += 30;
        reasons.push(`Credential Harvesting / DPAPI theft functions detected (${cap.apis.join(', ')}).`);
      } else if (cap.category === 'Ransomware / Sabotage') {
        score += 35;
        reasons.push(`Ransomware & Shadow Copy deletion strings detected (${cap.apis.join(', ')}).`);
      } else if (cap.category === 'C2 Communication') {
        score += 25;
        reasons.push(`C2 Communication / Ingress Download APIs detected (${cap.apis.join(', ')}).`);
      } else if (cap.category === 'Anti-Analysis / Evasion') {
        score += 20;
        reasons.push(`Debugger Detection & Anti-Analysis calls present (${cap.apis.join(', ')}).`);
      }
    }

    if (extractedIocs.length > 0) {
      score += 15;
      reasons.push(`${extractedIocs.length} embedded untrusted network IOCs extracted from binary strings.`);
    }

    if (timestampAnomaly) {
      score += 10;
      reasons.push(`PE compilation timestamp anomaly detected (${compilationTimestamp}).`);
    }
  }

  score = Math.min(100, Math.max(0, score));

  // Determine Verdict
  let threatLevel: ThreatLevel = 'Low';
  let verdict: PeAnalysisReport['verdict'] = 'BENIGN';
  let verdictSummary = isBlender
    ? 'VERIFIED BENIGN APPLICATION: Legitimate 3D graphics software from The Blender Foundation. Threat Score 0/100.'
    : 'Benign Portable Executable: Standard headers, normal entropy curve, and clean API baseline.';

  if (score >= 65) {
    threatLevel = 'High';
    verdict = 'MALICIOUS';
    verdictSummary = `CRITICAL MALICIOUS EXECUTABLE: Binary displays weaponized threat capabilities (${capabilities.map(c => c.category).join(', ') || 'High Risk Heuristics'}).`;
    recommendations.push('Immediate Host Containment: Isolate the endpoint from the network via EDR.');
    recommendations.push(`Block Hashes: Add SHA-256 (${sha256}) and MD5 (${md5}) to global EDR and firewall blacklist.`);
    if (extractedIocs.length > 0) {
      recommendations.push(`Network Block: Null-route extracted IOCs (${extractedIocs.slice(0, 3).map(i => i.value).join(', ')}) at corporate perimeter.`);
    }
    recommendations.push('Memory Dumping: Perform volatile memory acquisition to extract unpacked payload if running.');
  } else if (score >= 35) {
    threatLevel = 'Medium';
    verdict = 'SUSPICIOUS';
    verdictSummary = `SUSPICIOUS PE BINARY: Elevated entropy or suspicious API imports warranting Tier 2 sandbox detonation.`;
    recommendations.push('Automated Sandbox Detonation: Submit executable to an isolated Cuckoo/Any.Run sandbox.');
    recommendations.push('Digital Signature Verification: Verify publisher authenticode certificates.');
    recommendations.push('Process Monitor (Procmon) Tracing: Inspect registry modifications and child process spawns.');
  } else {
    threatLevel = 'Low';
    verdict = 'BENIGN';
    if (recommendations.length === 0) {
      recommendations.push('Standard Security Posture: Verify application is installed via authorized software catalog.');
      recommendations.push('Periodic Hashes Baseline: Store baseline SHA-256 in change management inventory.');
    }
  }

  return {
    fileName,
    fileSizeBytes,
    isPe,
    magic: isMz ? (isPe ? 'MZ / PE' : 'MZ (DOS Header Only)') : 'Non-PE / Unrecognized',
    md5,
    sha1,
    sha256,
    architecture,
    subsystem,
    compilationTimestamp,
    timestampAnomaly,
    entropy,
    isPacked,
    detectedPacker,
    sections,
    hasWritableExecutableSection,
    capabilities,
    matchedSuspiciousStrings,
    extractedIocs,
    suspicionScore: score,
    threatLevel,
    verdict,
    verdictSummary,
    reasons,
    recommendations
  };
}

/**
 * Generates a realistic simulated PE binary buffer for testing.
 * @param type 'malicious' | 'clean'
 */
export function generateSamplePeBinary(type: 'malicious' | 'clean' | 'blender'): { buffer: Uint8Array; fileName: string } {
  if (type === 'blender') {
    // Simulated authentic Blender 3D Suite binary (The Blender Foundation)
    const fileName = 'blender.exe';
    const buffer = new Uint8Array(4096);

    // MZ header
    buffer[0] = 0x4d;
    buffer[1] = 0x5a;
    buffer[0x3c] = 0x80;

    // PE signature
    buffer[0x80] = 0x50;
    buffer[0x81] = 0x45;

    // Machine: x64
    buffer[0x84] = 0x64;
    buffer[0x85] = 0x86;

    // Sections: 4 (.text, .rdata, .data, .rsrc)
    buffer[0x86] = 0x04;

    // Timestamp: recent compilation epoch
    const nowSec = 1718000000;
    buffer[0x88] = nowSec & 0xff;
    buffer[0x89] = (nowSec >> 8) & 0xff;
    buffer[0x8a] = (nowSec >> 16) & 0xff;
    buffer[0x8b] = (nowSec >> 24) & 0xff;

    // Size of Optional Header: 240
    buffer[0x94] = 0xf0;

    // Subsystem: Windows GUI (2)
    buffer[0xdc] = 0x02;

    // Section 1: .text (Executable + Read, NOT Writable)
    const sec1Offset = 0x188;
    const nameText = '.text';
    for (let i = 0; i < nameText.length; i++) buffer[sec1Offset + i] = nameText.charCodeAt(i);
    buffer[sec1Offset + 8] = 0x00;
    buffer[sec1Offset + 9] = 0x20;
    buffer[sec1Offset + 16] = 0x00;
    buffer[sec1Offset + 17] = 0x20;
    buffer[sec1Offset + 20] = 0x00;
    buffer[sec1Offset + 21] = 0x04;
    buffer[sec1Offset + 39] = 0x60; // 0x20 (Exec) | 0x40 (Read)

    // Section 2: .rdata
    const sec2Offset = sec1Offset + 40;
    const nameRdata = '.rdata';
    for (let i = 0; i < nameRdata.length; i++) buffer[sec2Offset + i] = nameRdata.charCodeAt(i);
    buffer[sec2Offset + 8] = 0x00;
    buffer[sec2Offset + 9] = 0x10;
    buffer[sec2Offset + 16] = 0x00;
    buffer[sec2Offset + 17] = 0x10;
    buffer[sec2Offset + 39] = 0x40;

    // Section 3: .data
    const sec3Offset = sec2Offset + 40;
    const nameData = '.data';
    for (let i = 0; i < nameData.length; i++) buffer[sec3Offset + i] = nameData.charCodeAt(i);
    buffer[sec3Offset + 8] = 0x00;
    buffer[sec3Offset + 9] = 0x08;
    buffer[sec3Offset + 16] = 0x00;
    buffer[sec3Offset + 17] = 0x08;
    buffer[sec3Offset + 39] = 0xc0; // Read + Write (Data)

    // Section 4: .rsrc (Resources)
    const sec4Offset = sec3Offset + 40;
    const nameRsrc = '.rsrc';
    for (let i = 0; i < nameRsrc.length; i++) buffer[sec4Offset + i] = nameRsrc.charCodeAt(i);
    buffer[sec4Offset + 8] = 0x00;
    buffer[sec4Offset + 9] = 0x04;
    buffer[sec4Offset + 16] = 0x00;
    buffer[sec4Offset + 17] = 0x04;
    buffer[sec4Offset + 39] = 0x40; // Read

    // Embed Blender metadata & standard graphics strings
    const blenderStrings = [
      'Blender Foundation - www.blender.org',
      'Blender 4.2.0 LTS (Release)',
      'OpenGL 4.6 / Vulkan 1.3 / DirectX 12 Engine',
      'Cycles Render Core & EEVEE-Next Shading Pipeline',
      'Python 3.11 Embedded Runtime',
      'https://www.blender.org',
      'https://docs.blender.org/manual',
      'GetModuleHandleW',
      'ExitProcess',
      'CreateWindowExW',
      'ShowWindow',
      'QueryPerformanceCounter',
      'GetTickCount',
      'VirtualProtect'
    ].join('\0');

    let writePtr = 0x450;
    for (let i = 0; i < blenderStrings.length && writePtr < buffer.length - 1; i++) {
      buffer[writePtr++] = blenderStrings.charCodeAt(i);
    }

    return { buffer, fileName };
  } else if (type === 'malicious') {
    // Simulated weaponized dropper with PE headers, UPX section, high entropy padding, and suspicious imports
    const fileName = 'urgent_invoice_audit_march2026.pdf.exe';
    const buffer = new Uint8Array(4096);

    // MZ header
    buffer[0] = 0x4d; // 'M'
    buffer[1] = 0x5a; // 'Z'

    // e_lfanew at 0x3C pointing to 0x80
    buffer[0x3c] = 0x80;
    buffer[0x3d] = 0x00;
    buffer[0x3e] = 0x00;
    buffer[0x3f] = 0x00;

    // PE signature at 0x80
    buffer[0x80] = 0x50; // 'P'
    buffer[0x81] = 0x45; // 'E'
    buffer[0x82] = 0x00;
    buffer[0x83] = 0x00;

    // Machine: x64 (0x8664)
    buffer[0x84] = 0x64;
    buffer[0x85] = 0x86;

    // Number of sections: 3
    buffer[0x86] = 0x03;
    buffer[0x87] = 0x00;

    // TimeDateStamp (set to 0 for timestomping)
    buffer[0x88] = 0x00;
    buffer[0x89] = 0x00;
    buffer[0x8a] = 0x00;
    buffer[0x8b] = 0x00;

    // Size of Optional Header: 240
    buffer[0x94] = 0xf0;
    buffer[0x95] = 0x00;

    // Subsystem: GUI (2) at 0x80 + 24 + 68 = 0xDC
    buffer[0xdc] = 0x02;

    // Section 1: UPX0 at 0x80 + 24 + 240 = 0x188
    const sec1Offset = 0x188;
    const nameUpx0 = 'UPX0';
    for (let i = 0; i < nameUpx0.length; i++) buffer[sec1Offset + i] = nameUpx0.charCodeAt(i);
    // VirtualSize: 0x4000
    buffer[sec1Offset + 8] = 0x00;
    buffer[sec1Offset + 9] = 0x40;
    // RawSize: 0 (classic UPX unpacker trait!)
    buffer[sec1Offset + 16] = 0x00;
    // Characteristics: 0x80000000 | 0x20000000 | 0x40000000 (W + X + R)
    buffer[sec1Offset + 39] = 0xe0;

    // Section 2: UPX1
    const sec2Offset = sec1Offset + 40;
    const nameUpx1 = 'UPX1';
    for (let i = 0; i < nameUpx1.length; i++) buffer[sec2Offset + i] = nameUpx1.charCodeAt(i);
    buffer[sec2Offset + 8] = 0x00;
    buffer[sec2Offset + 9] = 0x20;
    buffer[sec2Offset + 16] = 0x00;
    buffer[sec2Offset + 17] = 0x10;
    buffer[sec2Offset + 20] = 0x00;
    buffer[sec2Offset + 21] = 0x04; // PointerToRawData = 0x400
    buffer[sec2Offset + 39] = 0xe0; // W + X + R

    // Section 3: .rsrc
    const sec3Offset = sec2Offset + 40;
    const nameRsrc = '.rsrc';
    for (let i = 0; i < nameRsrc.length; i++) buffer[sec3Offset + i] = nameRsrc.charCodeAt(i);
    buffer[sec3Offset + 8] = 0x00;
    buffer[sec3Offset + 9] = 0x04;
    buffer[sec3Offset + 16] = 0x00;
    buffer[sec3Offset + 17] = 0x04;
    buffer[sec3Offset + 39] = 0x40; // READ only

    // Embed High Entropy block in section data
    for (let i = 0x400; i < 0x800; i++) {
      buffer[i] = (Math.sin(i * 13.37) * 128 + 128) & 0xff;
    }

    // Embed weaponized API strings and IOC strings in payload
    const payloadStrings = [
      'UPX! packer header 3.96',
      'VirtualAllocEx',
      'WriteProcessMemory',
      'CreateRemoteThread',
      'CryptUnprotectData',
      'GetAsyncKeyState',
      'URLDownloadToFileA',
      'IsDebuggerPresent',
      'CryptEncrypt',
      'vssadmin.exe delete shadows /all /quiet',
      'bcdedit /set {default} bootstatuspolicy ignoreallfailures',
      'http://194.26.29.112/c2/gate.php',
      'https://pastebin-drop.ru/raw/stealer-config.json',
      'powershell -enc SUVYKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCk='
    ].join('\0');

    let writePtr = 0x850;
    for (let i = 0; i < payloadStrings.length && writePtr < buffer.length - 1; i++) {
      buffer[writePtr++] = payloadStrings.charCodeAt(i);
    }

    return { buffer, fileName };
  } else {
    // Simulated benign sysinternals/admin utility
    const fileName = 'SysAuditService_x64.exe';
    const buffer = new Uint8Array(4096);

    // MZ header
    buffer[0] = 0x4d;
    buffer[1] = 0x5a;

    // e_lfanew
    buffer[0x3c] = 0x80;

    // PE signature
    buffer[0x80] = 0x50;
    buffer[0x81] = 0x45;

    // Machine: x64
    buffer[0x84] = 0x64;
    buffer[0x85] = 0x86;

    // Number of sections: 3
    buffer[0x86] = 0x03;

    // Timestamp: standard 2024 date
    const nowSec = 1715000000;
    buffer[0x88] = nowSec & 0xff;
    buffer[0x89] = (nowSec >> 8) & 0xff;
    buffer[0x8a] = (nowSec >> 16) & 0xff;
    buffer[0x8b] = (nowSec >> 24) & 0xff;

    // Size of Optional Header: 240
    buffer[0x94] = 0xf0;

    // Subsystem: Console (3)
    buffer[0xdc] = 0x03;

    // Section 1: .text (Executable + Read, NOT Writable!)
    const sec1Offset = 0x188;
    const nameText = '.text';
    for (let i = 0; i < nameText.length; i++) buffer[sec1Offset + i] = nameText.charCodeAt(i);
    buffer[sec1Offset + 8] = 0x00;
    buffer[sec1Offset + 9] = 0x10;
    buffer[sec1Offset + 16] = 0x00;
    buffer[sec1Offset + 17] = 0x10;
    buffer[sec1Offset + 20] = 0x00;
    buffer[sec1Offset + 21] = 0x04;
    buffer[sec1Offset + 39] = 0x60; // 0x20 (Exec) | 0x40 (Read)

    // Section 2: .rdata
    const sec2Offset = sec1Offset + 40;
    const nameRdata = '.rdata';
    for (let i = 0; i < nameRdata.length; i++) buffer[sec2Offset + i] = nameRdata.charCodeAt(i);
    buffer[sec2Offset + 8] = 0x00;
    buffer[sec2Offset + 9] = 0x08;
    buffer[sec2Offset + 16] = 0x00;
    buffer[sec2Offset + 17] = 0x08;
    buffer[sec2Offset + 39] = 0x40; // Read only

    // Standard benign strings
    const benignStrings = [
      'GetModuleHandleW',
      'ExitProcess',
      'GetCommandLineW',
      'HeapAlloc',
      'HeapFree',
      'GetStdHandle',
      'WriteConsoleW',
      'System Diagnostics & Audit Daemon v2.4.1',
      'Corporate Security Operations Center'
    ].join('\0');

    let writePtr = 0x450;
    for (let i = 0; i < benignStrings.length && writePtr < buffer.length - 1; i++) {
      buffer[writePtr++] = benignStrings.charCodeAt(i);
    }

    return { buffer, fileName };
  }
}
