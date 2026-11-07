export type ThreatLevel = 'Low' | 'Medium' | 'High';

export interface Indicator {
  indicatorType: 'IP' | 'URL' | 'Domain' | 'Email' | 'Hash' | 'Header';
  indicatorValue: string;
  context?: string;
  reputation?: 'Clean' | 'Suspicious' | 'Malicious';
}

export interface RuleViolation {
  rule: string;
  score: number;
  severity: 'info' | 'warning' | 'critical';
  explanation: string;
}

export interface ApiTelemetryRecord {
  id: string;
  service: string;
  endpoint: string;
  method: string;
  targetQueried: string;
  status: '200 OK' | '404 Clean' | 'Failed' | 'Warning' | 'Cached';
  statusCode: number;
  latencyMs: number;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'INFO';
  summary: string;
  rawResponse?: any;
}

export interface PhishingAnalysisResult {
  id: number;
  score: number;
  threatLevel: ThreatLevel;
  highlightKeywords: string[];
  indicators: Indicator[];
  headers?: Record<string, string>;
  rulesTriggered?: RuleViolation[];
  dnsLiveCheck?: {
    domain: string;
    spfFound: boolean;
    spfRecord?: string;
    dmarcFound: boolean;
    dmarcRecord?: string;
    mxFound?: boolean;
    mxRecords?: string[];
    dnsStatus: 'verified' | 'unprotected' | 'suspicious' | 'error';
    summary: string;
  };
  liveTelemetry?: ApiTelemetryRecord[];
  aiAnalysis?: {
    summary: string;
    attackVector: string;
    techniques: string[];
    recommendations: string[];
  };
  timestamp: string;
  rawContent?: string;
}

export interface UrlScanResult {
  target: string;
  source: string;
  threatCategory: string;
  enginesDetected: number;
  totalEngines: number;
  isMalicious: boolean;
  threatLevel: ThreatLevel;
  liveTelemetry?: ApiTelemetryRecord[];
  details?: {
    ip?: string;
    asn?: string;
    country?: string;
    city?: string;
    isp?: string;
    org?: string;
    sslStatus?: string;
    registrar?: string;
    domainAge?: string;
    domainCreated?: string;
    httpStatus?: number;
    httpServer?: string;
    finalDestinationUrl?: string;
    redirectCount?: number;
    responseTimeMs?: number;
    urlhausThreat?: string;
    urlhausStatus?: string;
    urlhausTags?: string[];
    openphishThreat?: string;
    isLiveFeed?: boolean;
    dnsSpfRecord?: string;
    dnsDmarcRecord?: string;
    dnsMxRecord?: string;
  };
}

export interface BatchItem {
  indicatorValue: string;
  isMalicious: boolean;
  threatType: string;
  enginesDetected?: number;
  confidence?: number;
}

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
  suspicionScore: number;
  threatLevel: ThreatLevel;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
  verdictSummary: string;
  reasons: string[];
  recommendations: string[];
}

export interface LnkAnalysisReport {
  fileName: string;
  fileSizeBytes: number;
  isLnk: boolean;
  headerClsid: string;
  targetPath: string;
  workingDirectory?: string;
  commandArguments?: string;
  iconLocation?: string;
  showCommand: string;
  isLolbin: boolean;
  lolbinDetected?: string;
  hasObfuscatedArgs: boolean;
  hasHiddenWindow: boolean;
  hasDownloadCradle: boolean;
  isKnownBenignApp: boolean;
  knownAppName?: string;
  suspicionScore: number;
  threatLevel: ThreatLevel;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
  verdictSummary: string;
  reasons: string[];
  recommendations: string[];
  extractedIocs: Array<{ type: 'IP' | 'URL' | 'Domain' | 'Command'; value: string; threatLevel?: ThreatLevel }>;
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
  };
}

export interface BatchUploadResponse {
  filename?: string;
  totalParsed: number;
  threatsCount: number;
  items: BatchItem[];
  peAnalysis?: PeAnalysisReport;
  lnkAnalysis?: LnkAnalysisReport;
}

export interface DashboardStats {
  totalScans: number;
  highRisk: number;
  blockedDomains: number;
  cleanScans: number;
  threatDistribution: Array<{
    threatLevel: ThreatLevel;
    count: number;
  }>;
  recentAlerts: Array<{
    id: number;
    score: number;
    threatLevel: ThreatLevel;
    timestamp: string;
    target?: string;
    summary?: string;
  }>;
}

export interface ScanLog extends PhishingAnalysisResult {
  scanDate: string;
}
