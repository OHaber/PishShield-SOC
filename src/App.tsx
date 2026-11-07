import React, { useState, useEffect, useCallback } from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Globe,
  UploadCloud,
  History,
  Terminal,
  Cpu,
  Wrench
} from 'lucide-react';
import { Header } from './components/Header';
import { DashboardTab } from './components/DashboardTab';
import { AnalyzerTab } from './components/AnalyzerTab';
import { UrlScannerTab } from './components/UrlScannerTab';
import { BatchTab } from './components/BatchTab';
import { HistoryTab } from './components/HistoryTab';
import { SocToolsTab } from './components/SocToolsTab';
import { AuditDrawer } from './components/AuditDrawer';
import {
  DashboardStats,
  ScanLog,
  PhishingAnalysisResult,
  UrlScanResult,
  BatchUploadResponse
} from './types';
import {
  INITIAL_LOGS,
  computeDashboardStats,
  analyzePhishingContent,
  scanUrlReputation,
  parseBatchData,
  parseZipArchive,
  scanExecutablePe,
  scanWindowsShortcutLnk,
  isWindowsShortcutBuffer
} from './threatEngine';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('tab-dashboard');
  const [apiBase, setApiBase] = useState<string>('/api');
  const [backendConnected, setBackendConnected] = useState<boolean>(true);

  // Core state
  const [logs, setLogs] = useState<ScanLog[]>(INITIAL_LOGS);
  const [stats, setStats] = useState<DashboardStats>(() => computeDashboardStats(INITIAL_LOGS));
  const [lastAnalysis, setLastAnalysis] = useState<PhishingAnalysisResult | null>(null);
  const [historyFilterRisk, setHistoryFilterRisk] = useState<string>('all');
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [selectedAuditLog, setSelectedAuditLog] = useState<ScanLog | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(false);
  const [pivotUrl, setPivotUrl] = useState<string>('');

  // 1. Load Dashboard Stats (Stable callback - no circular logs dependency)
  const loadDashboardStats = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/dashboard/stats`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setStats(data);
      setBackendConnected(true);
    } catch (err) {
      console.warn('Backend offline or unreachable, using local fallback state.', err);
      setBackendConnected(false);
      setLogs((currentLogs) => {
        setStats(computeDashboardStats(currentLogs));
        return currentLogs;
      });
    }
  }, [apiBase]);

  // 2. Load History (Fetches all master logs; filtering is instant & non-destructive)
  const loadScanHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await fetch(`${apiBase}/history?page=1&risk=all`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.logs && Array.isArray(data.logs)) {
        setLogs(data.logs);
        setStats(computeDashboardStats(data.logs));
      }
      setBackendConnected(true);
    } catch (err) {
      console.warn('Failed to load history from backend, keeping local memory logs.', err);
      setBackendConnected(false);
    } finally {
      setHistoryLoading(false);
    }
  }, [apiBase]);

  // Initial load once on mount or when apiBase changes
  useEffect(() => {
    loadDashboardStats();
    loadScanHistory();
  }, [apiBase, loadDashboardStats, loadScanHistory]);

  // Expose global window.viewJsonAudit for complete compatibility with user's snippet
  useEffect(() => {
    (window as any).viewJsonAudit = (logData: ScanLog) => {
      setSelectedAuditLog(logData);
      setIsDrawerOpen(true);
    };
    return () => {
      delete (window as any).viewJsonAudit;
    };
  }, []);

  // Handle Tab Switch
  const handleTabChange = (tabId: string) => {
    setActiveTab(tabId);
    if (tabId === 'tab-dashboard') loadDashboardStats();
    if (tabId === 'tab-history') loadScanHistory();
  };

  // Analyze Email
  const handleAnalyzeEmail = async (content: string): Promise<PhishingAnalysisResult> => {
    try {
      const res = await fetch(`${apiBase}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });

      if (!res.ok) {
        throw new Error(`Server returned ${res.status}`);
      }

      const data: PhishingAnalysisResult = await res.json();
      setBackendConnected(true);
      setLastAnalysis(data);

      // Prepend to local logs and recompute stats
      const newLog: ScanLog = { ...data, scanDate: data.timestamp };
      setLogs((prev) => [newLog, ...prev]);
      setStats((prev) => {
        const updatedLogs = [newLog, ...logs];
        return computeDashboardStats(updatedLogs);
      });

      return data;
    } catch (err) {
      console.warn('API analyze request failed, executing client-side threat heuristic engine...', err);
      setBackendConnected(false);

      // Client-side fallback heuristic
      const localResult = analyzePhishingContent(content);
      const newLog: ScanLog = { ...localResult, scanDate: localResult.timestamp };
      setLastAnalysis(localResult);
      setLogs((prev) => [newLog, ...prev]);
      setStats((prev) => computeDashboardStats([newLog, ...logs]));
      return localResult;
    }
  };

  // URL / IP Reputation Scan
  const handleScanUrl = async (url: string): Promise<UrlScanResult> => {
    try {
      const res = await fetch(`${apiBase}/url/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: UrlScanResult = await res.json();
      setBackendConnected(true);
      return data;
    } catch (err) {
      console.warn('URL scan endpoint error, falling back to local database.', err);
      setBackendConnected(false);
      return scanUrlReputation(url);
    }
  };

  // Batch Upload with ZIP Archive & File Triage
  const handleBatchUpload = async (file?: File, textContent?: string): Promise<BatchUploadResponse> => {
    // If it's a ZIP file, we can also parse client-side directly or send to server
    const isZip = file && (
      file.name.toLowerCase().endsWith('.zip') ||
      file.type.includes('zip') ||
      file.type === 'application/x-zip-compressed'
    );

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

      let data: BatchUploadResponse;
      if (file) {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch(`${apiBase}/batch/upload`, {
          method: 'POST',
          body: formData,
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        data = await res.json();
      } else {
        const res = await fetch(`${apiBase}/batch/upload`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: textContent }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        data = await res.json();
      }
      setBackendConnected(true);
      return data;
    } catch (err: any) {
      console.warn('Batch upload endpoint error or timeout, running high-speed local engine...', err);
      setBackendConnected(false);

      if (file && isZip) {
        // Parse ZIP directly in browser using JSZip
        const arrayBuffer = await file.arrayBuffer();
        const items = await parseZipArchive(arrayBuffer, file.name);
        return {
          filename: file.name,
          totalParsed: items.length,
          threatsCount: items.filter((i) => i.isMalicious).length,
          items
        };
      }

      const isLnk =
        file &&
        (file.name.toLowerCase().endsWith('.lnk') ||
          (file.type === 'application/x-ms-shortcut'));

      if (file && isLnk) {
        const arrayBuffer = await file.arrayBuffer();
        const lnkReport = await scanWindowsShortcutLnk(arrayBuffer, file.name);
        const items = [
          {
            indicatorValue: `${file.name} -> ${lnkReport.targetPath}`,
            isMalicious: lnkReport.verdict === 'MALICIOUS',
            threatType: lnkReport.verdictSummary,
            enginesDetected: lnkReport.verdict === 'MALICIOUS' ? 79 : 0,
            confidence: lnkReport.suspicionScore
          }
        ];

        if (lnkReport.isLolbin) {
          items.push({
            indicatorValue: `LOLBin: ${lnkReport.lolbinDetected}`,
            isMalicious: true,
            threatType: 'Living Off The Land Binary Execution Proxy',
            enginesDetected: 82,
            confidence: 96
          });
        }

        if (lnkReport.commandArguments) {
          items.push({
            indicatorValue: `Arguments: ${lnkReport.commandArguments}`,
            isMalicious: lnkReport.hasObfuscatedArgs || lnkReport.hasDownloadCradle,
            threatType: lnkReport.hasObfuscatedArgs ? 'Obfuscated Command-Line / PowerShell Base64' : 'Command-Line Parameters',
            enginesDetected: lnkReport.hasObfuscatedArgs ? 85 : 0,
            confidence: 94
          });
        }

        return {
          filename: file.name,
          totalParsed: items.length,
          threatsCount: items.filter((i) => i.isMalicious).length,
          items,
          lnkAnalysis: lnkReport
        };
      }

      const isExe =
        file &&
        (file.name.toLowerCase().endsWith('.exe') ||
          file.name.toLowerCase().endsWith('.dll') ||
          file.name.toLowerCase().endsWith('.bin') ||
          file.name.toLowerCase().endsWith('.scr'));

      if (file && isExe) {
        const arrayBuffer = await file.arrayBuffer();
        const peReport = await scanExecutablePe(arrayBuffer, file.name);
        const items = [
          {
            indicatorValue: `${file.name} [PE binary - ${peReport.architecture}]`,
            isMalicious: peReport.verdict === 'MALICIOUS',
            threatType: peReport.verdictSummary,
            enginesDetected: peReport.verdict === 'MALICIOUS' ? 76 : (peReport.verdict === 'SUSPICIOUS' ? 42 : 0),
            confidence: peReport.suspicionScore
          },
          {
            indicatorValue: `Entropy: ${peReport.entropy} / 8.0 [${peReport.isPacked ? (peReport.detectedPacker || 'Packed Crypter') : 'Standard Distribution'}]`,
            isMalicious: peReport.isPacked || peReport.entropy >= 7.15,
            threatType: peReport.isPacked ? `Packed Binary Evasion (${peReport.detectedPacker || 'High Entropy Obfuscation'})` : 'Standard Binary Code Density',
            enginesDetected: peReport.isPacked ? 71 : 0,
            confidence: 95
          }
        ];

        if (peReport.hasWritableExecutableSection) {
          items.push({
            indicatorValue: `${file.name}: W+X Section Detected`,
            isMalicious: true,
            threatType: 'Writable & Executable Memory Section (Self-Modifying Shellcode Alert)',
            enginesDetected: 84,
            confidence: 99
          });
        }

        for (const cap of peReport.capabilities) {
          items.push({
            indicatorValue: `Capability: ${cap.category} [${cap.mitreId}]`,
            isMalicious: cap.severity === 'critical',
            threatType: `${cap.technique} (Imports: ${cap.apis.slice(0, 4).join(', ')})`,
            enginesDetected: cap.severity === 'critical' ? 79 : 45,
            confidence: 92
          });
        }

        for (const ioc of peReport.extractedIocs) {
          items.push({
            indicatorValue: `IOC: ${ioc.value} (${ioc.type})`,
            isMalicious: ioc.threatLevel === 'High',
            threatType: `Extracted String Artifact [${ioc.type}]`,
            enginesDetected: ioc.threatLevel === 'High' ? 68 : 12,
            confidence: 90
          });
        }

        return {
          filename: file.name,
          totalParsed: items.length,
          threatsCount: items.filter((i) => i.isMalicious).length,
          items,
          peAnalysis: peReport
        };
      }

      let contentToParse = textContent || '';
      if (file) {
        contentToParse = await file.text();
      }
      const items = parseBatchData(contentToParse);
      return {
        filename: file?.name || 'batch-input.txt',
        totalParsed: items.length,
        threatsCount: items.filter((i) => i.isMalicious).length,
        items
      };
    }
  };

  // Filter risk in History (instantaneous, zero-lag local filter)
  const handleFilterRiskChange = (risk: string) => {
    setHistoryFilterRisk(risk);
  };

  // Open JSON Audit Drawer
  const openAuditDrawer = (log: ScanLog) => {
    setSelectedAuditLog(log);
    setIsDrawerOpen(true);
  };

  // Drilldown from Dashboard Alert
  const handleInspectAlert = (alertId: number) => {
    const found = logs.find((l) => l.id === alertId);
    if (found) {
      openAuditDrawer(found);
    } else {
      setActiveTab('tab-history');
    }
  };

  // Pivot from IOC table to URL Scanner
  const handlePivotToUrlScanner = (target: string) => {
    setPivotUrl(target);
    setActiveTab('tab-url');
  };

  return (
    <div className="min-h-screen bg-[#0e121a] text-[#f8fafc] flex flex-col selection:bg-[#2563eb]/30 selection:text-white">
      {/* Top SOC Navigation Header */}
      <Header
        backendConnected={backendConnected}
        totalThreats={stats.highRisk}
        apiBase={apiBase}
        onUpdateApiBase={(newBase) => {
          setApiBase(newBase);
          setTimeout(() => {
            loadDashboardStats();
            loadScanHistory();
          }, 100);
        }}
        onRefreshAll={() => {
          loadDashboardStats();
          loadScanHistory();
        }}
      />

      {/* Main Tab Navigation Bar matching user specification buttons */}
      <nav className="border-b border-[#242e40] bg-[#111622] px-4 lg:px-8 py-2">
        <div className="max-w-7xl mx-auto flex items-center overflow-x-auto no-scrollbar gap-1.5">
          <button
            className={`tab-btn ${activeTab === 'tab-dashboard' ? 'active' : ''}`}
            data-tab="tab-dashboard"
            onClick={() => handleTabChange('tab-dashboard')}
          >
            <LayoutDashboard className="w-3.5 h-3.5 text-[#94a3b8]" />
            <span>Dashboard</span>
          </button>

          <button
            className={`tab-btn ${activeTab === 'tab-analyze' ? 'active' : ''}`}
            data-tab="tab-analyze"
            onClick={() => handleTabChange('tab-analyze')}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-[#fb7185]" />
            <span>Phishing Analyzer</span>
          </button>

          <button
            className={`tab-btn ${activeTab === 'tab-url' ? 'active' : ''}`}
            data-tab="tab-url"
            onClick={() => handleTabChange('tab-url')}
          >
            <Globe className="w-3.5 h-3.5 text-[#fbbf24]" />
            <span>URL / IP Reputation</span>
          </button>

          <button
            className={`tab-btn ${activeTab === 'tab-batch' ? 'active' : ''}`}
            data-tab="tab-batch"
            onClick={() => handleTabChange('tab-batch')}
          >
            <UploadCloud className="w-3.5 h-3.5 text-[#38bdf8]" />
            <span>Batch & EML Triage</span>
          </button>

          <button
            className={`tab-btn ${activeTab === 'tab-history' ? 'active' : ''}`}
            data-tab="tab-history"
            onClick={() => handleTabChange('tab-history')}
          >
            <History className="w-3.5 h-3.5 text-[#4ade80]" />
            <span>Audit History</span>
            {logs.length > 0 && (
              <span className="ml-1 text-[11px] font-mono text-[#64748b]">
                ({logs.length})
              </span>
            )}
          </button>

          <button
            className={`tab-btn ${activeTab === 'tab-tools' ? 'active' : ''}`}
            data-tab="tab-tools"
            onClick={() => handleTabChange('tab-tools')}
          >
            <Wrench className="w-3.5 h-3.5 text-[#38bdf8]" />
            <span>SOC Defense Toolkit</span>
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-8">
        {/* Tab 1: Dashboard */}
        <div
          id="tab-dashboard"
          className={`tab-pane ${activeTab === 'tab-dashboard' ? 'active block' : 'hidden'}`}
        >
          <DashboardTab
            stats={stats}
            onInspectAlert={handleInspectAlert}
            onNavigateToTab={handleTabChange}
          />
        </div>

        {/* Tab 2: Phishing Analysis */}
        <div
          id="tab-analyze"
          className={`tab-pane ${activeTab === 'tab-analyze' ? 'active block' : 'hidden'}`}
        >
          <AnalyzerTab
            onAnalyze={handleAnalyzeEmail}
            onInspectUrl={handlePivotToUrlScanner}
            lastAnalysis={lastAnalysis}
          />
        </div>

        {/* Tab 3: URL & IP Reputation */}
        <div
          id="tab-url"
          className={`tab-pane ${activeTab === 'tab-url' ? 'active block' : 'hidden'}`}
        >
          <UrlScannerTab
            onScanUrl={handleScanUrl}
            initialUrl={pivotUrl || 'http://194.26.29.112/confirm-login?id=99281'}
          />
        </div>

        {/* Tab 4: Batch & EML Upload */}
        <div
          id="tab-batch"
          className={`tab-pane ${activeTab === 'tab-batch' ? 'active block' : 'hidden'}`}
        >
          <BatchTab onBatchUpload={handleBatchUpload} />
        </div>

        {/* Tab 5: Scan History */}
        <div
          id="tab-history"
          className={`tab-pane ${activeTab === 'tab-history' ? 'active block' : 'hidden'}`}
        >
          <HistoryTab
            logs={logs}
            loading={historyLoading}
            filterRisk={historyFilterRisk}
            onFilterChange={handleFilterRiskChange}
            onRefresh={() => loadScanHistory()}
            onInspectJson={openAuditDrawer}
            onClearHistory={() => setLogs([])}
          />
        </div>

        {/* Tab 6: SOC Toolkit */}
        <div
          id="tab-tools"
          className={`tab-pane ${activeTab === 'tab-tools' ? 'active block' : 'hidden'}`}
        >
          <SocToolsTab />
        </div>
      </main>

      {/* JSON Audit Slide-over Drawer */}
      <AuditDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        selectedLog={selectedAuditLog}
      />
    </div>
  );
}
