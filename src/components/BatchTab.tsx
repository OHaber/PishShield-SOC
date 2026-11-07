import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  Download,
  Play,
  FileArchive,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Binary,
  Copy,
  Check,
  Terminal,
  Cpu,
  FileCode,
  Bug,
  Lock,
  Layers,
  Network,
  Link2,
  FolderOpen,
  Sparkles
} from 'lucide-react';
import JSZip from 'jszip';
import { BatchItem, BatchUploadResponse, PeAnalysisReport, LnkAnalysisReport } from '../types';
import { generateSamplePeBinary } from '../peAnalysisEngine';
import { generateSampleLnk } from '../lnkAnalysisEngine';

interface BatchTabProps {
  onBatchUpload: (file?: File, textContent?: string) => Promise<BatchUploadResponse>;
}

export const BatchTab: React.FC<BatchTabProps> = ({ onBatchUpload }) => {
  const [isDragOver, setIsDragOver] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [showProgress, setShowProgress] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [batchItems, setBatchItems] = useState<BatchItem[]>([]);
  const [peReport, setPeReport] = useState<PeAnalysisReport | null>(null);
  const [lnkReport, setLnkReport] = useState<LnkAnalysisReport | null>(null);
  const [currentFile, setCurrentFile] = useState<string>('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const processFile = async (file: File) => {
    setShowProgress(true);
    setProgress(20);
    setLoading(true);
    setCurrentFile(file.name);
    setPeReport(null);
    setLnkReport(null);

    const progressInterval = setInterval(() => {
      setProgress((prev) => (prev < 85 ? prev + 12 : prev));
    }, 150);

    try {
      const res = await onBatchUpload(file);
      clearInterval(progressInterval);
      setProgress(100);
      setBatchItems(res.items);
      if (res.peAnalysis) {
        setPeReport(res.peAnalysis);
      }
      if (res.lnkAnalysis) {
        setLnkReport(res.lnkAnalysis);
      }
      setTimeout(() => setShowProgress(false), 500);
    } catch (err: any) {
      clearInterval(progressInterval);
      setProgress(100);
      setTimeout(() => setShowProgress(false), 500);
      alert(err.message || 'Batch upload failed.');
    } finally {
      clearInterval(progressInterval);
      setLoading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  // Test Blender Shortcut (.LNK) -> Demonstrates verified clean 0/100 score
  const loadSampleBlenderShortcut = async () => {
    setShowProgress(true);
    setProgress(25);
    setLoading(true);
    setPeReport(null);
    setLnkReport(null);

    try {
      const { buffer, fileName } = generateSampleLnk('blender');
      setCurrentFile(fileName);
      const file = new File([buffer as unknown as BlobPart], fileName, { type: 'application/x-ms-shortcut' });
      await processFile(file);
    } catch (err: any) {
      setShowProgress(false);
      setLoading(false);
      alert('Failed to generate sample blender shortcut: ' + err.message);
    }
  };

  // Test Weaponized Malicious Shortcut (.LNK) -> Demonstrates LOLBin / PowerShell detection
  const loadSampleMaliciousShortcut = async () => {
    setShowProgress(true);
    setProgress(25);
    setLoading(true);
    setPeReport(null);
    setLnkReport(null);

    try {
      const { buffer, fileName } = generateSampleLnk('malicious');
      setCurrentFile(fileName);
      const file = new File([buffer as unknown as BlobPart], fileName, { type: 'application/x-ms-shortcut' });
      await processFile(file);
    } catch (err: any) {
      setShowProgress(false);
      setLoading(false);
      alert('Failed to generate sample malicious shortcut: ' + err.message);
    }
  };

  // Test Blender Executable (.EXE)
  const loadSampleBlenderExe = async () => {
    setShowProgress(true);
    setProgress(25);
    setLoading(true);
    setPeReport(null);
    setLnkReport(null);

    try {
      const { buffer, fileName } = generateSamplePeBinary('blender');
      setCurrentFile(fileName);
      const file = new File([buffer as unknown as BlobPart], fileName, { type: 'application/x-msdownload' });
      await processFile(file);
    } catch (err: any) {
      setShowProgress(false);
      setLoading(false);
      alert('Failed to generate sample blender executable: ' + err.message);
    }
  };

  // Test Malicious Weaponized PE Executable
  const loadSampleMaliciousExe = async () => {
    setShowProgress(true);
    setProgress(25);
    setLoading(true);
    setPeReport(null);
    setLnkReport(null);

    try {
      const { buffer, fileName } = generateSamplePeBinary('malicious');
      setCurrentFile(fileName);
      const file = new File([buffer as unknown as BlobPart], fileName, { type: 'application/x-msdownload' });
      await processFile(file);
    } catch (err: any) {
      setShowProgress(false);
      setLoading(false);
      alert('Failed to generate sample malicious executable: ' + err.message);
    }
  };

  // Test Clean Benign Sysinternals / Utility Executable
  const loadSampleCleanExe = async () => {
    setShowProgress(true);
    setProgress(25);
    setLoading(true);
    setPeReport(null);
    setLnkReport(null);

    try {
      const { buffer, fileName } = generateSamplePeBinary('clean');
      setCurrentFile(fileName);
      const file = new File([buffer as unknown as BlobPart], fileName, { type: 'application/x-msdownload' });
      await processFile(file);
    } catch (err: any) {
      setShowProgress(false);
      setLoading(false);
      alert('Failed to generate sample clean executable: ' + err.message);
    }
  };

  const loadSampleBatch = async () => {
    setShowProgress(true);
    setProgress(35);
    setLoading(true);
    setPeReport(null);
    setCurrentFile('sample-incident-feed.csv');

    const sampleCsv = `indicatorValue,threatType
http://194.26.29.112/confirm-login?id=99281,Active Phish
login.micros0ft-verify.com,Credential Harvesting
https://google.com/search?q=cybersecurity,Safe Domain
alerts@paypal-account-center.com,Spoofed Mailer
https://github.com/torvalds/linux,Safe Repository
unknown-bulletproof-host.ru,Bulletproof Mailer
https://paypal.com/signin,Clean Authentication`;

    try {
      setTimeout(() => setProgress(80), 150);
      const res = await onBatchUpload(undefined, sampleCsv);
      setProgress(100);
      setBatchItems(res.items);
      setTimeout(() => setShowProgress(false), 500);
    } catch (err: any) {
      setProgress(100);
      alert(err.message || 'Failed to parse batch.');
    } finally {
      setLoading(false);
    }
  };

  const loadSampleZipArchive = async () => {
    setShowProgress(true);
    setProgress(25);
    setLoading(true);
    setPeReport(null);
    setCurrentFile('malicious_invoice_package.zip');

    try {
      const zip = new JSZip();
      const { buffer: exeBuffer } = generateSamplePeBinary('malicious');
      zip.file('Urgent_Overdue_Invoice_Ref9921.pdf.exe', exeBuffer);
      zip.file('Payment_Verification_Script.vbs', 'Set WshShell = CreateObject("WScript.Shell")\nWshShell.Run "cmd /c powershell -enc ..."');
      zip.file(
        'notification_alert.eml',
        `From: security@paypal-account-center.com\nSubject: Account Compromise Alert\n\nVerify immediately: http://194.26.29.112/confirm-login`
      );
      zip.file('legitimate_readme.txt', 'Corporate billing instructions.');

      const blob = await zip.generateAsync({ type: 'blob' });
      const testZipFile = new File([blob], 'malicious_invoice_package.zip', { type: 'application/zip' });

      await processFile(testZipFile);
    } catch (err: any) {
      setShowProgress(false);
      setLoading(false);
      alert('Failed to generate sample zip: ' + err.message);
    }
  };

  const exportResultsCsv = () => {
    if (batchItems.length === 0) return;
    const header = 'Indicator,Verdict,ThreatCategory,Confidence\n';
    const rows = batchItems
      .map(
        (i) =>
          `"${i.indicatorValue}","${i.isMalicious ? 'THREAT' : 'CLEAN'}","${i.threatType}","${i.confidence || 95}%"`
      )
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-batch-audit-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const maliciousCount = batchItems.filter((i) => i.isMalicious).length;
  const cleanCount = batchItems.filter((i) => !i.isMalicious).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-5 flex flex-col xl:flex-row items-start xl:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <UploadCloud className="w-4 h-4 text-[#38bdf8]" />
            Bulk Artifact, Shortcut (.LNK), EML & Executable (.EXE) Triage
          </h2>
          <p className="text-xs text-[#94a3b8] mt-1">
            Deep static forensic inspection for Windows Shortcuts (.LNK / LOLBins), PE binaries (.EXE / entropy / packing / imports), .ZIP archives, and .EML emails.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 w-full xl:w-auto">
          {/* Blender Shortcut Test Button */}
          <button
            onClick={loadSampleBlenderShortcut}
            disabled={loading}
            title="Scan authentic Blender 3D Suite shortcut (verifies 0/100 Clean Safe status)"
            className="px-2.5 py-1.5 rounded-md bg-[#11241c] hover:bg-[#183629] border border-[#1d4d33] text-xs font-mono text-[#4ade80] flex items-center gap-1.5 transition cursor-pointer shadow-sm"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#22c55e]" />
            <span>Test Blender Shortcut</span>
          </button>

          {/* Malicious Shortcut Test Button */}
          <button
            onClick={loadSampleMaliciousShortcut}
            disabled={loading}
            title="Scan simulated weaponized .LNK shortcut with hidden PowerShell execution"
            className="px-2.5 py-1.5 rounded-md bg-[#2d1217] hover:bg-[#3d1820] border border-[#521b28] text-xs font-mono text-[#fb7185] flex items-center gap-1.5 transition cursor-pointer shadow-sm"
          >
            <Link2 className="w-3.5 h-3.5 text-[#f43f5e]" />
            <span>Test Malicious .LNK</span>
          </button>

          {/* Blender Binary Test Button */}
          <button
            onClick={loadSampleBlenderExe}
            disabled={loading}
            title="Scan simulated Blender 3D executable (verifies 0/100 Clean Safe status)"
            className="px-2.5 py-1.5 rounded-md bg-[#13251c] hover:bg-[#1a3326] border border-[#1e4832] text-xs font-mono text-[#86efac] flex items-center gap-1.5 transition cursor-pointer shadow-sm"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-[#22c55e]" />
            <span>Test Blender .EXE</span>
          </button>

          {/* Malicious PE Test Button */}
          <button
            onClick={loadSampleMaliciousExe}
            disabled={loading}
            title="Scan simulated weaponized infostealer dropper with high entropy and injection APIs"
            className="px-2.5 py-1.5 rounded-md bg-[#25151c] hover:bg-[#351a24] border border-[#481c2d] text-xs font-mono text-[#fda4af] flex items-center gap-1.5 transition cursor-pointer shadow-sm"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-[#f43f5e]" />
            <span>Test Malicious .EXE</span>
          </button>

          <button
            onClick={loadSampleZipArchive}
            disabled={loading}
            className="px-2.5 py-1.5 rounded-md bg-[#1a2230] hover:bg-[#202b3d] border border-[#263347] text-xs font-mono text-[#93c5fd] flex items-center gap-1.5 transition cursor-pointer"
          >
            <FileArchive className="w-3.5 h-3.5" />
            <span>Test ZIP</span>
          </button>

          <button
            onClick={loadSampleBatch}
            disabled={loading}
            className="px-2.5 py-1.5 rounded-md bg-[#1a2230] hover:bg-[#202b3d] border border-[#263347] text-xs font-medium text-slate-200 flex items-center gap-1.5 transition cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            <span>CSV Feed</span>
          </button>

          {batchItems.length > 0 && (
            <button
              onClick={exportResultsCsv}
              className="px-2.5 py-1.5 rounded-md bg-[#1a2230] hover:bg-[#202b3d] border border-[#263347] text-xs font-medium text-slate-200 flex items-center gap-1.5 transition cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
          )}
        </div>
      </div>

      {/* Drop Zone matching exact ID #dropZone */}
      <div
        id="dropZone"
        onClick={() => fileInputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragOver(true);
        }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition flex flex-col items-center justify-center gap-2.5 ${
          isDragOver
            ? 'dragover border-[#3b82f6] bg-[#1a2230]'
            : 'border-[#242e40] bg-[#0e121a] hover:border-[#334158]'
        }`}
      >
        <div className="w-12 h-12 rounded-lg bg-[#151b26] border border-[#242e40] flex items-center justify-center text-slate-300">
          <Binary className="w-6 h-6 text-[#38bdf8]" />
        </div>

        <div>
          <p className="text-xs font-medium text-slate-200">
            Click to upload or drag & drop Windows Shortcuts (.LNK), .EXE binaries, .ZIP archives, or .EML files
          </p>
          <p className="text-[11px] text-[#64748b] mt-1">
            Accepts: <span className="text-[#38bdf8] font-mono">.LNK</span> (Windows Shortcuts & LOLBins) | <span className="text-[#4ade80] font-mono">.EXE, .DLL, .BIN, .SCR</span> (PE Executables) | <span className="text-slate-300 font-mono">.ZIP, .EML, .CSV, .TXT</span>
          </p>
        </div>

        {/* Hidden input matching exact ID #fileInput */}
        <input
          id="fileInput"
          ref={fileInputRef}
          type="file"
          accept=".lnk,.exe,.dll,.bin,.scr,.sys,.zip,.eml,.msg,.txt,.csv,.json,.log"
          onChange={handleFileChange}
          className="hidden"
        />
      </div>

      {/* Progress Bar matching exact ID #bulkProgressWrapper and #bulkProgressBar */}
      <div
        id="bulkProgressWrapper"
        className="bg-[#151b26] border border-[#242e40] rounded-lg p-3.5"
        style={{ display: showProgress ? 'block' : 'none' }}
      >
        <div className="flex items-center justify-between text-xs text-[#94a3b8] mb-2 font-mono">
          <span>Processing: {currentFile || 'Binary Analysis Engine'}</span>
          <span>{progress}%</span>
        </div>
        <div className="w-full bg-[#0e121a] h-2 rounded-full overflow-hidden border border-[#242e40]">
          <div
            id="bulkProgressBar"
            className="bg-[#2563eb] h-full transition-all duration-150 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* DEDICATED PE FORENSIC INSPECTOR CARD */}
      {peReport && (
        <div className="bg-[#121722] border border-[#283548] rounded-xl overflow-hidden shadow-xl space-y-0">
          {/* Verdict Banner */}
          <div
            className={`p-5 border-b flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
              peReport.verdict === 'MALICIOUS'
                ? 'bg-[#291116] border-[#5e1f2b] text-[#fb7185]'
                : peReport.verdict === 'SUSPICIOUS'
                ? 'bg-[#281e0f] border-[#5c4217] text-[#fbbf24]'
                : 'bg-[#0e2417] border-[#1d4d2f] text-[#4ade80]'
            }`}
          >
            <div className="flex items-start gap-3">
              <div
                className={`p-2.5 rounded-lg border mt-0.5 ${
                  peReport.verdict === 'MALICIOUS'
                    ? 'bg-[#3b121b] border-[#752132]'
                    : peReport.verdict === 'SUSPICIOUS'
                    ? 'bg-[#382610] border-[#6b4e1a]'
                    : 'bg-[#133320] border-[#22633b]'
                }`}
              >
                {peReport.verdict === 'MALICIOUS' ? (
                  <ShieldAlert className="w-6 h-6 text-[#f43f5e]" />
                ) : peReport.verdict === 'SUSPICIOUS' ? (
                  <AlertTriangle className="w-6 h-6 text-[#f59e0b]" />
                ) : (
                  <ShieldCheck className="w-6 h-6 text-[#22c55e]" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-bold font-mono tracking-wide uppercase">
                    {peReport.verdict} EXECUTABLE DETECTED
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                      peReport.verdict === 'MALICIOUS'
                        ? 'bg-[#e11d48] text-white'
                        : peReport.verdict === 'SUSPICIOUS'
                        ? 'bg-[#d97706] text-white'
                        : 'bg-[#16a34a] text-white'
                    }`}
                  >
                    Risk Score: {peReport.suspicionScore}/100
                  </span>
                  {peReport.isPacked && (
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#831843] text-[#fbcfe8] border border-[#9d174d]">
                      {peReport.detectedPacker || 'Packed Binary'}
                    </span>
                  )}
                  {peReport.hasWritableExecutableSection && (
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#7f1d1d] text-[#fecaca] border border-[#b91c1c] animate-pulse">
                      W+X Memory Alert
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-300 mt-1.5 font-medium leading-relaxed">
                  {peReport.verdictSummary}
                </p>
                <div className="text-[11px] text-slate-400 font-mono mt-1 flex items-center gap-3">
                  <span>File: <strong className="text-white">{peReport.fileName}</strong></span>
                  <span>Size: {(peReport.fileSizeBytes / 1024).toFixed(1)} KB</span>
                  <span>Magic: {peReport.magic}</span>
                </div>
              </div>
            </div>

            {/* Suspicion Meter */}
            <div className="w-full md:w-44 bg-[#0a0e14] border border-[#242e40] p-3 rounded-lg">
              <div className="flex justify-between items-center text-[10px] font-mono text-[#94a3b8] mb-1">
                <span>Threat Index</span>
                <span className="font-bold text-white">{peReport.suspicionScore}%</span>
              </div>
              <div className="w-full bg-[#151b26] h-2 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${
                    peReport.suspicionScore >= 65
                      ? 'bg-gradient-to-r from-orange-500 to-rose-600'
                      : peReport.suspicionScore >= 35
                      ? 'bg-gradient-to-r from-yellow-500 to-amber-600'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${peReport.suspicionScore}%` }}
                />
              </div>
              <span className="text-[9px] text-[#64748b] block mt-1 text-center font-mono">
                {peReport.threatLevel} Severity Level
              </span>
            </div>
          </div>

          <div className="p-5 space-y-5">
            {/* PE Structure & Static Telemetry Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
              <div className="bg-[#171e2c] border border-[#263245] rounded-lg p-3">
                <div className="text-[#64748b] text-[10px] uppercase font-mono flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-[#38bdf8]" />
                  <span>Architecture</span>
                </div>
                <div className="text-slate-100 font-mono font-semibold text-sm mt-1">
                  {peReport.architecture}
                </div>
                <div className="text-[10px] text-[#94a3b8] mt-0.5 font-mono">
                  Subsystem: {peReport.subsystem}
                </div>
              </div>

              <div className="bg-[#171e2c] border border-[#263245] rounded-lg p-3">
                <div className="text-[#64748b] text-[10px] uppercase font-mono flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-[#a855f7]" />
                  <span>Shannon Entropy</span>
                </div>
                <div className="text-slate-100 font-mono font-semibold text-sm mt-1 flex items-baseline gap-1.5">
                  <span className={peReport.entropy >= 7.15 ? 'text-[#fb7185]' : peReport.entropy >= 6.8 ? 'text-[#f59e0b]' : 'text-[#4ade80]'}>
                    {peReport.entropy.toFixed(3)}
                  </span>
                  <span className="text-[11px] text-[#64748b]">/ 8.00</span>
                </div>
                <div className="text-[10px] font-mono mt-0.5">
                  {peReport.entropy >= 7.15 ? (
                    <span className="text-[#fb7185]">High (Encrypted/Packed)</span>
                  ) : peReport.entropy >= 6.8 ? (
                    <span className="text-[#fbbf24]">Elevated Density</span>
                  ) : (
                    <span className="text-[#4ade80]">Normal Benign Curve</span>
                  )}
                </div>
              </div>

              <div className="bg-[#171e2c] border border-[#263245] rounded-lg p-3">
                <div className="text-[#64748b] text-[10px] uppercase font-mono flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-[#f43f5e]" />
                  <span>Packer / Obfuscator</span>
                </div>
                <div className="text-slate-100 font-mono font-semibold text-xs mt-1 truncate" title={peReport.detectedPacker || 'None detected'}>
                  {peReport.detectedPacker || 'Unpacked / Standard'}
                </div>
                <div className="text-[10px] text-[#94a3b8] mt-0.5 font-mono">
                  {peReport.isPacked ? 'Signature Confirmed' : 'Standard Compiler Baseline'}
                </div>
              </div>

              <div className="bg-[#171e2c] border border-[#263245] rounded-lg p-3">
                <div className="text-[#64748b] text-[10px] uppercase font-mono flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-[#38bdf8]" />
                  <span>Timestamp Header</span>
                </div>
                <div className="text-slate-200 font-mono text-xs mt-1 truncate" title={peReport.compilationTimestamp || 'N/A'}>
                  {peReport.compilationTimestamp ? peReport.compilationTimestamp.split('T')[0] : 'Unknown'}
                </div>
                <div className="text-[10px] font-mono mt-0.5">
                  {peReport.timestampAnomaly ? (
                    <span className="text-[#fb7185]">Timestomp Anomaly</span>
                  ) : (
                    <span className="text-[#94a3b8]">Plausible Epoch</span>
                  )}
                </div>
              </div>
            </div>

            {/* Cryptographic Hashes Section */}
            <div className="bg-[#0e121a] border border-[#222c3d] rounded-lg p-3 font-mono text-xs space-y-2">
              <div className="text-[11px] text-[#64748b] uppercase tracking-wider font-semibold flex items-center justify-between">
                <span>Cryptographic Hashes</span>
                <span className="text-[10px] text-[#38bdf8]">EDR Blacklist Artifacts</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div className="bg-[#151b26] p-2 rounded border border-[#242e40] flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-[#64748b] text-[10px] block">SHA-256</span>
                    <span className="text-slate-200 text-[11px] truncate block select-all" title={peReport.sha256}>
                      {peReport.sha256}
                    </span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(peReport.sha256, 'sha256')}
                    className="p-1.5 rounded hover:bg-[#202b3d] text-slate-400 hover:text-white transition"
                    title="Copy SHA-256"
                  >
                    {copiedHash === 'sha256' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <div className="bg-[#151b26] p-2 rounded border border-[#242e40] flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-[#64748b] text-[10px] block">MD5</span>
                    <span className="text-slate-200 text-[11px] truncate block select-all" title={peReport.md5}>
                      {peReport.md5}
                    </span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(peReport.md5, 'md5')}
                    className="p-1.5 rounded hover:bg-[#202b3d] text-slate-400 hover:text-white transition"
                    title="Copy MD5"
                  >
                    {copiedHash === 'md5' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <div className="bg-[#151b26] p-2 rounded border border-[#242e40] flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-[#64748b] text-[10px] block">SHA-1</span>
                    <span className="text-slate-200 text-[11px] truncate block select-all" title={peReport.sha1}>
                      {peReport.sha1}
                    </span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(peReport.sha1, 'sha1')}
                    className="p-1.5 rounded hover:bg-[#202b3d] text-slate-400 hover:text-white transition"
                    title="Copy SHA-1"
                  >
                    {copiedHash === 'sha1' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            {/* Weaponized Capabilities & MITRE ATT&CK */}
            {peReport.capabilities.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <Bug className="w-4 h-4 text-[#fb7185]" />
                  Flagged Threat Capabilities & Windows APIs ({peReport.capabilities.length})
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {peReport.capabilities.map((cap, i) => (
                    <div
                      key={i}
                      className={`p-3 rounded-lg border text-xs font-mono ${
                        cap.severity === 'critical'
                          ? 'bg-[#211116] border-[#4c1d27]'
                          : 'bg-[#201a11] border-[#4a391c]'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="font-bold text-slate-200 flex items-center gap-1.5">
                          <span
                            className={`w-2 h-2 rounded-full ${
                              cap.severity === 'critical' ? 'bg-[#f43f5e]' : 'bg-[#f59e0b]'
                            }`}
                          />
                          {cap.category}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded ${
                            cap.severity === 'critical'
                              ? 'bg-[#e11d48]/20 text-[#fb7185] border border-[#e11d48]/40'
                              : 'bg-[#d97706]/20 text-[#fbbf24] border border-[#d97706]/40'
                          }`}
                        >
                          {cap.mitreId}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-300 mb-2 font-sans">
                        {cap.description}
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {cap.apis.map((api, aidx) => (
                          <span
                            key={aidx}
                            className="bg-[#0d131a] px-1.5 py-0.5 rounded text-[10px] text-[#38bdf8] border border-[#1f2937]"
                          >
                            {api}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* PE Sections Table */}
            {peReport.sections.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <FileCode className="w-4 h-4 text-[#38bdf8]" />
                  PE Section Breakdown ({peReport.sections.length} Sections)
                </h3>
                <div className="overflow-x-auto rounded-lg border border-[#242e40] bg-[#0e121a]">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-[#242e40] text-[#64748b] bg-[#151b26]">
                        <th className="py-2 px-3 font-medium">Section</th>
                        <th className="py-2 px-3 font-medium">Virtual Size</th>
                        <th className="py-2 px-3 font-medium">Raw Size</th>
                        <th className="py-2 px-3 font-medium">Entropy</th>
                        <th className="py-2 px-3 font-medium">Characteristics</th>
                        <th className="py-2 px-3 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#242e40]">
                      {peReport.sections.map((sec, sidx) => (
                        <tr
                          key={sidx}
                          className={`hover:bg-[#161d2a] transition ${
                            sec.isSuspicious ? 'bg-[#201317]/50' : ''
                          }`}
                        >
                          <td className="py-2 px-3 font-bold text-slate-200">
                            {sec.name}
                          </td>
                          <td className="py-2 px-3 text-slate-300">
                            0x{sec.virtualSize.toString(16).toUpperCase()} ({sec.virtualSize} B)
                          </td>
                          <td className="py-2 px-3">
                            <span
                              className={
                                sec.rawSize === 0 && sec.virtualSize > 0
                                  ? 'text-[#fb7185] font-bold'
                                  : 'text-slate-300'
                              }
                            >
                              0x{sec.rawSize.toString(16).toUpperCase()} ({sec.rawSize} B)
                            </span>
                          </td>
                          <td className="py-2 px-3">
                            <span
                              className={
                                sec.entropy > 7.15
                                  ? 'text-[#fb7185] font-bold'
                                  : sec.entropy > 6.5
                                  ? 'text-[#fbbf24]'
                                  : 'text-[#4ade80]'
                              }
                            >
                              {sec.entropy.toFixed(2)}
                            </span>
                          </td>
                          <td className="py-2 px-3">
                            <div className="flex flex-wrap gap-1">
                              {sec.characteristics.map((c, cidx) => (
                                <span
                                  key={cidx}
                                  className={`px-1 py-0.5 rounded text-[10px] ${
                                    c === 'W+X_ALERT'
                                      ? 'bg-red-900/60 text-red-200 border border-red-500 font-bold'
                                      : 'bg-[#1a2230] text-slate-300 border border-[#2a384f]'
                                  }`}
                                >
                                  {c}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="py-2 px-3">
                            {sec.isSuspicious ? (
                              <span className="badge High">SUSPICIOUS</span>
                            ) : (
                              <span className="badge Low">NORMAL</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Extracted IOCs & Command Strings */}
            {(peReport.extractedIocs.length > 0 || peReport.matchedSuspiciousStrings.length > 0) && (
              <div>
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Network className="w-4 h-4 text-[#38bdf8]" />
                  Embedded Network & Command Artifacts
                </h3>
                <div className="space-y-1.5">
                  {peReport.extractedIocs.map((ioc, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-2 rounded bg-[#0e121a] border border-[#242e40] text-xs font-mono"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span className="px-1.5 py-0.5 rounded bg-[#1a2333] text-[#38bdf8] text-[10px]">
                          {ioc.type}
                        </span>
                        <code className="text-slate-200 select-all">{ioc.value}</code>
                      </div>
                      <span className={`badge ${ioc.threatLevel || 'High'}`}>
                        {ioc.threatLevel === 'High' ? 'C2 IOC' : 'REVIEW'}
                      </span>
                    </div>
                  ))}
                  {peReport.matchedSuspiciousStrings.map((ms, idx) => (
                    <div
                      key={'str-' + idx}
                      className="flex items-center justify-between p-2 rounded bg-[#1f1216] border border-[#3d1822] text-xs font-mono"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span className="px-1.5 py-0.5 rounded bg-[#3b151f] text-[#fb7185] text-[10px]">
                          {ms.category}
                        </span>
                        <code className="text-[#fda4af] select-all truncate">{ms.value}</code>
                      </div>
                      <span className="badge High">WEAPONIZED</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actionable SOC Playbook Recommendations */}
            <div className="bg-[#101724] border border-[#212f45] rounded-lg p-4 space-y-3">
              <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#38bdf8]" />
                Automated SOC Containment Playbook
              </h4>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                {peReport.recommendations.map((rec, rIdx) => (
                  <li key={rIdx} className="leading-relaxed">
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* DEDICATED WINDOWS SHORTCUT (.LNK) FORENSIC INSPECTOR CARD */}
      {lnkReport && (
        <div className="bg-[#121722] border border-[#283548] rounded-xl overflow-hidden shadow-xl space-y-0">
          {/* Verdict Banner */}
          <div
            className={`p-5 border-b flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
              lnkReport.verdict === 'MALICIOUS'
                ? 'bg-[#291116] border-[#5e1f2b] text-[#fb7185]'
                : lnkReport.verdict === 'SUSPICIOUS'
                ? 'bg-[#281e0f] border-[#5c4217] text-[#fbbf24]'
                : 'bg-[#0e2417] border-[#1d4d2f] text-[#4ade80]'
            }`}
          >
            <div className="flex items-start gap-3">
              <div
                className={`p-2.5 rounded-lg border mt-0.5 ${
                  lnkReport.verdict === 'MALICIOUS'
                    ? 'bg-[#3b121b] border-[#752132]'
                    : lnkReport.verdict === 'SUSPICIOUS'
                    ? 'bg-[#382610] border-[#6b4e1a]'
                    : 'bg-[#133320] border-[#22633b]'
                }`}
              >
                {lnkReport.verdict === 'MALICIOUS' ? (
                  <ShieldAlert className="w-6 h-6 text-[#f43f5e]" />
                ) : lnkReport.verdict === 'SUSPICIOUS' ? (
                  <AlertTriangle className="w-6 h-6 text-[#f59e0b]" />
                ) : (
                  <ShieldCheck className="w-6 h-6 text-[#22c55e]" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-bold font-mono tracking-wide uppercase">
                    {lnkReport.verdict === 'BENIGN'
                      ? (lnkReport.isKnownBenignApp ? 'VERIFIED CLEAN APPLICATION SHORTCUT (.LNK)' : 'BENIGN DESKTOP SHORTCUT (.LNK)')
                      : `${lnkReport.verdict} WINDOWS SHORTCUT (.LNK)`}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                      lnkReport.verdict === 'MALICIOUS'
                        ? 'bg-[#e11d48] text-white'
                        : lnkReport.verdict === 'SUSPICIOUS'
                        ? 'bg-[#d97706] text-white'
                        : 'bg-[#16a34a] text-white'
                    }`}
                  >
                    Risk Score: {lnkReport.suspicionScore}/100
                  </span>
                  {lnkReport.isKnownBenignApp && (
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#15803d] text-white border border-[#22c55e]/40 font-bold flex items-center gap-1">
                      <Sparkles className="w-3 h-3" />
                      {lnkReport.knownAppName || 'Verified Software Publisher'}
                    </span>
                  )}
                  {lnkReport.isLolbin && (
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#7f1d1d] text-[#fecaca] border border-[#b91c1c] font-bold">
                      LOLBin Detected
                    </span>
                  )}
                  {lnkReport.hasHiddenWindow && (
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#7f1d1d] text-[#fecaca] border border-[#b91c1c] font-bold animate-pulse">
                      Hidden Window Execution
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-300 mt-1.5 font-medium leading-relaxed">
                  {lnkReport.verdictSummary}
                </p>
                <div className="text-[11px] text-slate-400 font-mono mt-1 flex items-center gap-3">
                  <span>File: <strong className="text-white">{lnkReport.fileName}</strong></span>
                  <span>Size: {lnkReport.fileSizeBytes} B</span>
                  <span>Format: MS-SHLLINK (CLSID: 00021401...)</span>
                </div>
              </div>
            </div>

            {/* Suspicion Meter */}
            <div className="w-full md:w-44 bg-[#0a0e14] border border-[#242e40] p-3 rounded-lg">
              <div className="flex justify-between items-center text-[10px] font-mono text-[#94a3b8] mb-1">
                <span>Threat Index</span>
                <span className="font-bold text-white">{lnkReport.suspicionScore}%</span>
              </div>
              <div className="w-full bg-[#151b26] h-2 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${
                    lnkReport.suspicionScore >= 65
                      ? 'bg-gradient-to-r from-orange-500 to-rose-600'
                      : lnkReport.suspicionScore >= 30
                      ? 'bg-gradient-to-r from-yellow-500 to-amber-600'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.max(4, lnkReport.suspicionScore)}%` }}
                />
              </div>
              <span className="text-[9px] text-[#64748b] block mt-1 text-center font-mono">
                {lnkReport.threatLevel} Severity Level
              </span>
            </div>
          </div>

          <div className="p-5 space-y-5">
            {/* Target Path & Execution Parameters Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="bg-[#171e2c] border border-[#263245] rounded-lg p-3 space-y-1">
                <div className="text-[#64748b] text-[10px] uppercase font-mono flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <Link2 className="w-3.5 h-3.5 text-[#38bdf8]" />
                    Target Executable Path
                  </span>
                  {lnkReport.isLolbin ? (
                    <span className="text-[#fb7185] font-bold">Living Off The Land Binary</span>
                  ) : lnkReport.isKnownBenignApp ? (
                    <span className="text-[#4ade80] font-bold">Legitimate Executable</span>
                  ) : (
                    <span className="text-slate-400">Local Executable</span>
                  )}
                </div>
                <div className="text-slate-100 font-mono text-xs break-all bg-[#0e121a] p-2 rounded border border-[#242e40] select-all">
                  {lnkReport.targetPath}
                </div>
                {lnkReport.workingDirectory && (
                  <div className="text-[11px] text-[#94a3b8] font-mono flex items-center gap-1.5 mt-1">
                    <FolderOpen className="w-3 h-3 text-[#38bdf8]" />
                    <span>Working Dir: <strong className="text-slate-200">{lnkReport.workingDirectory}</strong></span>
                  </div>
                )}
              </div>

              <div className="bg-[#171e2c] border border-[#263245] rounded-lg p-3 space-y-1">
                <div className="text-[#64748b] text-[10px] uppercase font-mono flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-[#38bdf8]" />
                    Launch Window & Arguments
                  </span>
                  <span className={lnkReport.hasHiddenWindow ? 'text-[#fb7185] font-bold' : 'text-[#4ade80]'}>
                    {lnkReport.showCommand}
                  </span>
                </div>
                <div className="text-slate-300 font-mono text-xs break-all bg-[#0e121a] p-2 rounded border border-[#242e40] select-all min-h-[34px]">
                  {lnkReport.commandArguments ? (
                    <span className={lnkReport.hasObfuscatedArgs ? 'text-[#fb7185] font-bold' : 'text-slate-200'}>
                      {lnkReport.commandArguments}
                    </span>
                  ) : (
                    <span className="text-[#64748b] italic">No command-line arguments (Direct executable invocation)</span>
                  )}
                </div>
                {lnkReport.iconLocation && (
                  <div className="text-[11px] text-[#94a3b8] font-mono truncate mt-1">
                    Icon: <span className="text-slate-300">{lnkReport.iconLocation}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Cryptographic Hashes Section */}
            <div className="bg-[#0e121a] border border-[#222c3d] rounded-lg p-3 font-mono text-xs space-y-2">
              <div className="text-[11px] text-[#64748b] uppercase tracking-wider font-semibold flex items-center justify-between">
                <span>Cryptographic Hashes</span>
                <span className="text-[10px] text-[#38bdf8]">LNK Forensic Artifacts</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div className="bg-[#151b26] p-2 rounded border border-[#242e40] flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-[#64748b] text-[10px] block">SHA-256</span>
                    <span className="text-slate-200 text-[11px] truncate block select-all" title={lnkReport.hashes.sha256}>
                      {lnkReport.hashes.sha256}
                    </span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(lnkReport.hashes.sha256, 'lnk-sha256')}
                    className="p-1.5 rounded hover:bg-[#202b3d] text-slate-400 hover:text-white transition cursor-pointer"
                    title="Copy SHA-256"
                  >
                    {copiedHash === 'lnk-sha256' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <div className="bg-[#151b26] p-2 rounded border border-[#242e40] flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-[#64748b] text-[10px] block">MD5</span>
                    <span className="text-slate-200 text-[11px] truncate block select-all" title={lnkReport.hashes.md5}>
                      {lnkReport.hashes.md5}
                    </span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(lnkReport.hashes.md5, 'lnk-md5')}
                    className="p-1.5 rounded hover:bg-[#202b3d] text-slate-400 hover:text-white transition cursor-pointer"
                    title="Copy MD5"
                  >
                    {copiedHash === 'lnk-md5' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <div className="bg-[#151b26] p-2 rounded border border-[#242e40] flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-[#64748b] text-[10px] block">SHA-1</span>
                    <span className="text-slate-200 text-[11px] truncate block select-all" title={lnkReport.hashes.sha1}>
                      {lnkReport.hashes.sha1}
                    </span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(lnkReport.hashes.sha1, 'lnk-sha1')}
                    className="p-1.5 rounded hover:bg-[#202b3d] text-slate-400 hover:text-white transition cursor-pointer"
                    title="Copy SHA-1"
                  >
                    {copiedHash === 'lnk-sha1' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            {/* Forensic Reasons & Evaluation */}
            <div className="bg-[#101724] border border-[#212f45] rounded-lg p-4 space-y-2">
              <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#38bdf8]" />
                Forensic Analysis & Score Justification
              </h4>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                {lnkReport.reasons.map((reason, rIdx) => (
                  <li key={rIdx} className="leading-relaxed">
                    {reason}
                  </li>
                ))}
              </ul>
            </div>

            {/* Actionable SOC Playbook Recommendations */}
            <div className="bg-[#101724] border border-[#212f45] rounded-lg p-4 space-y-2">
              <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#38bdf8]" />
                SOC Playbook Next Steps
              </h4>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                {lnkReport.recommendations.map((rec, rIdx) => (
                  <li key={rIdx} className="leading-relaxed">
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Summary Row */}
      {batchItems.length > 0 && (
        <div className="grid grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-md bg-[#151b26] border border-[#242e40]">
            <span className="text-[#64748b] text-[10px] block uppercase font-mono">Total Parsed</span>
            <span className="text-base font-bold font-mono text-white mt-0.5 block">{batchItems.length}</span>
          </div>
          <div className="p-3 rounded-md bg-[#22151b] border border-[#3b1d28]">
            <span className="text-[#fb7185] text-[10px] block uppercase font-mono">Threats Identified</span>
            <span className="text-base font-bold font-mono text-[#fb7185] mt-0.5 block">{maliciousCount}</span>
          </div>
          <div className="p-3 rounded-md bg-[#132219] border border-[#1e3d29]">
            <span className="text-[#4ade80] text-[10px] block uppercase font-mono">Clean Verified</span>
            <span className="text-base font-bold font-mono text-[#4ade80] mt-0.5 block">{cleanCount}</span>
          </div>
        </div>
      )}

      {/* Results Table matching exact ID #batchResultTable tbody */}
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4 overflow-hidden">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#242e40]">
          <span className="text-xs font-semibold text-slate-200">
            Batch & Binary Analysis Results ({batchItems.length} Items)
          </span>
          <span className="text-[11px] text-[#64748b] font-mono">
            Automated Triage Output
          </span>
        </div>

        <div className="overflow-x-auto">
          <table id="batchResultTable" className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-[#242e40] text-[#64748b]">
                <th className="pb-2 font-medium">Indicator / Artifact Value</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#242e40]">
              {batchItems.length > 0 ? (
                batchItems.map((item, idx) => (
                  <tr key={idx} className="hover:bg-[#1a2230] transition">
                    <td className="py-2.5">
                      <code className="text-slate-200 bg-[#0e121a] px-2 py-1 rounded border border-[#242e40] break-all">
                        {item.indicatorValue}
                      </code>
                    </td>
                    <td className="py-2.5">
                      <span className={`badge ${item.isMalicious ? 'High' : 'Low'}`}>
                        {item.isMalicious ? 'THREAT' : 'CLEAN'}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-300">
                      {item.threatType || 'Normal'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={3} className="py-6 text-center text-[#64748b] italic">
                    Drop a .EXE file, .ZIP archive, or .EML message above or click &ldquo;Test Malicious .EXE&rdquo; to begin static inspection.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
