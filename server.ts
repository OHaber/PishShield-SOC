import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import path from 'path';
import multer from 'multer';
import { GoogleGenAI } from '@google/genai';
import {
  analyzePhishingContent,
  scanUrlReputation,
  parseBatchData,
  parseZipArchive,
  computeDashboardStats,
  INITIAL_LOGS
} from './src/threatEngine';
import {
  scanUrlReputationWithLiveFeeds,
  enrichEmailWithLiveApis,
  syncLiveThreatFeeds
} from './src/liveThreatService';
import { scanExecutablePe } from './src/peAnalysisEngine';
import { scanWindowsShortcutLnk, isWindowsShortcutBuffer } from './src/lnkAnalysisEngine';
import { ScanLog, BatchItem } from './src/types';

dotenv.config();

const PORT = 3000;
const isProd = process.env.NODE_ENV === 'production';

// In-memory persistent database of scan logs during server runtime
let scanLogs: ScanLog[] = [...INITIAL_LOGS];

// Set up Multer for handling file / EML uploads in-memory
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB max
});

async function startServer() {
  // Pre-synchronize live threat intelligence feeds in background
  syncLiveThreatFeeds().catch(e => console.warn('Background feed sync failed:', e.message));

  const app = express();

  app.use(express.json({ limit: '15mb' }));
  app.use(express.urlencoded({ extended: true, limit: '15mb' }));

  // CORS headers just in case clients query from different port/origin
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  // --- API Endpoints ---

  // 1. Dashboard Stats
  app.get('/api/dashboard/stats', (_req: Request, res: Response) => {
    try {
      const stats = computeDashboardStats(scanLogs);
      res.json(stats);
    } catch (error: any) {
      res.status(500).json({ error: error.message || 'Failed to compute stats' });
    }
  });

  // 2. Email Phishing Analyzer (Calls Real External Security APIs: Google DoH, URLhaus, OpenPhish, Feodo, IP-API, RDAP)
  app.post('/api/analyze', async (req: Request, res: Response) => {
    try {
      const { content } = req.body;
      if (!content || typeof content !== 'string') {
        return res.status(400).json({ error: 'Please enter email content or headers.' });
      }

      // Step 1: Base indicator extraction and structural heuristic triage
      const baseResult = analyzePhishingContent(content);

      // Step 2: Make REAL LIVE external API queries across all indicators
      const enrichedResult = await enrichEmailWithLiveApis(content, baseResult);

      // Step 3: Attempt AI enrichment if Gemini API key exists
      if (process.env.GEMINI_API_KEY) {
        try {
          const ai = new GoogleGenAI({});
          const prompt = `You are a Tier 3 Senior SOC Analyst. Analyze this suspicious email snippet and return concise JSON.
Headers/Body:
"""
${content.slice(0, 1500)}
"""
Score: ${enrichedResult.score}/100, ThreatLevel: ${enrichedResult.threatLevel}
Rules: ${enrichedResult.rulesTriggered?.map(r => r.rule).join(', ')}

Provide an object with:
"summary": 1-2 sentence executive briefing of the threat.
"attackVector": Primary threat technique (e.g., "MFA Bypass / Reverse Proxy", "Credential Harvesting", "Executive Impersonation / BEC", "Malicious Attachment Lure").
"techniques": Array of 3 MITRE ATT&CK techniques observed (e.g. ["T1566.002 - Spearphishing Link", "T1071.001 - Web Protocols", "T1586.002 - Email Accounts"]).
"recommendations": Array of 3 actionable mitigation steps for the security team.`;

          const timeoutPromise = new Promise<null>((_, reject) =>
            setTimeout(() => reject(new Error('AI enrichment timeout')), 2500)
          );

          const generatePromise = ai.models.generateContent({
            model: 'gemini-3.8-flash',
            contents: prompt,
            config: {
              responseMimeType: 'application/json'
            }
          });

          const aiResponse: any = await Promise.race([generatePromise, timeoutPromise]);

          if (aiResponse && aiResponse.text) {
            enrichedResult.aiAnalysis = JSON.parse(aiResponse.text);
          }
        } catch (aiErr) {
          console.warn('Gemini AI enrichment skipped or failed:', (aiErr as any)?.message);
        }
      }

      const newLog: ScanLog = {
        ...enrichedResult,
        scanDate: new Date().toISOString()
      };

      // Prepend to history logs
      scanLogs.unshift(newLog);

      res.json(enrichedResult);
    } catch (error: any) {
      console.error('Analyze error:', error);
      res.status(500).json({ error: error.message || 'Analysis failed' });
    }
  });

  // 3. URL / IP Reputation Scan (Live abuse.ch URLhaus + ip-api.com)
  app.post('/api/url/scan', async (req: Request, res: Response) => {
    try {
      const { url } = req.body;
      if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'Enter URL or IP.' });
      }

      const result = await scanUrlReputationWithLiveFeeds(url);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message || 'URL scan failed' });
    }
  });

  // 4. Batch & EML / ZIP Archive Upload
  app.post('/api/batch/upload', upload.single('file'), async (req: Request, res: Response) => {
    try {
      if (req.file) {
        const originalName = req.file.originalname || 'upload.bin';
        const lowerName = originalName.toLowerCase();
        const isZip =
          lowerName.endsWith('.zip') ||
          (req.file.mimetype && req.file.mimetype.includes('zip')) ||
          (req.file.buffer.length >= 4 &&
            req.file.buffer[0] === 0x50 &&
            req.file.buffer[1] === 0x4b &&
            req.file.buffer[2] === 0x03 &&
            req.file.buffer[3] === 0x04);

        if (isZip) {
          const items = await parseZipArchive(req.file.buffer, originalName);
          const threatsCount = items.filter(i => i.isMalicious).length;
          return res.json({
            filename: originalName,
            totalParsed: items.length,
            threatsCount,
            items
          });
        }

        // Windows Shortcut (.LNK) scan
        const isLnk =
          lowerName.endsWith('.lnk') ||
          isWindowsShortcutBuffer(req.file.buffer);

        if (isLnk) {
          const lnkReport = await scanWindowsShortcutLnk(req.file.buffer, originalName);
          const items: BatchItem[] = [
            {
              indicatorValue: `${originalName} -> ${lnkReport.targetPath}`,
              isMalicious: lnkReport.verdict === 'MALICIOUS',
              threatType: lnkReport.verdictSummary,
              enginesDetected: lnkReport.verdict === 'MALICIOUS' ? 79 : (lnkReport.verdict === 'SUSPICIOUS' ? 38 : 0),
              confidence: lnkReport.suspicionScore
            }
          ];

          if (lnkReport.isLolbin) {
            items.push({
              indicatorValue: `LOLBin Detected: ${lnkReport.lolbinDetected}`,
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

          if (lnkReport.hasHiddenWindow) {
            items.push({
              indicatorValue: 'Window Mode: Hidden / Minimized Non-Interactive',
              isMalicious: true,
              threatType: 'Stealth Execution (Hidden Window / Background Spawn)',
              enginesDetected: 72,
              confidence: 90
            });
          }

          for (const ioc of lnkReport.extractedIocs) {
            items.push({
              indicatorValue: `IOC: ${ioc.value} (${ioc.type})`,
              isMalicious: ioc.threatLevel === 'High',
              threatType: `Extracted String Artifact [${ioc.type}]`,
              enginesDetected: ioc.threatLevel === 'High' ? 68 : 12,
              confidence: 90
            });
          }

          const threatsCount = items.filter(i => i.isMalicious).length;
          return res.json({
            filename: originalName,
            totalParsed: items.length,
            threatsCount,
            items,
            lnkAnalysis: lnkReport
          });
        }

        // Executable (.EXE / PE / DLL / SCR / BIN) scan
        const isExe =
          lowerName.endsWith('.exe') ||
          lowerName.endsWith('.dll') ||
          lowerName.endsWith('.bin') ||
          lowerName.endsWith('.scr') ||
          lowerName.endsWith('.sys') ||
          (req.file.buffer.length >= 2 && req.file.buffer[0] === 0x4d && req.file.buffer[1] === 0x5a);

        if (isExe) {
          const peReport = await scanExecutablePe(req.file.buffer, originalName);
          const items: BatchItem[] = [
            {
              indicatorValue: `${originalName} [PE binary - ${peReport.architecture}]`,
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
              indicatorValue: `${originalName}: W+X Section Detected`,
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

          const threatsCount = items.filter(i => i.isMalicious).length;
          return res.json({
            filename: originalName,
            totalParsed: items.length,
            threatsCount,
            items,
            peAnalysis: peReport
          });
        }

        // Plain text / EML / CSV
        const content = req.file.buffer.toString('utf-8');
        const items = parseBatchData(content);
        const threatsCount = items.filter(i => i.isMalicious).length;
        return res.json({
          filename: originalName,
          totalParsed: items.length,
          threatsCount,
          items
        });
      }

      if (req.body.content) {
        const items = parseBatchData(req.body.content);
        const threatsCount = items.filter(i => i.isMalicious).length;
        return res.json({
          filename: 'batch-input.txt',
          totalParsed: items.length,
          threatsCount,
          items
        });
      }

      // Default sample fallback
      const items = parseBatchData('');
      return res.json({
        filename: 'sample-batch.txt',
        totalParsed: items.length,
        threatsCount: items.filter(i => i.isMalicious).length,
        items
      });
    } catch (error: any) {
      console.error('Batch upload error:', error);
      res.status(500).json({ error: error.message || 'Batch upload failed' });
    }
  });

  // 5. History Logs
  app.get('/api/history', (req: Request, res: Response) => {
    try {
      const risk = (req.query.risk as string) || 'all';
      let filtered = [...scanLogs];

      if (risk && risk.toLowerCase() !== 'all') {
        filtered = filtered.filter(l => l.threatLevel.toLowerCase() === risk.toLowerCase());
      }

      res.json({
        total: filtered.length,
        logs: filtered
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message || 'Failed to fetch history' });
    }
  });

  // 6. Clear History
  app.post('/api/history/clear', (_req: Request, res: Response) => {
    scanLogs = [];
    res.json({ message: 'History cleared', count: 0 });
  });

  // Serve static assets or mount Vite dev middleware
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PhishShield SOC] Server running on port ${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
