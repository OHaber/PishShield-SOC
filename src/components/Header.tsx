import React, { useState, useEffect } from 'react';
import { ShieldAlert, RefreshCw, Settings2, ShieldCheck, CheckCircle2 } from 'lucide-react';

interface HeaderProps {
  backendConnected: boolean;
  totalThreats: number;
  apiBase: string;
  onUpdateApiBase: (url: string) => void;
  onRefreshAll: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  backendConnected,
  totalThreats,
  apiBase,
  onUpdateApiBase,
  onRefreshAll
}) => {
  const [currentTime, setCurrentTime] = useState<string>('');
  const [showSettings, setShowSettings] = useState<boolean>(false);
  const [customApiUrl, setCustomApiUrl] = useState<string>(apiBase);

  useEffect(() => {
    const update = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().slice(17, 25) + ' UTC');
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleSaveApi = (e: React.FormEvent) => {
    e.preventDefault();
    onUpdateApiBase(customApiUrl.trim() || '/api');
    setShowSettings(false);
  };

  return (
    <header className="border-b border-[#242e40] bg-[#111622] sticky top-0 z-40 px-4 lg:px-8 py-3">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
        {/* Left: Product Identity */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-md bg-[#1d2636] border border-[#2d3a50] text-[#38bdf8]">
            <ShieldAlert className="w-4 h-4 text-slate-200" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-sm tracking-tight text-white font-sans">
                PhishShield
              </span>
              <span className="text-[11px] font-mono text-[#94a3b8]">
                Security Operations
              </span>
            </div>
            <p className="text-[11px] text-[#64748b]">
              Email Forensic Triage & Reputation Engine
            </p>
          </div>
        </div>

        {/* Center: Unboxed Status Metadata */}
        <div className="hidden md:flex items-center gap-3 text-xs text-[#94a3b8]">
          <span className="flex items-center gap-1.5">
            <span
              className={`inline-block w-1.5 h-1.5 rounded-full ${
                backendConnected ? 'bg-[#16a34a]' : 'bg-[#d97706]'
              }`}
            />
            <span className="text-slate-300">
              {backendConnected ? 'Engine Online' : 'Local Sandbox'}
            </span>
          </span>
          <span className="text-[#334158]" aria-hidden="true">·</span>
          <span>Live Feeds: URLhaus + ip-api</span>
          <span className="text-[#334158]" aria-hidden="true">·</span>
          <span className="font-mono text-[11px]">{currentTime || 'Synchronizing'}</span>
        </div>

        {/* Right: Actions & Target Controls */}
        <div className="flex items-center gap-2 text-xs">
          {/* Threats Count */}
          <div className="px-2.5 py-1 rounded-md bg-[#22151b] border border-[#3b1d28] text-[#fb7185] font-mono font-medium text-[11px]">
            {totalThreats} High Threats
          </div>

          {/* Settings Trigger */}
          <button
            onClick={() => setShowSettings(true)}
            title="Configure API Connection"
            className="p-1.5 rounded-md bg-[#171e2c] border border-[#263347] text-[#94a3b8] hover:text-white hover:border-[#384964] transition cursor-pointer"
          >
            <Settings2 className="w-3.5 h-3.5" />
          </button>

          {/* Refresh Action */}
          <button
            onClick={onRefreshAll}
            title="Refresh All Feeds"
            className="p-1.5 rounded-md bg-[#171e2c] border border-[#263347] text-[#94a3b8] hover:text-white hover:border-[#384964] transition cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-[#151b26] border border-[#263347] rounded-lg max-w-md w-full p-5 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#242e40]">
              <span className="font-semibold text-sm text-slate-100">
                API Endpoint Configuration
              </span>
              <button
                onClick={() => setShowSettings(false)}
                className="text-[#94a3b8] hover:text-white text-sm cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveApi} className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Base API URL
                </label>
                <input
                  type="text"
                  value={customApiUrl}
                  onChange={(e) => setCustomApiUrl(e.target.value)}
                  placeholder="/api or http://localhost:5000/api"
                  className="w-full px-3 py-2 rounded-md bg-[#0e121a] border border-[#263347] text-xs text-slate-100 font-mono focus:outline-none focus:border-[#3b82f6]"
                />
                <p className="text-[11px] text-[#94a3b8] mt-1.5 leading-relaxed">
                  Defaults to <code className="text-slate-200">/api</code>. Enter a custom server path if running an external endpoint.
                </p>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setCustomApiUrl('/api');
                    onUpdateApiBase('/api');
                    setShowSettings(false);
                  }}
                  className="px-3 py-1.5 rounded-md bg-[#1c2434] text-xs text-slate-300 hover:bg-[#232e42] transition cursor-pointer"
                >
                  Reset Default
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded-md bg-[#2563eb] hover:bg-[#1d4ed8] text-xs font-medium text-white transition cursor-pointer"
                >
                  Apply
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </header>
  );
};
