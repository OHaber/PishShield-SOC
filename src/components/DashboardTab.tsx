import React from 'react';
import { Shield, ShieldAlert, ArrowUpRight, BarChart3, AlertCircle } from 'lucide-react';
import { DashboardStats } from '../types';

interface DashboardTabProps {
  stats: DashboardStats;
  onInspectAlert: (alertId: number) => void;
  onNavigateToTab: (tabId: string) => void;
}

export const DashboardTab: React.FC<DashboardTabProps> = ({
  stats,
  onInspectAlert,
  onNavigateToTab
}) => {
  const total = stats.threatDistribution.reduce((sum, d) => sum + d.count, 0) || 1;

  // Compute SVG chart coordinates matching user's exact coordinate formula
  const chartBars = stats.threatDistribution.map((d, index) => {
    const barHeight = Math.max(8, (d.count / total) * 140);
    const y = 170 - barHeight;
    const currentX = 25 + index * 90;
    const color = d.threatLevel === 'High' ? '#e11d48' : d.threatLevel === 'Medium' ? '#d97706' : '#16a34a';
    return {
      threatLevel: d.threatLevel,
      count: d.count,
      x: currentX,
      y,
      barHeight,
      color
    };
  });

  const latestAlert = stats.recentAlerts.length > 0 ? stats.recentAlerts[0] : null;

  return (
    <div className="space-y-6">
      {/* Ticker: Operational Status Strip */}
      <div className="bg-[#151b26] border border-[#242e40] rounded-lg px-4 py-2.5 flex items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="font-semibold text-slate-200 uppercase tracking-wider text-[11px] shrink-0 font-mono">
            Latest Detection
          </span>
          <span className="text-[#334158]" aria-hidden="true">/</span>
          <p id="tickerText" className="text-slate-300 font-mono text-[11px] truncate">
            {latestAlert
              ? `Scan #${latestAlert.id} scored ${latestAlert.score}/100: ${latestAlert.threatLevel.toUpperCase()} risk evaluation recorded.`
              : 'Sensors active. Ingesting email telemetry and network threat indicators.'}
          </p>
        </div>

        <div className="hidden sm:flex items-center gap-1.5 text-[#94a3b8] text-[11px] shrink-0">
          <span>Feed Status: Connected</span>
        </div>
      </div>

      {/* Metrics Row: Crisp technical metric counters with zero glowing clichés */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Metric 1: Total Scans */}
        <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4">
          <div className="text-xs text-[#94a3b8] font-medium">Total Scans</div>
          <div className="mt-1 flex items-baseline gap-2">
            <div id="metricTotal" className="text-2xl font-bold font-mono text-white tabular-nums">
              {stats.totalScans}
            </div>
            <span className="text-[11px] text-[#64748b]">Executed</span>
          </div>
          <div className="mt-2 text-[11px] text-[#64748b]">
            Cumulative email payloads and URL reputation queries
          </div>
        </div>

        {/* Metric 2: High Risk */}
        <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4">
          <div className="text-xs text-[#94a3b8] font-medium">High Risk Threats</div>
          <div className="mt-1 flex items-baseline gap-2">
            <div id="metricHigh" className="text-2xl font-bold font-mono text-[#fb7185] tabular-nums">
              {stats.highRisk}
            </div>
            <span className="text-[11px] text-[#fb7185]">Score &ge; 70</span>
          </div>
          <div className="mt-2 text-[11px] text-[#64748b]">
            Confirmed phishing attempts, credential lures, and malicious URLs
          </div>
        </div>

        {/* Metric 3: Blocked Domains */}
        <div className="bg-[#151b26] border border-[#242e40] rounded-lg p-4">
          <div className="text-xs text-[#94a3b8] font-medium">Blocked Indicators</div>
          <div className="mt-1 flex items-baseline gap-2">
            <div id="metricBlocked" className="text-2xl font-bold font-mono text-[#fbbf24] tabular-nums">
              {stats.blockedDomains}
            </div>
            <span className="text-[11px] text-[#64748b]">Firewall candidates</span>
          </div>
          <div className="mt-2 text-[11px] text-[#64748b]">
            Hostnames, direct IPs, and mail domains identified as hostile
          </div>
        </div>
      </div>

      {/* Asymmetric 2-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Severity Distribution Chart */}
        <div className="lg:col-span-7 bg-[#151b26] border border-[#242e40] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-[#242e40]">
              <div className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-[#94a3b8]" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Threat Classification Distribution
                </h3>
              </div>
              <span className="text-[11px] text-[#64748b]">Aggregated Heuristics</span>
            </div>

            <p className="text-xs text-[#94a3b8] mb-4 leading-relaxed">
              Distribution of inspected security telemetry across Low (0-34), Medium (35-69), and High (70-100) severity categories.
            </p>

            {/* SVG Chart Container matching user formula */}
            <div className="bg-[#0e121a] border border-[#242e40] rounded-md p-4 flex items-center justify-center">
              <svg
                id="threatChart"
                viewBox="0 0 290 200"
                className="w-full max-w-[340px] h-48 overflow-visible"
              >
                {/* Horizontal reference lines */}
                <line x1="15" y1="30" x2="275" y2="30" stroke="#1c2438" strokeDasharray="2 2" />
                <line x1="15" y1="100" x2="275" y2="100" stroke="#1c2438" strokeDasharray="2 2" />
                <line x1="15" y1="170" x2="275" y2="170" stroke="#263347" />

                {/* Bars dynamically rendered with formula from user snippet */}
                {chartBars.map((bar) => (
                  <g key={bar.threatLevel}>
                    <rect
                      x={bar.x}
                      y={bar.y}
                      width="54"
                      height={bar.barHeight}
                      fill={bar.color}
                      rx="3"
                    />
                    <text
                      x={bar.x + 10}
                      y="188"
                      fill="#94a3b8"
                      fontSize="11"
                      fontFamily="monospace"
                    >
                      {bar.threatLevel}
                    </text>
                    <text
                      x={bar.x + 20}
                      y={bar.y - 7}
                      fill="#f8fafc"
                      fontSize="12"
                      fontWeight="600"
                      fontFamily="monospace"
                    >
                      {bar.count}
                    </text>
                  </g>
                ))}
              </svg>
            </div>
          </div>

          {/* Clean unboxed legend */}
          <div className="flex items-center justify-around mt-4 pt-3 border-t border-[#242e40] text-xs text-[#94a3b8]">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#16a34a]" />
              <span>Low: Clean (0 to 34)</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#d97706]" />
              <span>Medium: Suspicious (35 to 69)</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#e11d48]" />
              <span>High: Malicious (70 to 100)</span>
            </span>
          </div>
        </div>

        {/* Right Column: Recent Alerts Feed */}
        <div className="lg:col-span-5 bg-[#151b26] border border-[#242e40] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-[#242e40]">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-[#94a3b8]" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Recent Detections
                </h3>
              </div>
              <button
                onClick={() => onNavigateToTab('tab-history')}
                className="text-xs text-[#38bdf8] hover:text-[#7dd3fc] flex items-center gap-1 cursor-pointer transition"
              >
                <span>Full Audit Log</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* List matching user specification ID */}
            <ul id="recentAlertsList" className="space-y-2">
              {stats.recentAlerts.map((alert) => (
                <li
                  key={alert.id}
                  onClick={() => onInspectAlert(alert.id)}
                  className="p-3 rounded-md bg-[#0e121a] border border-[#242e40] hover:border-[#384964] transition cursor-pointer flex items-center justify-between gap-3 group"
                >
                  <div className="min-w-0">
                    <div className="text-xs font-mono font-medium text-slate-200 group-hover:text-white transition">
                      <strong>Scan #{alert.id}</strong> <span className="text-[#64748b]">·</span> Score: {alert.score}/100
                    </div>
                    <div className="text-[11px] text-[#94a3b8] font-mono truncate mt-0.5">
                      {alert.target || alert.summary || 'Email Artifact'}
                    </div>
                  </div>

                  <span className={`badge ${alert.threatLevel} shrink-0`}>
                    {alert.threatLevel}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          {/* Functional Navigation Buttons */}
          <div className="grid grid-cols-2 gap-3 mt-4 pt-3 border-t border-[#242e40]">
            <button
              onClick={() => onNavigateToTab('tab-analyze')}
              className="px-3 py-2 rounded-md bg-[#1a2230] hover:bg-[#202b3d] border border-[#2d3a50] text-slate-200 text-xs font-medium transition cursor-pointer text-center"
            >
              Analyze Email Payload
            </button>
            <button
              onClick={() => onNavigateToTab('tab-url')}
              className="px-3 py-2 rounded-md bg-[#1a2230] hover:bg-[#202b3d] border border-[#2d3a50] text-slate-200 text-xs font-medium transition cursor-pointer text-center"
            >
              Scan URL Reputation
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
