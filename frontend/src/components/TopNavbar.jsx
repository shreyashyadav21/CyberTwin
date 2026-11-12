import React, { useState } from 'react';
import { 
  Building2, 
  ShieldCheck, 
  Bell, 
  UserCircle, 
  Sparkles, 
  PlayCircle,
  FileDown,
  RefreshCw,
  LogOut
} from 'lucide-react';
import { downloadReportPdfBlob, downloadReportPdfUrl } from '../services/api';

export default function TopNavbar({
  networks = [],
  currentNetwork,
  onSelectNetwork,
  alertsCount = 0,
  onStartDemoMode,
  onRefresh,
  isRefreshing,
  currentUser,
  onLogout
}) {
  const [isExporting, setIsExporting] = useState(false);

  const handleExportPdf = async () => {
    if (!currentNetwork?.id) return;
    setIsExporting(true);
    try {
      await downloadReportPdfBlob(currentNetwork.id);
    } catch (err) {
      console.error('Failed to download PDF:', err);
      // Fallback direct open
      window.open(downloadReportPdfUrl(currentNetwork.id), '_blank');
    } finally {
      setIsExporting(false);
    }
  };

  const initials = currentUser?.name
    ? currentUser.name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase()
    : 'LA';

  return (
    <header className="h-16 bg-[#FFFFFF] border-b border-[#E2E8F0] px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Left: Organization & Network Selector */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 text-xs font-medium text-[#718096]">
          <Building2 className="h-4 w-4 text-[#397C78]" />
          <span className="hidden sm:inline">Organization:</span>
          <span className="text-[#253443] font-semibold">State University Campus</span>
        </div>

        <span className="text-[#E2E8F0] hidden sm:inline">|</span>

        <div className="flex items-center space-x-2">
          <label htmlFor="network-select" className="text-xs font-medium text-[#718096] hidden md:inline">
            Active Twin:
          </label>
          <select
            id="network-select"
            value={currentNetwork?.id || ''}
            onChange={(e) => onSelectNetwork(e.target.value)}
            className="bg-[#F5F7F6] border border-[#E2E8F0] text-[#253443] text-xs font-medium rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-[#397C78] max-w-[240px] truncate"
          >
            {networks.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
              </option>
            ))}
          </select>

          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh network and telemetry data"
            className="p-1.5 rounded-lg border border-[#E2E8F0] text-[#718096] hover:text-[#253443] hover:bg-[#F5F7F6] transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin text-[#397C78]' : ''}`} />
          </button>
        </div>
      </div>

      {/* Right: Environment Badge, Demo Mode, Alerts & Profile */}
      <div className="flex items-center space-x-3">
        {/* Environment Status Badge */}
        <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[#80AAA1]/15 text-[#397C78] border border-[#80AAA1]/30">
          <ShieldCheck className="h-3.5 w-3.5 text-[#397C78]" />
          <span>Simulated Environment</span>
        </div>

        {/* Quick Action: Demo Mode for Hackathon Judges */}
        <button
          onClick={onStartDemoMode}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#397C78] hover:bg-[#2F6763] text-white text-xs font-semibold shadow-sm transition-colors"
          title="Run complete 9-step Hackathon Demonstration Walkthrough"
        >
          <PlayCircle className="h-3.5 w-3.5" />
          <span className="hidden lg:inline">Hackathon Demo Mode</span>
        </button>

        {/* PDF Assessment Export */}
        {currentNetwork && (
          <button
            onClick={handleExportPdf}
            disabled={isExporting}
            className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg border border-[#E2E8F0] bg-white hover:bg-[#F5F7F6] text-[#253443] text-xs font-medium transition-colors"
            title="Download PDF Assessment Report to your device"
          >
            <FileDown className={`h-3.5 w-3.5 text-[#397C78] ${isExporting ? 'animate-bounce' : ''}`} />
            <span className="hidden xl:inline">{isExporting ? 'Exporting...' : 'Export PDF'}</span>
          </button>
        )}

        {/* Threat Alerts Bell */}
        <div className="relative">
          <button 
            title="Active threat alerts"
            className="p-2 rounded-lg border border-[#E2E8F0] text-[#718096] hover:text-[#253443] hover:bg-[#F5F7F6] transition-colors"
          >
            <Bell className="h-4 w-4" />
          </button>
          {alertsCount > 0 && (
            <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-[#CE7373] text-white text-[10px] font-bold flex items-center justify-center">
              {alertsCount}
            </span>
          )}
        </div>

        {/* User Profile & Logout */}
        <div className="flex items-center space-x-2.5 pl-3 border-l border-[#E2E8F0]">
          <div className="h-8 w-8 rounded-full bg-[#397C78]/15 text-[#397C78] flex items-center justify-center font-bold text-xs border border-[#397C78]/30">
            {initials}
          </div>
          <div className="text-left hidden md:block">
            <span className="text-xs font-semibold text-[#253443] block leading-tight">
              {currentUser?.name || 'Lead Security Analyst'}
            </span>
            <span className="text-[10px] text-[#718096] block leading-tight">
              {currentUser?.role || 'SecOps Team'}
            </span>
          </div>

          <button
            onClick={onLogout}
            title="Log out of CyberTwin"
            className="p-1.5 text-slate-400 hover:text-[#CE7373] hover:bg-slate-100 rounded-lg transition-colors ml-1"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
