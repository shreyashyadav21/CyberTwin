import React from 'react';
import { 
  LayoutDashboard, 
  Network, 
  ShieldAlert, 
  Cpu, 
  Radio, 
  AlertOctagon, 
  SlidersHorizontal, 
  FileText, 
  Settings,
  Shield
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'network-twin', label: 'Network Twin', icon: Network },
  { id: 'assessment', label: 'Security Assessment', icon: ShieldAlert },
  { id: 'simulator', label: 'Attack Simulation Lab', icon: Cpu },
  { id: 'monitoring', label: 'Threat Monitoring', icon: Radio },
  { id: 'incidents', label: 'Incident Response', icon: AlertOctagon },
  { id: 'controls', label: 'Security Controls', icon: SlidersHorizontal },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export default function Sidebar({ activeTab, onSelectTab, alertsCount = 0, incidentsCount = 0 }) {
  return (
    <aside className="w-64 bg-[#202E39] text-slate-100 flex flex-col shrink-0 min-h-screen border-r border-[#1B2731]">
      {/* Brand Header */}
      <div className="p-5 border-b border-[#2A3B49]">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-lg bg-[#397C78] flex items-center justify-center text-white shadow-sm">
            <Shield className="h-5 w-5 stroke-[2.2]" />
          </div>
          <div>
            <span className="text-lg font-bold tracking-tight text-white block">
              CyberTwin
            </span>
            <span className="text-[11px] text-[#80AAA1] font-medium tracking-wide">
              Simulate • Detect • Defend
            </span>
          </div>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 py-4 px-3 space-y-1">
        <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          Digital Twin Modules
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-[#397C78] text-white shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-[#2A3B49]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`h-4 w-4 ${isActive ? 'text-white' : 'text-[#80AAA1]'}`} />
                <span>{item.label}</span>
              </div>

              {/* Dynamic notification counts */}
              {item.id === 'monitoring' && alertsCount > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-[#CE7373] text-white">
                  {alertsCount}
                </span>
              )}
              {item.id === 'incidents' && incidentsCount > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-[#D5A45C] text-[#202E39]">
                  {incidentsCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom Status Panel */}
      <div className="p-4 border-t border-[#2A3B49] bg-[#1B2731]/60">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span>Engine Status</span>
          <span className="flex items-center space-x-1.5 text-[#5B9678] font-medium">
            <span className="h-2 w-2 rounded-full bg-[#5B9678] inline-block animate-pulse" />
            <span>Operational</span>
          </span>
        </div>
        <p className="text-[11px] text-slate-400 leading-tight">
          Safe isolated virtual simulation model.
        </p>
      </div>
    </aside>
  );
}

