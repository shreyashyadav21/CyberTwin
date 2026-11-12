import React from 'react';

export function Card({ children, className = '', title, subtitle, action }) {
  return (
    <div className={`bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl shadow-sm overflow-hidden ${className}`}>
      {(title || subtitle || action) && (
        <div className="px-5 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
          <div>
            {title && <h3 className="text-sm font-semibold text-[#253443] tracking-tight">{title}</h3>}
            {subtitle && <p className="text-xs text-[#718096] mt-0.5">{subtitle}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}

export function StatCard({ label, value, subtext, icon: Icon, badge, color = 'primary' }) {
  const colorMap = {
    primary: 'bg-[#397C78]/10 text-[#397C78] border-[#397C78]/20',
    danger: 'bg-[#CE7373]/10 text-[#CE7373] border-[#CE7373]/20',
    warning: 'bg-[#D5A45C]/10 text-[#D5A45C] border-[#D5A45C]/20',
    success: 'bg-[#5B9678]/10 text-[#5B9678] border-[#5B9678]/20',
  };

  return (
    <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl p-5 shadow-sm hover:border-[#80AAA1] transition-all">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-[#718096] uppercase tracking-wider">{label}</p>
          <div className="text-2xl font-bold text-[#253443] mt-1 tracking-tight">{value}</div>
        </div>
        {Icon && (
          <div className={`p-2.5 rounded-lg border ${colorMap[color] || colorMap.primary}`}>
            <Icon className="h-5 w-5" />
          </div>
        )}
      </div>
      {(subtext || badge) && (
        <div className="mt-3 flex items-center justify-between text-xs text-[#718096] border-t border-[#EDF2F7] pt-2.5">
          <span>{subtext}</span>
          {badge}
        </div>
      )}
    </div>
  );
}

export default Card;

