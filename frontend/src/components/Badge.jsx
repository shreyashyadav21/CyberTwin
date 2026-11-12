import React from 'react';

export default function Badge({ children, variant = 'neutral', size = 'sm', className = '' }) {
  const variantStyles = {
    critical: 'bg-[#CE7373]/15 text-[#CE7373] border-[#CE7373]/30 font-semibold',
    danger: 'bg-[#CE7373]/15 text-[#CE7373] border-[#CE7373]/30 font-medium',
    high: 'bg-[#CE7373]/15 text-[#CE7373] border-[#CE7373]/30 font-medium',
    warning: 'bg-[#D5A45C]/15 text-[#D5A45C] border-[#D5A45C]/30 font-medium',
    medium: 'bg-[#D5A45C]/15 text-[#D5A45C] border-[#D5A45C]/30 font-medium',
    success: 'bg-[#5B9678]/15 text-[#5B9678] border-[#5B9678]/30 font-medium',
    low: 'bg-[#5B9678]/15 text-[#5B9678] border-[#5B9678]/30 font-medium',
    info: 'bg-[#397C78]/15 text-[#397C78] border-[#397C78]/30 font-medium',
    primary: 'bg-[#397C78]/15 text-[#397C78] border-[#397C78]/30 font-medium',
    neutral: 'bg-[#F5F7F6] text-[#718096] border-[#E2E8F0] font-medium',
  };

  const sizeStyles = {
    xs: 'px-1.5 py-0.5 text-[10px]',
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs',
  };

  return (
    <span
      className={`inline-flex items-center rounded-md border uppercase tracking-wider ${
        variantStyles[variant.toLowerCase()] || variantStyles.neutral
      } ${sizeStyles[size] || sizeStyles.sm} ${className}`}
    >
      {children}
    </span>
  );
}

