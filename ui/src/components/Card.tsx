import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  title?: string;
  actions?: React.ReactNode;
}

export function Card({ children, className = '', title, actions }: CardProps) {
  return (
    <div className={`bg-gray-900 border border-gray-800 rounded-lg ${className}`}>
      {(title || actions) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
          {title && <h3 className="text-sm font-semibold text-gray-200">{title}</h3>}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

/* ─── KPI Tile ─── */
interface KpiTileProps {
  label: string;
  value: string | number;
  subtext?: string;
  variant?: 'default' | 'danger' | 'warning' | 'success';
  onClick?: () => void;
}

const kpiVariants = {
  default: 'text-white',
  danger: 'text-red-400',
  warning: 'text-yellow-400',
  success: 'text-emerald-400',
};

export function KpiTile({ label, value, subtext, variant = 'default', onClick }: KpiTileProps) {
  const interactive = Boolean(onClick);
  return (
    <div
      onClick={onClick}
      onKeyDown={interactive ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick?.(); } } : undefined}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      className={`bg-gray-900 border border-gray-800 rounded-lg p-4 ${interactive ? 'cursor-pointer hover:border-gray-600 transition-colors focus-visible:ring-2 focus-visible:ring-blue-500' : ''}`}
    >
      <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">{label}</p>
      <p className={`text-2xl font-bold ${kpiVariants[variant]}`}>{value}</p>
      {subtext && <p className="text-xs text-gray-500 mt-1">{subtext}</p>}
    </div>
  );
}
