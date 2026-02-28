import React from 'react';

/**
 * A success checkmark that pops in with a brief animation.
 * Useful for "run completed", "saved", or "verified" confirmation.
 */
export function SuccessCheck({
  size = 48,
  label = 'Success',
  className = '',
}: {
  size?: number;
  label?: string;
  className?: string;
}) {
  const r = size / 2;
  return (
    <div className={`inline-flex flex-col items-center gap-2 check-pop ${className}`} role="status" aria-label={label}>
      <svg width={size} height={size} viewBox="0 0 48 48" fill="none">
        <circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="3" opacity="0.2" />
        <circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="3"
          strokeDasharray="138.23"
          strokeDashoffset="0"
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 500ms ease-out' }}
        />
        <path d="M14 24.5l7 7L34 17" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {label && <span className="text-xs text-emerald-400 font-medium">{label}</span>}
    </div>
  );
}

/**
 * Inline "Copied!" feedback icon — a small checkmark that replaces the copy icon briefly.
 */
export function CopiedIcon({ className = '' }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-1 text-emerald-400 text-xs font-medium check-pop ${className}`} role="status" aria-label="Copied">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3.5 8.5 6.5 11.5 12.5 4.5" />
      </svg>
      Copied
    </span>
  );
}
