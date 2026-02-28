import React from 'react';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info' | 'muted';
  size?: 'sm' | 'md';
  className?: string;
  title?: string;
}

const variants: Record<NonNullable<BadgeProps['variant']>, string> = {
  default: 'bg-gray-700 text-gray-200',
  success: 'bg-emerald-900/60 text-emerald-300 border border-emerald-700/50',
  warning: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50',
  danger: 'bg-red-900/60 text-red-300 border border-red-700/50',
  info: 'bg-blue-900/60 text-blue-300 border border-blue-700/50',
  muted: 'bg-gray-800 text-gray-400',
};

export function Badge({ children, variant = 'default', size = 'sm', className = '', title }: BadgeProps) {
  return (
    <span
      title={title}
      className={`inline-flex items-center font-medium rounded-md whitespace-nowrap
        ${size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-1 text-sm'}
        ${variants[variant]} ${className}`}
    >
      {children}
    </span>
  );
}

/* ─── Confidence Badge ─── */
export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const v = confidence === 'high' ? 'danger' : confidence === 'medium' ? 'warning' : 'muted';
  return <Badge variant={v}>{confidence}</Badge>;
}

/* ─── Queue Badge ─── */
export function QueueBadge({ queue }: { queue: string }) {
  const v = queue === 'soc_malware' ? 'danger' : queue === 'soc_policy' ? 'warning' : queue === 'soc_dev' ? 'info' : 'muted';
  return <Badge variant={v} title={queue}>{queue.replace('soc_', '')}</Badge>;
}

/* ─── Score Badge ─── */
const SCORE_BAR: Record<string, string> = {
  danger:  'bg-red-400',
  warning: 'bg-yellow-400',
  info:    'bg-blue-400',
  muted:   'bg-gray-500',
};

export function ScoreBadge({ score }: { score: number }) {
  const v = score >= 80 ? 'danger' : score >= 60 ? 'warning' : score >= 40 ? 'info' : 'muted';
  return (
    <span
      title={`Score: ${score} / 100`}
      className={`relative inline-flex items-center font-medium rounded-md whitespace-nowrap
        overflow-hidden px-1.5 py-0.5 text-xs ${variants[v]}`}
    >
      <span className="relative z-10">{score}</span>
      {/* thin progress bar along the bottom edge */}
      <span
        className={`absolute bottom-0 left-0 h-[2px] ${SCORE_BAR[v]} opacity-70`}
        style={{ width: `${score}%` }}
        aria-hidden="true"
      />
    </span>
  );
}

/* ─── Status Badge ─── */
export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, BadgeProps['variant']> = {
    success: 'success', running: 'info', pending: 'muted', failed: 'danger',
  };
  return <Badge variant={map[status] ?? 'default'}>{status}</Badge>;
}
