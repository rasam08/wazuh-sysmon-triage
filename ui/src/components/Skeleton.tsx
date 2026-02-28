import React from 'react';

/* ─── Primitive Skeleton shapes ─── */

interface SkeletonProps {
  className?: string;
  width?: string | number;
  height?: string | number;
}

/**
 * A single shimmering placeholder rectangle.
 */
export function Skeleton({ className = '', width, height }: SkeletonProps) {
  return (
    <div
      className={`skeleton ${className}`}
      style={{ width, height }}
      aria-hidden="true"
    />
  );
}

/**
 * A one-line text skeleton (defaults to full width, 0.875rem height).
 */
export function SkeletonText({ width = '100%', className = '' }: { width?: string | number; className?: string }) {
  return <Skeleton className={`h-3.5 ${className}`} width={width} />;
}

/* ─── Composite skeletons for common layouts ─── */

/**
 * KPI tiles row (3 shimmer tiles).
 */
export function SkeletonKpiRow({ count = 3 }: { count?: number }) {
  return (
    <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${count}, minmax(0, 1fr))` }}>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
          <Skeleton width="40%" height={12} />
          <Skeleton width="60%" height={28} />
        </div>
      ))}
    </div>
  );
}

/**
 * Table skeleton (header + n rows).
 */
export function SkeletonTable({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      {/* header */}
      <div className="flex gap-4 px-4 py-3 border-b border-gray-800">
        {Array.from({ length: cols }, (_, i) => (
          <Skeleton key={i} width={i === 0 ? '20%' : '14%'} height={12} />
        ))}
      </div>
      {/* rows */}
      {Array.from({ length: rows }, (_, ri) => (
        <div key={ri} className="flex gap-4 px-4 py-3 border-b border-gray-800/50">
          {Array.from({ length: cols }, (_, ci) => (
            <Skeleton key={ci} width={ci === 0 ? '25%' : `${10 + Math.random() * 12}%`} height={14} />
          ))}
        </div>
      ))}
    </div>
  );
}

/**
 * Card skeleton (title bar + body skeleton).
 */
export function SkeletonCard() {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg">
      <div className="px-4 py-3 border-b border-gray-800">
        <Skeleton width="30%" height={14} />
      </div>
      <div className="p-4 space-y-3">
        <Skeleton width="100%" height={14} />
        <Skeleton width="85%" height={14} />
        <Skeleton width="60%" height={14} />
      </div>
    </div>
  );
}

/**
 * Dashboard skeleton — KPI row + 2 card skeletons.
 */
export function SkeletonDashboard() {
  return (
    <div className="space-y-6 animate-fade-in-up">
      <div className="space-y-1">
        <Skeleton width={180} height={24} />
        <Skeleton width={240} height={14} />
      </div>
      <SkeletonKpiRow count={4} />
      <div className="grid grid-cols-2 gap-4">
        <SkeletonCard />
        <SkeletonCard />
      </div>
      <SkeletonTable rows={4} cols={6} />
    </div>
  );
}
