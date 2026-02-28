import React from 'react';

/**
 * A thin progress bar fixed at the top of the viewport.
 * - `active` shows the indeterminate shimmer animation.
 * - Respects the `data-motion="disabled"` root attribute gracefully (CSS handles this).
 */
export function GlobalProgressBar({ active }: { active: boolean }) {
  if (!active) return null;

  return (
    <div
      className="fixed top-0 left-0 right-0 z-50 h-[2px] bg-gray-800/40 overflow-hidden"
      role="progressbar"
      aria-valuetext="Loading"
      aria-busy="true"
    >
      <div className="progress-bar-indeterminate h-full w-[40%] bg-gradient-to-r from-blue-500 via-blue-400 to-blue-500 rounded-full" />
    </div>
  );
}
