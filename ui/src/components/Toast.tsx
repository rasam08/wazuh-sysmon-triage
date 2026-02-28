import React, { useEffect, useState } from 'react';
import { useToastStore } from '@/stores';

function ToastItem({ id, type, message, onDismiss }: { id: string; type: string; message: string; onDismiss: (id: string) => void }) {
  const [exiting, setExiting] = useState(false);

  const handleDismiss = () => {
    setExiting(true);
    setTimeout(() => onDismiss(id), 200);
  };

  // Auto-trigger exit animation shortly before the store auto-removes
  // (store handles the actual removal; this just animates the exit)
  useEffect(() => {
    // Nothing needed — the parent will unmount us when the store removes the toast
  }, []);

  return (
    <div
      className={`flex items-start gap-2 rounded-lg px-4 py-3 shadow-lg text-sm border
        ${exiting ? 'toast-exit' : 'toast-enter'}
        ${type === 'success' ? 'bg-emerald-950/90 border-emerald-800 text-emerald-200' : ''}
        ${type === 'error' ? 'bg-red-950/90 border-red-800 text-red-200' : ''}
        ${type === 'info' ? 'bg-blue-950/90 border-blue-800 text-blue-200' : ''}
      `}
      role="alert"
    >
      {/* Icon */}
      <span className="flex-shrink-0 mt-0.5">
        {type === 'success' && (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="8" cy="8" r="6" opacity="0.3" />
            <path d="M5 8.5 7 10.5 11 5.5" />
          </svg>
        )}
        {type === 'error' && (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="8" cy="8" r="6" opacity="0.3" />
            <path d="M6 6l4 4M10 6l-4 4" />
          </svg>
        )}
        {type === 'info' && (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="8" cy="8" r="6" opacity="0.3" />
            <path d="M8 7v3M8 5.5v.5" />
          </svg>
        )}
      </span>
      <span className="flex-1">{message}</span>
      <button onClick={handleDismiss} className="opacity-60 hover:opacity-100 transition-opacity" aria-label="Dismiss notification">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <path d="M5 5l6 6M11 5l-6 6" />
        </svg>
      </button>
    </div>
  );
}

export function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts);
  const remove = useToastStore((s) => s.removeToast);

  return (
    <div
      className="fixed bottom-4 right-4 z-[60] flex flex-col gap-2 max-w-sm"
      aria-live="polite"
      aria-atomic="false"
      role="status"
    >
      {toasts.map((t) => (
        <ToastItem key={t.id} id={t.id} type={t.type} message={t.message} onDismiss={remove} />
      ))}
    </div>
  );
}
