import React from 'react';
import { useToastStore } from '@/stores';

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
        <div
          key={t.id}
          className={`flex items-start gap-2 rounded-lg px-4 py-3 shadow-lg text-sm border
            ${t.type === 'success' ? 'bg-emerald-950/90 border-emerald-800 text-emerald-200' : ''}
            ${t.type === 'error' ? 'bg-red-950/90 border-red-800 text-red-200' : ''}
            ${t.type === 'info' ? 'bg-blue-950/90 border-blue-800 text-blue-200' : ''}
          `}
        >
          <span className="flex-1">{t.message}</span>
          <button onClick={() => remove(t.id)} className="opacity-60 hover:opacity-100" aria-label="Dismiss notification">x</button>
        </div>
      ))}
    </div>
  );
}
