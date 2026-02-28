import React from 'react';

export function LoadingSpinner({ label = 'Loading...' }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-gray-500">
      <svg className="animate-spin h-8 w-8 mb-3" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
      </svg>
      <p className="text-sm">{label}</p>
    </div>
  );
}

export function EmptyState({ title, description, action }: { title: string; description?: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="text-2xl mb-4 text-gray-600">No data</div>
      <h3 className="text-lg font-semibold text-gray-300 mb-1">{title}</h3>
      {description && <p className="text-sm text-gray-500 max-w-md mb-4">{description}</p>}
      {action}
    </div>
  );
}

export function ErrorPanel({ title = 'Error', message, onRetry, onCopy }: { title?: string; message: string; onRetry?: () => void; onCopy?: () => void }) {
  return (
    <div className="bg-red-950/40 border border-red-800/50 rounded-lg p-4">
      <div className="flex items-start gap-2">
        <span className="text-red-400 text-lg">!</span>
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-semibold text-red-300">{title}</h4>
          <pre className="text-xs text-red-400/80 mt-1 whitespace-pre-wrap break-all">{message}</pre>
          <div className="flex gap-2 mt-3">
            {onRetry && (
              <button onClick={onRetry} className="text-xs text-red-300 hover:text-red-200 underline">
                Retry
              </button>
            )}
            {onCopy && (
              <button onClick={onCopy} className="text-xs text-red-300 hover:text-red-200 underline">
                Copy Error
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
