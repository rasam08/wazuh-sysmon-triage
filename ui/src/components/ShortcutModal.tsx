import React, { useEffect } from 'react';

interface ShortcutGroup {
  group: string;
  shortcuts: { keys: string[]; description: string }[];
}

const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    group: 'Navigation',
    shortcuts: [
      { keys: ['j'], description: 'Select next alert' },
      { keys: ['k'], description: 'Select previous alert' },
      { keys: ['Ctrl', 'K'], description: 'Open command palette' },
    ],
  },
  {
    group: 'Alert actions',
    shortcuts: [
      { keys: ['e'], description: 'Toggle escalate on current/selected alert' },
      { keys: ['f'], description: 'Toggle false positive on current/selected alert' },
      { keys: ['p'], description: 'Pin / bookmark current alert' },
    ],
  },
  {
    group: 'Detail drawer',
    shortcuts: [
      { keys: ['1'], description: 'Overview tab' },
      { keys: ['2'], description: 'Explain tab' },
      { keys: ['3'], description: 'Process Context tab' },
      { keys: ['4'], description: 'Network Context tab' },
      { keys: ['5'], description: 'Related Alerts tab' },
      { keys: ['6'], description: 'Rule Metadata tab' },
    ],
  },
  {
    group: 'General',
    shortcuts: [
      { keys: ['?'], description: 'Show this help' },
      { keys: ['Esc'], description: 'Close drawer / dismiss' },
    ],
  },
];

interface ShortcutModalProps {
  open: boolean;
  onClose: () => void;
}

export function ShortcutModal({ open, onClose }: ShortcutModalProps) {
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center bg-black/70 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Keyboard shortcuts"
      onClick={onClose}
    >
      <div
        className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-200 tracking-wide uppercase">
            Keyboard Shortcuts
          </h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition-colors"
            aria-label="Close shortcuts"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-5 max-h-[70vh] overflow-y-auto">
          {SHORTCUT_GROUPS.map((group) => (
            <div key={group.group}>
              <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2">
                {group.group}
              </p>
              <div className="space-y-1.5">
                {group.shortcuts.map((sc) => (
                  <div key={sc.keys.join('+')} className="flex items-center justify-between gap-4">
                    <span className="text-sm text-gray-400">{sc.description}</span>
                    <span className="flex items-center gap-1 flex-shrink-0">
                      {sc.keys.map((k, idx) => (
                        <React.Fragment key={k}>
                          {idx > 0 && <span className="text-gray-600 text-xs">+</span>}
                          <kbd className="inline-flex items-center justify-center min-w-[26px] h-[22px] px-1.5 bg-gray-800 border border-gray-700 rounded text-[11px] font-mono text-gray-300 shadow-sm">
                            {k}
                          </kbd>
                        </React.Fragment>
                      ))}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="px-5 py-3 border-t border-gray-800 text-center">
          <p className="text-xs text-gray-600">Press <kbd className="inline-flex items-center justify-center min-w-[22px] h-[18px] px-1 bg-gray-800 border border-gray-700 rounded text-[10px] font-mono text-gray-400">Esc</kbd> or click outside to close</p>
        </div>
      </div>
    </div>
  );
}
