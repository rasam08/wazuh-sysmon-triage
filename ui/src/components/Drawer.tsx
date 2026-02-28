import React, { useCallback, useEffect, useRef, useState } from 'react';

function IcoExpand({ expanded }: { expanded: boolean }) {
  return expanded ? (
    <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true">
      <path d="M10 2h4v4M6 14H2v-4M2 6V2h4M14 10v4h-4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ) : (
    <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true">
      <path d="M2 6V2h4M10 2h4v4M14 10v4h-4M6 14H2v-4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  width?: string;
  children: React.ReactNode;
}

function useFocusTrap(ref: React.RefObject<HTMLElement | null>, active: boolean) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key !== 'Tab' || !ref.current) return;
      const focusable = ref.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else if (document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    },
    [ref],
  );

  useEffect(() => {
    if (!active) return;
    document.addEventListener('keydown', handleKeyDown);
    // Focus the first focusable element on open
    const timer = setTimeout(() => {
      if (ref.current) {
        const first = ref.current.querySelector<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        first?.focus();
      }
    }, 50);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      clearTimeout(timer);
    };
  }, [active, handleKeyDown, ref]);
}

export function Drawer({ open, onClose, title, width = 'w-[520px]', children }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const [visible, setVisible] = useState(false);
  const [closing, setClosing] = useState(false);
  const [expanded, setExpanded] = useState(false);

  useFocusTrap(panelRef, open);

  // Handle open/close transitions
  useEffect(() => {
    if (open) {
      previousFocusRef.current = document.activeElement as HTMLElement | null;
      setVisible(true);
      setClosing(false);
    } else if (visible) {
      // Start exit animation
      setClosing(true);
    }
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleAnimationEnd = useCallback(() => {
    if (closing) {
      setVisible(false);
      setClosing(false);
      if (previousFocusRef.current) {
        previousFocusRef.current.focus();
        previousFocusRef.current = null;
      }
    }
  }, [closing]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (open) document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!visible) return null;

  const effectiveWidth = expanded ? 'w-[90vw] max-w-[1200px]' : width;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label={title ?? 'Details'}>
      {/* Backdrop */}
      <div
        className={`absolute inset-0 bg-black/50 transition-opacity duration-200 ${closing ? 'opacity-0' : 'opacity-100'}`}
        onClick={onClose}
        aria-hidden="true"
      />
      {/* Panel */}
      <div
        ref={panelRef}
        className={`relative ${effectiveWidth} max-w-full bg-gray-900 border-l border-gray-800 shadow-2xl flex flex-col transition-[width] duration-150`}
        style={{ animation: `${closing ? 'slideOut' : 'slideIn'} 200ms ease-out forwards` }}
        onAnimationEnd={handleAnimationEnd}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-200 truncate">{title ?? 'Details'}</h2>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setExpanded((e) => !e)}
              className="text-gray-500 hover:text-gray-300 p-1.5 rounded hover:bg-gray-800 transition-colors"
              aria-label={expanded ? 'Collapse to drawer' : 'Expand to full panel'}
              title={expanded ? 'Collapse to drawer' : 'Expand to full panel'}
            >
              <IcoExpand expanded={expanded} />
            </button>
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-gray-300 p-1.5 rounded hover:bg-gray-800 text-lg leading-none transition-colors"
              aria-label="Close drawer"
            >
              ×
            </button>
          </div>
        </div>
        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">{children}</div>
      </div>
      <style>{`
        @keyframes slideIn {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
        @keyframes slideOut {
          from { transform: translateX(0); }
          to { transform: translateX(100%); }
        }
      `}</style>
    </div>
  );
}
