import React, { useEffect, useRef, useState } from 'react';
import { Button } from './Button';

interface ConfirmModalProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
  variant?: 'danger' | 'primary';
}

export function ConfirmModal({ open, title, message, confirmLabel = 'Confirm', onConfirm, onCancel, variant = 'danger' }: ConfirmModalProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (open) {
      previousFocusRef.current = document.activeElement as HTMLElement | null;
      // Focus the cancel button on open
      const timer = setTimeout(() => {
        if (panelRef.current) {
          const btn = panelRef.current.querySelector<HTMLElement>('button');
          btn?.focus();
        }
      }, 50);
      return () => clearTimeout(timer);
    } else if (previousFocusRef.current) {
      previousFocusRef.current.focus();
      previousFocusRef.current = null;
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { onCancel(); return; }
      if (e.key !== 'Tab' || !panelRef.current) return;
      const focusable = panelRef.current.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last.focus(); }
      } else if (document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onCancel]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/60" onClick={onCancel} aria-hidden="true" />
      <div ref={panelRef} className="relative bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-md p-6">
        <h3 className="text-lg font-semibold text-gray-200 mb-2">{title}</h3>
        <p className="text-sm text-gray-400 mb-6">{message}</p>
        <div className="flex justify-end gap-3">
          <Button variant="secondary" size="sm" onClick={onCancel}>Cancel</Button>
          <Button variant={variant} size="sm" onClick={onConfirm}>{confirmLabel}</Button>
        </div>
      </div>
    </div>
  );
}

/** Hook to manage confirmation modals declaratively */
export function useConfirmModal() {
  const [state, setState] = useState<{ open: boolean; title: string; message: string; resolve?: (v: boolean) => void }>({
    open: false, title: '', message: '',
  });

  const confirm = (title: string, message: string): Promise<boolean> => {
    return new Promise((resolve) => {
      setState({ open: true, title, message, resolve });
    });
  };

  const modal = (
    <ConfirmModal
      open={state.open}
      title={state.title}
      message={state.message}
      onConfirm={() => { state.resolve?.(true); setState((s) => ({ ...s, open: false })); }}
      onCancel={() => { state.resolve?.(false); setState((s) => ({ ...s, open: false })); }}
    />
  );

  return { confirm, modal };
}
