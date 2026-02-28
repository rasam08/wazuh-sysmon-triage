import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useRunsStore } from '@/stores';

interface CommandItem {
  id: string;
  label: string;
  description?: string;
  group: string;
  action: () => void;
}

function IcoSearch() {
  return (
    <svg className="w-4 h-4 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="11" cy="11" r="8" strokeWidth={2} />
      <path d="m21 21-4.35-4.35" strokeWidth={2} strokeLinecap="round" />
    </svg>
  );
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const { runs } = useRunsStore();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((v) => !v);
        setQuery('');
        setSelected(0);
      }
      if (e.key === 'Escape' && open) {
        setOpen(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [open]);

  useEffect(() => {
    setSelected(0);
  }, [query]);

  const staticItems: CommandItem[] = [
    { id: 'nav-dash', label: 'Dashboard', description: 'Operational overview', group: 'Navigate', action: () => navigate('/dashboard') },
    { id: 'nav-alerts', label: 'Alert Workbench', description: 'Triage and review security alerts', group: 'Navigate', action: () => navigate('/alerts') },
    { id: 'nav-runs', label: 'Runs', description: 'Browse past triage runs', group: 'Navigate', action: () => navigate('/runs') },
    { id: 'nav-cases', label: 'Cases', description: 'Case folder overview', group: 'Navigate', action: () => navigate('/cases') },
    { id: 'nav-new', label: 'New Run', description: 'Start a new triage run', group: 'Navigate', action: () => navigate('/new-run') },
    { id: 'nav-sim', label: 'Scenario Gym', description: 'Simulate attack scenarios offline', group: 'Navigate', action: () => navigate('/simulate') },
    { id: 'nav-settings', label: 'Settings', description: 'Thresholds, display, suppression rules', group: 'Navigate', action: () => navigate('/settings') },
  ];

  const runItems: CommandItem[] = runs.slice(0, 12).map((run) => ({
    id: `case-${run.id}`,
    label: run.params.case_id,
    description: `${run.status} · ${run.params.mode} · ${run.params.profile}`,
    group: 'Jump to Case',
    action: () => navigate(`/alerts?case=${encodeURIComponent(run.params.case_id)}`),
  }));

  const allItems = [...staticItems, ...runItems];

  const filtered = query.trim()
    ? allItems.filter(
        (item) =>
          item.label.toLowerCase().includes(query.toLowerCase()) ||
          item.description?.toLowerCase().includes(query.toLowerCase()),
      )
    : allItems;

  const groups = Array.from(new Set(filtered.map((i) => i.group)));

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelected((s) => Math.min(s + 1, filtered.length - 1));
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelected((s) => Math.max(s - 1, 0));
    }
    if (e.key === 'Enter' && filtered[selected]) {
      filtered[selected].action();
      setOpen(false);
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
        onClick={() => setOpen(false)}
        aria-hidden="true"
      />
      <div className="relative w-full max-w-xl mx-4 bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
        {/* Input */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-800">
          <IcoSearch />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search pages, cases, alerts…"
            className="flex-1 bg-transparent text-gray-100 placeholder:text-gray-500 text-sm outline-none"
            aria-label="Command palette search"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="hidden sm:inline px-1.5 py-0.5 text-[10px] text-gray-600 bg-gray-800 border border-gray-700 rounded font-mono">
            esc
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto py-1.5" role="listbox" aria-label="Results">
          {filtered.length === 0 ? (
            <p className="px-4 py-8 text-center text-sm text-gray-500">No results for &ldquo;{query}&rdquo;</p>
          ) : (
            groups.map((group) => (
              <div key={group}>
                <p className="px-4 pt-3 pb-1 text-[10px] font-semibold text-gray-600 uppercase tracking-wider">
                  {group}
                </p>
                {filtered
                  .filter((i) => i.group === group)
                  .map((item) => {
                    const idx = filtered.indexOf(item);
                    return (
                      <button
                        key={item.id}
                        role="option"
                        aria-selected={idx === selected}
                        onClick={() => {
                          item.action();
                          setOpen(false);
                        }}
                        onMouseEnter={() => setSelected(idx)}
                        className={`w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${
                          idx === selected
                            ? 'bg-blue-600/20 text-gray-100'
                            : 'text-gray-300 hover:bg-gray-800/60'
                        }`}
                      >
                        <span className="text-sm font-medium shrink-0">{item.label}</span>
                        {item.description && (
                          <span className="text-xs text-gray-500 truncate">{item.description}</span>
                        )}
                      </button>
                    );
                  })}
              </div>
            ))
          )}
        </div>

        {/* Footer hints */}
        <div className="border-t border-gray-800 px-4 py-2 flex items-center gap-4 text-[10px] text-gray-600 font-mono">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> select</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
