import React, { useState, useCallback } from 'react';
import { Button } from '@/components';
import type { AlertFilters, AlertSort, AlertQueue, AlertCategory, Confidence } from '@/types';

const QUEUE_OPTIONS: AlertQueue[] = ['soc_malware', 'soc_policy', 'soc_dev', 'soc_info'];
const CATEGORY_OPTIONS: AlertCategory[] = [
  'malware_execution',
  'c2_outbound',
  'persistence',
  'policy_violation',
  'developer_tooling',
];
const CONFIDENCE_OPTIONS: Confidence[] = ['high', 'medium', 'low'];
const PRESETS_KEY = 'wst-filter-presets';

interface FilterPreset {
  name: string;
  filters: AlertFilters;
  sort: AlertSort;
}

interface AlertFilterBarProps {
  filters: AlertFilters;
  sort: AlertSort;
  totalAlerts: number;
  filteredCount: number;
  setFilters: (partial: Partial<AlertFilters>) => void;
  setSort: (sort: AlertSort) => void;
  resetFilters: () => void;
}

function toggleFilter<T extends string>(arr: T[], val: T): T[] {
  return arr.includes(val) ? arr.filter((x) => x !== val) : [...arr, val];
}

export function AlertFilterBar({
  filters,
  sort,
  totalAlerts,
  filteredCount,
  setFilters,
  setSort,
  resetFilters,
}: AlertFilterBarProps) {
  const [presetName, setPresetName] = useState('');

  const loadPresets = useCallback((): FilterPreset[] => {
    try {
      return JSON.parse(localStorage.getItem(PRESETS_KEY) ?? '[]') as FilterPreset[];
    } catch {
      return [];
    }
  }, []);

  const [presets, setPresets] = useState<FilterPreset[]>(loadPresets);

  const savePreset = useCallback(() => {
    const name = presetName.trim();
    if (!name) return;
    const updated = [...presets.filter((p) => p.name !== name), { name, filters, sort }];
    localStorage.setItem(PRESETS_KEY, JSON.stringify(updated));
    setPresets(updated);
    setPresetName('');
  }, [presetName, presets, filters, sort]);

  const applyPreset = useCallback((preset: FilterPreset) => {
    resetFilters();
    setFilters(preset.filters);
    setSort(preset.sort);
  }, [resetFilters, setFilters, setSort]);

  const deletePreset = useCallback((name: string) => {
    const updated = presets.filter((p) => p.name !== name);
    localStorage.setItem(PRESETS_KEY, JSON.stringify(updated));
    setPresets(updated);
  }, [presets]);
  return (
    <div
      className="flex-shrink-0 bg-gray-900 border border-gray-800 rounded-lg p-3 mb-4 space-y-3"
      role="search"
      aria-label="Alert filters"
    >
      {/* Top row: search, sort, counts */}
      <div className="flex items-center gap-3 flex-wrap">
        <input
          placeholder="Search alerts…"
          value={filters.search}
          onChange={(e) => setFilters({ search: e.target.value })}
          aria-label="Search alerts by text"
          className="flex-1 min-w-[160px] max-w-xs bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200
            placeholder:text-gray-600 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500/30"
        />

        {/* Sort toggles */}
        <div className="flex items-center gap-1 text-xs text-gray-500" role="group" aria-label="Sort options">
          <span>Sort:</span>
          {(['score', 'utc_time', 'confidence'] as const).map((field) => (
            <button
              key={field}
              onClick={() =>
                setSort({
                  field,
                  direction:
                    sort.field === field && sort.direction === 'desc' ? 'asc' : 'desc',
                })
              }
              aria-pressed={sort.field === field}
              className={`px-2 py-1 rounded transition-colors ${
                sort.field === field
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {field === 'utc_time' ? 'newest' : field}
              {sort.field === field ? (sort.direction === 'desc' ? ' ↓' : ' ↑') : ''}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1.5 ml-auto text-xs">
          <span className="text-gray-500">
            {filteredCount} of {totalAlerts} alerts
          </span>
          <span className="text-gray-600 hidden lg:inline">
            Shortcuts: j/k navigate · e escalate · f false positive
          </span>
          <Button variant="ghost" size="sm" onClick={resetFilters}>
            Clear
          </Button>
        </div>
      </div>

      {/* Filter chips */}
      <div className="flex flex-wrap gap-4">
        {/* Queue */}
        <fieldset className="flex items-center gap-1">
          <legend className="text-xs text-gray-500 mr-1 sr-only">Filter by queue</legend>
          <span className="text-xs text-gray-500 mr-1" aria-hidden="true">Queue:</span>
          {QUEUE_OPTIONS.map((queue) => (
            <button
              key={queue}
              onClick={() => setFilters({ queues: toggleFilter(filters.queues, queue) })}
              aria-pressed={filters.queues.includes(queue)}
              title={queue}
              className={`px-2 py-0.5 rounded text-xs transition-colors ${
                filters.queues.includes(queue)
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {queue.replace('soc_', '')}
            </button>
          ))}
        </fieldset>

        {/* Category */}
        <fieldset className="flex items-center gap-1 flex-wrap">
          <legend className="text-xs text-gray-500 mr-1 sr-only">Filter by category</legend>
          <span className="text-xs text-gray-500 mr-1" aria-hidden="true">Category:</span>
          {CATEGORY_OPTIONS.map((category) => (
            <button
              key={category}
              onClick={() => setFilters({ categories: toggleFilter(filters.categories, category) })}
              aria-pressed={filters.categories.includes(category)}
              className={`px-2 py-0.5 rounded text-xs transition-colors ${
                filters.categories.includes(category)
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {category.replace(/_/g, ' ')}
            </button>
          ))}
        </fieldset>

        {/* Confidence */}
        <fieldset className="flex items-center gap-1">
          <legend className="text-xs text-gray-500 mr-1 sr-only">Filter by confidence</legend>
          <span className="text-xs text-gray-500 mr-1" aria-hidden="true">Confidence:</span>
          {CONFIDENCE_OPTIONS.map((conf) => (
            <button
              key={conf}
              onClick={() => setFilters({ confidences: toggleFilter(filters.confidences, conf) })}
              aria-pressed={filters.confidences.includes(conf)}
              className={`px-2 py-0.5 rounded text-xs transition-colors ${
                filters.confidences.includes(conf)
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {conf}
            </button>
          ))}
        </fieldset>

        {/* Score range */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">Score:</span>
          <input
            type="number"
            min={0}
            max={100}
            value={filters.score_min}
            onChange={(e) => setFilters({ score_min: Number(e.target.value) })}
            aria-label="Minimum score filter"
            className="w-14 bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          />
          <span className="text-gray-600">–</span>
          <input
            type="number"
            min={0}
            max={100}
            value={filters.score_max}
            onChange={(e) => setFilters({ score_max: Number(e.target.value) })}
            aria-label="Maximum score filter"
            className="w-14 bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Filter presets */}
      <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-gray-800/60">
        <span className="text-xs text-gray-600">Presets:</span>
        {presets.map((preset) => (
          <span key={preset.name} className="flex items-center gap-0.5">
            <button
              onClick={() => applyPreset(preset)}
              className="px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200 transition-colors"
            >
              {preset.name}
            </button>
            <button
              onClick={() => deletePreset(preset.name)}
              className="text-gray-700 hover:text-red-400 text-[10px] px-0.5 transition-colors"
              aria-label={`Delete preset ${preset.name}`}
            >
              ×
            </button>
          </span>
        ))}
        <input
          value={presetName}
          onChange={(e) => setPresetName(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') savePreset(); }}
          placeholder="Save as…"
          className="w-28 bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-300 placeholder:text-gray-700 focus:border-blue-500 focus:outline-none"
        />
        <Button size="sm" variant="ghost" onClick={savePreset} disabled={!presetName.trim()}>
          Save
        </Button>
      </div>
    </div>
  );
}
