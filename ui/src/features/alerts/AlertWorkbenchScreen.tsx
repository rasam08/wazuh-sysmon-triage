import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  createColumnHelper,
  flexRender,
  type SortingState,
} from '@tanstack/react-table';
import { useAlertsStore, useToastStore, useAlertAnnotationsStore, useSettingsStore } from '@/stores';
import { filterAlerts, sortAlerts } from '@/data/parsers';
import { fetchAlertBundle } from '@/data/api';
import {
  Button, Drawer, ScoreBadge, QueueBadge, ConfidenceBadge, Badge, LoadingSpinner, EmptyState,
} from '@/components';
import { exportAlert, openBundleInTab, copyToClipboard } from '@/utils/exports';
import { formatDateTime, formatTime } from '@/utils/datetime';
import type { Alert, AlertBundle, AlertQueue, AlertCategory, Confidence, AlertFilters } from '@/types';

const col = createColumnHelper<Alert>();
const QUEUE_OPTIONS: AlertQueue[] = ['soc_malware', 'soc_policy', 'soc_dev', 'soc_info'];
const CATEGORY_OPTIONS: AlertCategory[] = ['malware_execution', 'c2_outbound', 'persistence', 'policy_violation', 'developer_tooling'];
const CONFIDENCE_OPTIONS: Confidence[] = ['high', 'medium', 'low'];
const TABS = ['overview', 'explain', 'process', 'network', 'related', 'rule'] as const;

function buildPivotQuery(alert: Alert, caseId?: string | null) {
  const time = new Date(alert.utc_time).getTime();
  const hasTime = Number.isFinite(time);
  const start = hasTime ? new Date(time - 10 * 60_000).toISOString() : undefined;
  const end = hasTime ? new Date(time + 10 * 60_000).toISOString() : undefined;

  return {
    case_id: caseId ?? undefined,
    pivot: {
      alert_id: alert.alert_id,
      process_guid: alert.process_guid || undefined,
      image: alert.image || undefined,
      parent_image: alert.parent_image || undefined,
      destination_ip: alert.destination_ip || undefined,
      destination_port: alert.destination_port ?? undefined,
      utc_time_window: { start, end },
      tags: alert.tags,
    },
    context: {
      score: alert.score,
      queue: alert.queue,
      confidence: alert.confidence,
      category: alert.category,
    },
  };
}

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
}

export default function AlertWorkbenchScreen() {
  const [searchParams] = useSearchParams();
  const {
    alerts,
    activeCaseId,
    loading,
    filters,
    sort,
    selectedAlertId,
    fetchAlerts: loadAlerts,
    setFilters,
    setSort,
    selectAlert,
    resetFilters,
  } = useAlertsStore();
  const alertsPageSize = useSettingsStore((s) => s.display.alerts_page_size);
  const monospaceCommands = useSettingsStore((s) => s.display.monospace_commands);
  const showProcessGuids = useSettingsStore((s) => s.display.show_process_guids);
  const dateFormat = useSettingsStore((s) => s.display.date_format);
  const addToast = useToastStore((s) => s.addToast);
  const annotations = useAlertAnnotationsStore();

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [bundle, setBundle] = useState<AlertBundle | null>(null);
  const [bundleLoading, setBundleLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<(typeof TABS)[number]>('overview');
  const [noteText, setNoteText] = useState('');
  const [sorting, setSorting] = useState<SortingState>([]);
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: alertsPageSize });
  const queryKey = searchParams.toString();

  useEffect(() => {
    const params = new URLSearchParams(queryKey);
    const caseId = params.get('case') || undefined;
    const confidence = params.get('confidence');
    const queue = params.get('queue');
    const category = params.get('category');
    const search = params.get('search');
    const scoreMin = params.get('score_min');
    const scoreMax = params.get('score_max');

    resetFilters();
    const patch: Partial<AlertFilters> = {};
    if (confidence && CONFIDENCE_OPTIONS.includes(confidence as Confidence)) {
      patch.confidences = [confidence as Confidence];
    }
    if (queue) {
      const queues = queue.split(',').map((q) => q.trim()).filter((q): q is AlertQueue => QUEUE_OPTIONS.includes(q as AlertQueue));
      if (queues.length) patch.queues = queues;
    }
    if (category) {
      const categories = category
        .split(',')
        .map((c) => c.trim())
        .filter((c): c is AlertCategory => CATEGORY_OPTIONS.includes(c as AlertCategory));
      if (categories.length) patch.categories = categories;
    }
    if (search) patch.search = search;
    if (scoreMin && !Number.isNaN(Number(scoreMin))) patch.score_min = Number(scoreMin);
    if (scoreMax && !Number.isNaN(Number(scoreMax))) patch.score_max = Number(scoreMax);
    if (Object.keys(patch).length > 0) setFilters(patch);

    void loadAlerts(caseId);
  }, [queryKey, loadAlerts, resetFilters, setFilters]);

  useEffect(() => {
    setPagination((p) => ({ ...p, pageSize: alertsPageSize, pageIndex: 0 }));
  }, [alertsPageSize]);

  const processed = useMemo(() => {
    const filtered = filterAlerts(alerts, filters);
    return sortAlerts(filtered, sort);
  }, [alerts, filters, sort]);

  const selectedAlert = useMemo(
    () => alerts.find((a) => a.alert_id === selectedAlertId),
    [alerts, selectedAlertId],
  );

  const openAlert = useCallback(async (id: string) => {
    selectAlert(id);
    setDrawerOpen(true);
    setActiveTab('overview');
    setBundleLoading(true);
    try {
      const caseId = activeCaseId ?? new URLSearchParams(queryKey).get('case');
      if (!caseId) {
        addToast('error', 'No case context selected for alert bundle');
        setBundle(null);
        return;
      }
      const loaded = await fetchAlertBundle(id, caseId);
      setBundle(loaded ?? null);
    } catch (e) {
      setBundle(null);
      addToast('error', `Failed to load alert bundle: ${(e as Error).message}`);
    } finally {
      setBundleLoading(false);
    }
  }, [activeCaseId, queryKey, selectAlert, addToast]);

  const navigateSelection = useCallback((delta: 1 | -1) => {
    if (processed.length === 0) return;
    const currentIndex = selectedAlertId
      ? processed.findIndex((alert) => alert.alert_id === selectedAlertId)
      : -1;
    const nextIndex = currentIndex < 0
      ? (delta > 0 ? 0 : processed.length - 1)
      : (currentIndex + delta + processed.length) % processed.length;
    void openAlert(processed[nextIndex].alert_id);
  }, [openAlert, processed, selectedAlertId]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey) return;
      if (isTypingTarget(event.target)) return;

      const key = event.key.toLowerCase();
      if (key === 'j') {
        event.preventDefault();
        navigateSelection(1);
        return;
      }
      if (key === 'k') {
        event.preventDefault();
        navigateSelection(-1);
        return;
      }

      const currentAlert = selectedAlert ?? processed[0];
      if (!currentAlert) return;

      if (key === 'e') {
        event.preventDefault();
        annotations.toggleEscalated(currentAlert.alert_id);
        const isEsc = annotations.isEscalated(currentAlert.alert_id);
        addToast('success', isEsc ? `Escalated ${currentAlert.alert_id}` : `Escalation removed for ${currentAlert.alert_id}`);
        void openAlert(currentAlert.alert_id);
        return;
      }

      if (key === 'f') {
        event.preventDefault();
        annotations.toggleFalsePositive(currentAlert.alert_id);
        const isFp = annotations.isFalsePositive(currentAlert.alert_id);
        addToast('success', isFp ? `Marked ${currentAlert.alert_id} as false positive` : `Removed false positive mark for ${currentAlert.alert_id}`);
        void openAlert(currentAlert.alert_id);
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [addToast, annotations, navigateSelection, openAlert, processed, selectedAlert]);

  const columns = useMemo(() => [
    col.accessor('alert_id', {
      header: 'Alert ID',
      cell: (i) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            void openAlert(i.getValue());
          }}
          className="text-blue-400 hover:underline font-mono text-xs"
        >
          {i.getValue()}
        </button>
      ),
      size: 90,
    }),
    col.accessor('utc_time', {
      header: 'Time',
      cell: (i) => <span className="text-xs text-gray-400 tabular-nums">{formatTime(i.getValue(), dateFormat)}</span>,
      size: 88,
    }),
    col.accessor('score', { header: 'Score', cell: (i) => <ScoreBadge score={i.getValue()} />, size: 64 }),
    col.accessor('alert_type', { header: 'Type', cell: (i) => <span className="text-xs text-gray-400">{i.getValue()}</span>, size: 120 }),
    col.accessor('category', {
      header: 'Category',
      cell: (i) => <span className="text-xs text-gray-300">{i.getValue().replace(/_/g, ' ')}</span>,
      size: 130,
    }),
    col.accessor('queue', { header: 'Queue', cell: (i) => <QueueBadge queue={i.getValue()} />, size: 95 }),
    col.accessor('confidence', { header: 'Conf.', cell: (i) => <ConfidenceBadge confidence={i.getValue()} />, size: 80 }),
    col.accessor('image', {
      header: 'Image',
      cell: (i) => (
        <span className={`text-xs text-gray-300 truncate block max-w-[180px] ${monospaceCommands ? 'font-mono' : ''}`} title={i.getValue()}>
          {i.getValue().split('\\').pop()}
        </span>
      ),
      size: 150,
    }),
    col.accessor('reason', {
      header: 'Reason',
      cell: (i) => <span className="text-xs text-gray-400 truncate block max-w-[260px]" title={i.getValue()}>{i.getValue()}</span>,
      size: 240,
    }),
  ], [openAlert, monospaceCommands, dateFormat]);

  const table = useReactTable({
    data: processed,
    columns,
    state: { sorting, pagination },
    onSortingChange: setSorting,
    onPaginationChange: setPagination,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  const toggleFilter = <T extends string>(arr: T[], val: T, setter: (v: T[]) => void) => {
    setter(arr.includes(val) ? arr.filter((x) => x !== val) : [...arr, val]);
  };

  if (loading && !alerts.length) return <LoadingSpinner label="Loading alerts..." />;

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)]">
      <div className="flex-shrink-0 bg-gray-900 border border-gray-800 rounded-lg p-3 mb-4 space-y-3">
        <div className="flex items-center gap-3">
          <input
            placeholder="Search alerts..."
            value={filters.search}
            onChange={(e) => setFilters({ search: e.target.value })}
            aria-label="Search alerts"
            className="flex-1 max-w-xs bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
          />
          <div className="flex items-center gap-1 text-xs text-gray-500">
            <span>Sort:</span>
            {(['score', 'utc_time', 'confidence'] as const).map((field) => (
              <button
                key={field}
                onClick={() => setSort({ field, direction: sort.field === field && sort.direction === 'desc' ? 'asc' : 'desc' })}
                className={`px-2 py-1 rounded ${sort.field === field ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
              >
                {field === 'utc_time' ? 'newest' : field} {sort.field === field ? (sort.direction === 'desc' ? 'v' : '^') : ''}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1.5 ml-auto text-xs">
            <span className="text-gray-500">{processed.length} of {alerts.length} alerts</span>
            <span className="text-gray-600 hidden lg:inline">Shortcuts: j/k navigate, e escalate, f mark FP</span>
            <Button variant="ghost" size="sm" onClick={resetFilters}>Clear Filters</Button>
          </div>
        </div>

        <div className="flex flex-wrap gap-4">
          <div className="flex items-center gap-1">
            <span className="text-xs text-gray-500 mr-1">Queue:</span>
            {QUEUE_OPTIONS.map((queue) => (
              <button
                key={queue}
                onClick={() => toggleFilter(filters.queues, queue, (v) => setFilters({ queues: v }))}
                aria-pressed={filters.queues.includes(queue)}
                className={`px-2 py-0.5 rounded text-xs ${filters.queues.includes(queue) ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
              >
                {queue.replace('soc_', '')}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1">
            <span className="text-xs text-gray-500 mr-1">Category:</span>
            {CATEGORY_OPTIONS.map((category) => (
              <button
                key={category}
                onClick={() => toggleFilter(filters.categories, category, (v) => setFilters({ categories: v }))}
                aria-pressed={filters.categories.includes(category)}
                className={`px-2 py-0.5 rounded text-xs ${filters.categories.includes(category) ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
              >
                {category.replace(/_/g, ' ')}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1">
            <span className="text-xs text-gray-500 mr-1">Confidence:</span>
            {CONFIDENCE_OPTIONS.map((confidence) => (
              <button
                key={confidence}
                onClick={() => toggleFilter(filters.confidences, confidence, (v) => setFilters({ confidences: v }))}
                aria-pressed={filters.confidences.includes(confidence)}
                className={`px-2 py-0.5 rounded text-xs ${filters.confidences.includes(confidence) ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
              >
                {confidence}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500">Score:</span>
            <input
              type="number"
              min={0}
              max={100}
              value={filters.score_min}
              onChange={(e) => setFilters({ score_min: Number(e.target.value) })}
              aria-label="Minimum score"
              className="w-14 bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-300 focus:outline-none"
            />
            <span className="text-gray-600">-</span>
            <input
              type="number"
              min={0}
              max={100}
              value={filters.score_max}
              onChange={(e) => setFilters({ score_max: Number(e.target.value) })}
              aria-label="Maximum score"
              className="w-14 bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-300 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {processed.length === 0 ? (
        <EmptyState title="No alerts match filters" description="Try adjusting your filter criteria" action={<Button variant="secondary" onClick={resetFilters}>Reset Filters</Button>} />
      ) : (
        <div className="flex-1 overflow-auto border border-gray-800 rounded-lg">
          <table className="w-full table-dense text-left">
            <thead className="bg-gray-900 sticky top-0 z-10">
              {table.getHeaderGroups().map((group) => (
                <tr key={group.id}>
                  {group.headers.map((header) => (
                    <th
                      key={header.id}
                      onClick={header.column.getToggleSortingHandler()}
                      className="px-3 py-2 text-xs font-semibold text-gray-500 uppercase cursor-pointer hover:text-gray-300 border-b border-gray-800 select-none"
                      style={{ width: header.getSize() }}
                    >
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {{ asc: ' ^', desc: ' v' }[header.column.getIsSorted() as string] ?? ''}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className={`border-b border-gray-800/30 hover:bg-gray-800/40 cursor-pointer transition-colors ${row.original.alert_id === selectedAlertId ? 'bg-blue-950/30' : ''}`}
                  onClick={() => { void openAlert(row.original.alert_id); }}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-3 py-1.5">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {processed.length > pagination.pageSize && (
        <div className="flex items-center justify-between mt-2 text-xs text-gray-500">
          <span>Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}</span>
          <div className="flex gap-1">
            <Button variant="ghost" size="sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>Prev</Button>
            <Button variant="ghost" size="sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>Next</Button>
          </div>
        </div>
      )}

      <Drawer
        open={drawerOpen}
        onClose={() => { setDrawerOpen(false); selectAlert(null); }}
        title={selectedAlert ? `Alert ${selectedAlert.alert_id}` : 'Alert Details'}
        width="w-[580px]"
      >
        {bundleLoading ? <LoadingSpinner label="Loading alert details..." /> : selectedAlert ? (
          <div className="space-y-4">
            <div className="flex gap-1 border-b border-gray-800 pb-0">
              {TABS.map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-t transition-colors ${activeTab === tab ? 'bg-gray-800 text-gray-200 border-b-2 border-blue-500' : 'text-gray-500 hover:text-gray-300'}`}
                >
                  {tab === 'process' ? 'Process Context' : tab === 'network' ? 'Network Context' : tab === 'related' ? 'Related Alerts' : tab === 'rule' ? 'Rule Metadata' : tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>

            {activeTab === 'overview' && (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <ScoreBadge score={selectedAlert.score} />
                  <QueueBadge queue={selectedAlert.queue} />
                  <ConfidenceBadge confidence={selectedAlert.confidence} />
                  <Badge>{selectedAlert.category.replace(/_/g, ' ')}</Badge>
                  {(selectedAlert.derived_fields?.length ?? 0) > 0 && (
                    <Badge variant="warning" size="sm">derived fields</Badge>
                  )}
                </div>
                {(selectedAlert.derived_fields?.length ?? 0) > 0 && (
                  <p className="text-xs text-amber-300/90">
                    Inferred values: {selectedAlert.derived_fields?.join(', ')}
                  </p>
                )}
                <dl className="space-y-2 text-sm">
                  <DRow label="Time" value={formatDateTime(selectedAlert.utc_time, dateFormat)} />
                  <DRow label="Image" value={selectedAlert.image} mono={monospaceCommands} />
                  <DRow label="Command Line" value={selectedAlert.command_line} mono={monospaceCommands} />
                  <DRow label="Parent Image" value={selectedAlert.parent_image} mono={monospaceCommands} />
                  <DRow label="Destination" value={`${selectedAlert.destination_ip}:${selectedAlert.destination_port ?? '-'}`} />
                  {showProcessGuids && <DRow label="Process GUID" value={selectedAlert.process_guid} mono={monospaceCommands} />}
                  <DRow label="Reason" value={selectedAlert.reason} />
                </dl>
                <div className="flex flex-wrap gap-1">
                  {selectedAlert.tags.map((tag) => <Badge key={tag} variant="info" size="sm">{tag}</Badge>)}
                </div>
              </div>
            )}

            {activeTab === 'explain' && (
              <div className="space-y-4">
                {(selectedAlert.derived_fields?.length ?? 0) > 0 && (
                  <div className="bg-amber-950/30 border border-amber-800/50 rounded-lg p-3">
                    <h4 className="text-xs font-semibold text-amber-300 uppercase mb-2">Data Quality Note</h4>
                    <p className="text-sm text-amber-100/90 leading-relaxed">
                      This alert includes inferred values for: {selectedAlert.derived_fields?.join(', ')}.
                    </p>
                  </div>
                )}
                <div className="bg-gray-800 rounded-lg p-3">
                  <h4 className="text-xs font-semibold text-gray-400 uppercase mb-2">Routing Explanation</h4>
                  <p className="text-sm text-gray-200 leading-relaxed">{selectedAlert.routing_why}</p>
                </div>
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-gray-400 uppercase">Contributing Signals</h4>
                  <div className="flex flex-wrap gap-1">
                    {selectedAlert.tags.map((tag) => <Badge key={tag} variant="warning" size="sm">{tag}</Badge>)}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'process' && bundle && (
              <div className="space-y-3">
                {bundle.process_context.length === 0 ? (
                  <p className="text-sm text-gray-500">No process context available</p>
                ) : bundle.process_context.map((node) => (
                  <div key={node.guid} className="bg-gray-800 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-sm text-gray-200 ${monospaceCommands ? 'font-mono' : ''}`}>{node.image.split('\\').pop()}</span>
                      <span className="text-xs text-gray-500">PID {node.pid}</span>
                      {node.synthetic && <Badge variant="muted" size="sm">synthetic</Badge>}
                    </div>
                    <p className={`text-xs text-gray-400 truncate ${monospaceCommands ? 'font-mono' : ''}`}>{node.cmdline}</p>
                    <p className="text-xs text-gray-500 mt-1">{node.user} | {formatTime(node.first_seen, dateFormat)} -&gt; {formatTime(node.last_seen, dateFormat)}</p>
                    {node.tags.length > 0 && (
                      <div className="flex gap-1 mt-1">{node.tags.map((tag) => <Badge key={tag} size="sm">{tag}</Badge>)}</div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'network' && bundle && (
              <div className="space-y-3">
                {bundle.network_context.length === 0 ? (
                  <p className="text-sm text-gray-500">No network context available</p>
                ) : bundle.network_context.map((net, idx) => (
                  <div key={idx} className="bg-gray-800 rounded-lg p-3 flex items-center justify-between">
                    <div>
                      <span className={`text-sm text-gray-200 ${monospaceCommands ? 'font-mono' : ''}`}>{net.image.split('\\').pop()}</span>
                      <span className="text-xs text-gray-400 ml-2">-&gt; {net.destination_ip}:{net.destination_port}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-500">{net.protocol}</span>
                      {net.suspicious && <Badge variant="danger" size="sm">suspicious</Badge>}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'related' && bundle && (
              <div className="space-y-2">
                <p className="text-xs text-gray-500">Related timeline events:</p>
                {bundle.related_events.map((event, idx) => (
                  <div key={idx} className="bg-gray-800 rounded p-2 text-xs">
                    <span className="text-gray-500 tabular-nums">{formatTime(event.timestamp, dateFormat)}</span>
                    <span className="text-gray-400 ml-2">EID {event.event_id}</span>
                    <span className={`text-gray-300 ml-2 ${monospaceCommands ? 'font-mono' : ''}`}>{event.image}</span>
                    {event.command_line && (
                      <p className={`text-gray-500 mt-0.5 truncate ${monospaceCommands ? 'font-mono' : ''}`}>{event.command_line}</p>
                    )}
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'rule' && (
              <div className="space-y-2">
                <dl className="space-y-1.5 text-sm">
                  <DRow label="Rule ID" value={selectedAlert.rule_id ?? '-'} />
                  <DRow label="Rule Name" value={selectedAlert.rule_name ?? '-'} />
                  <DRow label="Alert Type" value={selectedAlert.alert_type} />
                </dl>
                {selectedAlert.suppressed_related_rules && selectedAlert.suppressed_related_rules.length > 0 && (
                  <div>
                    <p className="text-xs text-gray-500 mt-3 mb-1">Suppressed Related Rules:</p>
                    <div className="flex flex-wrap gap-1">
                      {selectedAlert.suppressed_related_rules.map((rule) => <Badge key={rule} size="sm">{rule}</Badge>)}
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="space-y-3 pt-3 border-t border-gray-800">
              {(annotations.isFalsePositive(selectedAlert.alert_id) || annotations.isEscalated(selectedAlert.alert_id)) && (
                <div className="flex gap-2">
                  {annotations.isFalsePositive(selectedAlert.alert_id) && <Badge variant="muted">False Positive</Badge>}
                  {annotations.isEscalated(selectedAlert.alert_id) && <Badge variant="danger">Escalated</Badge>}
                </div>
              )}

              {(() => {
                const ann = annotations.getAnnotation(selectedAlert.alert_id);
                if (ann.notes.length === 0) return null;
                return (
                  <div className="space-y-1.5">
                    <p className="text-xs font-semibold text-gray-400 uppercase">Notes</p>
                    {ann.notes.map((note) => (
                      <div key={note.id} className="flex items-start gap-2 bg-gray-800 rounded p-2">
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-gray-300">{note.text}</p>
                          <p className="text-[10px] text-gray-600 mt-0.5">{formatDateTime(note.created_at, dateFormat)}</p>
                        </div>
                        <button
                          onClick={() => annotations.removeNote(selectedAlert.alert_id, note.id)}
                          className="text-gray-600 hover:text-red-400 text-xs flex-shrink-0"
                          aria-label="Delete note"
                        >
                          X
                        </button>
                      </div>
                    ))}
                  </div>
                );
              })()}

              <div className="flex gap-2">
                <input
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  placeholder="Add a note..."
                  className="flex-1 bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && noteText.trim()) {
                      annotations.addNote(selectedAlert.alert_id, noteText.trim());
                      setNoteText('');
                      addToast('success', 'Note added');
                    }
                  }}
                />
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={!noteText.trim()}
                  onClick={() => {
                    if (!noteText.trim()) return;
                    annotations.addNote(selectedAlert.alert_id, noteText.trim());
                    setNoteText('');
                    addToast('success', 'Note added');
                  }}
                >
                  Add Note
                </Button>
              </div>

              <div className="flex flex-wrap gap-2">
                <Button size="sm" onClick={() => setActiveTab('explain')}>Explain Alert</Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={async () => {
                    const pivot = buildPivotQuery(selectedAlert, activeCaseId);
                    const ok = await copyToClipboard(JSON.stringify(pivot, null, 2));
                    addToast(ok ? 'success' : 'error', ok ? 'Pivot query copied to clipboard' : 'Copy failed');
                  }}
                >
                  Copy Pivot Query
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => {
                    if (!bundle) {
                      addToast('error', 'No bundle data available');
                      return;
                    }
                    openBundleInTab(bundle);
                    addToast('info', 'Bundle opened in new tab');
                  }}
                >
                  Open Bundle JSON
                </Button>
                <Button
                  size="sm"
                  variant={annotations.isFalsePositive(selectedAlert.alert_id) ? 'ghost' : 'secondary'}
                  onClick={() => {
                    annotations.toggleFalsePositive(selectedAlert.alert_id);
                    const isFp = annotations.isFalsePositive(selectedAlert.alert_id);
                    addToast('success', isFp ? 'Marked as false positive' : 'Removed false positive mark');
                  }}
                >
                  {annotations.isFalsePositive(selectedAlert.alert_id) ? 'False Positive' : 'Mark False Positive'}
                </Button>
                <Button
                  size="sm"
                  variant={annotations.isEscalated(selectedAlert.alert_id) ? 'ghost' : 'danger'}
                  onClick={() => {
                    annotations.toggleEscalated(selectedAlert.alert_id);
                    const isEsc = annotations.isEscalated(selectedAlert.alert_id);
                    addToast('success', isEsc ? 'Alert escalated' : 'Escalation removed');
                  }}
                >
                  {annotations.isEscalated(selectedAlert.alert_id) ? 'Escalated' : 'Escalate'}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    exportAlert(selectedAlert, activeCaseId ?? undefined);
                    addToast('success', `Alert ${selectedAlert.alert_id} exported`);
                  }}
                >
                  Export Alert
                </Button>
              </div>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-500">No alert selected</p>
        )}
      </Drawer>
    </div>
  );
}

function DRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-2">
      <dt className="text-xs text-gray-500 w-28 flex-shrink-0 pt-0.5">{label}</dt>
      <dd className={`text-gray-300 break-all ${mono ? 'font-mono text-xs' : 'text-sm'}`}>{value || '-'}</dd>
    </div>
  );
}
