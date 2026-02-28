import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useRunsStore, useToastStore, useSettingsStore } from '@/stores';
import { Button, Card, StatusBadge, EmptyState, LoadingSpinner, ErrorPanel } from '@/components';
import { exportRunLogs, copyToClipboard } from '@/utils/exports';
import { formatDateTime } from '@/utils/datetime';

export default function RunsDashboardScreen() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { runs, loading, fetchRuns, selectRun, selectedRunId } = useRunsStore();
  const addToast = useToastStore((s) => s.addToast);
  const monospaceCommands = useSettingsStore((s) => s.display.monospace_commands);
  const dateFormat = useSettingsStore((s) => s.display.date_format);

  const [filterStatus, setFilterStatus] = useState('');
  const [filterMode, setFilterMode] = useState('');
  const [searchText, setSearchText] = useState('');

  useEffect(() => {
    void fetchRuns();
    const sel = searchParams.get('selected');
    if (sel) selectRun(sel);
  }, [fetchRuns, searchParams, selectRun]);

  const filteredRuns = useMemo(() => {
    return runs.filter((run) => {
      if (filterStatus && run.status !== filterStatus) return false;
      if (filterMode && run.params.mode !== filterMode) return false;
      if (searchText) {
        const q = searchText.toLowerCase();
        if (!run.params.case_id.toLowerCase().includes(q) && !run.id.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [runs, filterStatus, filterMode, searchText]);

  const selectedRun = useMemo(() => runs.find((run) => run.id === selectedRunId), [runs, selectedRunId]);

  if (loading && !runs.length) return <LoadingSpinner label="Loading runs..." />;

  if (!runs.length) {
    return (
      <EmptyState
        title="No runs yet"
        description="Start your first triage run to begin analyzing Sysmon events."
        action={<Button onClick={() => navigate('/new-run')}>Start First Run</Button>}
      />
    );
  }

  return (
    <div className="flex gap-4 h-[calc(100vh-8rem)]">
      <div className="w-80 flex-shrink-0 flex flex-col bg-gray-900 border border-gray-800 rounded-lg">
        <div className="p-3 border-b border-gray-800 space-y-2">
          <input
            placeholder="Search runs..."
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            aria-label="Search runs"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
          />
          <div className="flex gap-1.5">
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              aria-label="Filter by status"
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none"
            >
              <option value="">All Status</option>
              <option value="success">Success</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
              <option value="pending">Pending</option>
            </select>
            <select
              value={filterMode}
              onChange={(e) => setFilterMode(e.target.value)}
              aria-label="Filter by mode"
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none"
            >
              <option value="">All Modes</option>
              <option value="live">Live</option>
              <option value="offline">Offline</option>
            </select>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {filteredRuns.map((run) => (
            <button
              key={run.id}
              onClick={() => selectRun(run.id)}
              className={`w-full text-left px-3 py-2.5 border-b border-gray-800/50 hover:bg-gray-800/50 transition-colors
                ${selectedRunId === run.id ? 'bg-gray-800 border-l-2 border-l-blue-500' : ''}`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-gray-400 truncate">{run.id.slice(0, 8)}</span>
                <StatusBadge status={run.status} />
              </div>
              <div className="text-sm text-gray-200 truncate">{run.params.case_id}</div>
              <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
                <span>{run.params.mode}</span>
                <span>{run.alert_count ?? 0} alerts</span>
                <span>{run.duration_ms ? `${(run.duration_ms / 1000).toFixed(1)}s` : '-'}</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {selectedRun ? (
        <div className="flex-1 flex gap-4 min-w-0">
          <div className="flex-1 space-y-4 overflow-y-auto">
            <Card title="Run Status">
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <StatusBadge status={selectedRun.status} />
                  {selectedRun.current_stage && (
                    <span className="text-xs text-blue-400 animate-pulse">
                      Stage: {selectedRun.current_stage}
                    </span>
                  )}
                </div>
                {selectedRun.metadata?.stages && (
                  <div className="space-y-1.5">
                    {selectedRun.metadata.stages.map((stage) => (
                      <div key={stage.name} className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${stage.status === 'success' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                        <span className="text-xs text-gray-400 w-20">{stage.name}</span>
                        <div className="flex-1 bg-gray-800 rounded h-1.5">
                          <div className={`h-1.5 rounded ${stage.status === 'success' ? 'bg-emerald-600' : 'bg-red-600'}`} style={{ width: '100%' }} />
                        </div>
                        <span className="text-xs text-gray-500 tabular-nums w-16 text-right">{stage.duration_ms}ms</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>

            {selectedRun.error && (
              <ErrorPanel
                message={selectedRun.error}
                onRetry={() => addToast('info', 'Retry by starting a new run with the same settings')}
                onCopy={async () => {
                  const ok = await copyToClipboard(selectedRun.error ?? '');
                  addToast(ok ? 'success' : 'error', ok ? 'Error copied to clipboard' : 'Copy failed');
                }}
              />
            )}

            {selectedRun.stats && (
              <Card title="Diagnostics">
                <div className="grid grid-cols-3 gap-3">
                  <Stat label="Dropped Events" value={selectedRun.stats.dropped_events} />
                  <Stat label="Suppressed" value={selectedRun.stats.alerts_suppressed} />
                  <Stat label="Network Conn." value={selectedRun.stats.network_connections} />
                </div>
                {Object.keys(selectedRun.stats.dropped_by_reason).length > 0 && (
                  <div className="mt-3">
                    <p className="text-xs text-gray-500 mb-1">Drop reasons:</p>
                    {Object.entries(selectedRun.stats.dropped_by_reason).map(([key, value]) => (
                      <div key={key} className="flex justify-between text-xs text-gray-400">
                        <span>{key}</span>
                        <span>{value}</span>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            )}

            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => navigate(`/cases/${selectedRun.params.case_id}`)}>
                Open Case
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={async () => {
                  const outputPath = selectedRun.params.out_dir ?? './out';
                  const normalized = outputPath.replace(/\\/g, '/');
                  const fileUrl = /^[a-zA-Z]:\//.test(normalized) ? `file:///${normalized}` : `file://${normalized}`;
                  const opened = window.open(encodeURI(fileUrl), '_blank', 'noopener,noreferrer');
                  const copied = await copyToClipboard(outputPath);
                  if (opened) {
                    addToast('info', copied ? 'Opened folder hint and copied output path' : 'Opened folder hint');
                  } else {
                    addToast(copied ? 'success' : 'info', copied ? 'Output path copied to clipboard' : `Output directory: ${outputPath}`);
                  }
                }}
              >
                Open Output Folder
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  exportRunLogs({
                    id: selectedRun.id,
                    params: selectedRun.params as unknown as Record<string, unknown>,
                    stats: selectedRun.stats,
                    metadata: selectedRun.metadata as unknown as Record<string, unknown>,
                    error: selectedRun.error,
                    started_at: selectedRun.started_at,
                    completed_at: selectedRun.completed_at,
                    duration_ms: selectedRun.duration_ms,
                    case_id: selectedRun.params.case_id,
                  });
                  addToast('success', 'Run logs downloaded');
                }}
              >
                Download Logs
              </Button>
              <Button size="sm" variant="secondary" onClick={() => navigate('/new-run')}>
                Re-run with Same Settings
              </Button>
            </div>
          </div>

          <div className="w-72 flex-shrink-0 space-y-4 overflow-y-auto">
            <Card title="Run Metadata">
              <dl className="space-y-2 text-xs">
                <MetaRow label="Run ID" value={`${selectedRun.id.slice(0, 12)}...`} mono />
                <MetaRow label="Case ID" value={selectedRun.params.case_id} mono={monospaceCommands} />
                <MetaRow label="Mode" value={selectedRun.params.mode} />
                <MetaRow label="Profile" value={selectedRun.params.profile} />
                <MetaRow label="Time" value={selectedRun.params.time_preset} />
                <MetaRow label="Started" value={formatDateTime(selectedRun.started_at, dateFormat)} mono />
                <MetaRow label="Duration" value={selectedRun.duration_ms ? `${(selectedRun.duration_ms / 1000).toFixed(1)}s` : '-'} />
                <MetaRow label="Min Score" value={String(selectedRun.params.min_alert_score)} />
                <MetaRow label="Queues" value={selectedRun.params.queues.join(', ')} mono={monospaceCommands} />
              </dl>
            </Card>
            {selectedRun.stats && (
              <Card title="Stats Summary">
                <dl className="space-y-2 text-xs">
                  <MetaRow label="Total Events" value={String(selectedRun.stats.total_events)} />
                  <MetaRow label="Alerts" value={String(selectedRun.stats.alerts_generated)} />
                  <MetaRow label="Suppressed" value={String(selectedRun.stats.alerts_suppressed)} />
                  <MetaRow label="Suspicious IPs" value={String(selectedRun.stats.suspicious_destinations)} />
                </dl>
              </Card>
            )}
          </div>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
          Select a run to view details
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-gray-800 rounded px-3 py-2">
      <p className="text-xs text-gray-500">{label}</p>
      <p className="text-lg font-bold text-gray-200 tabular-nums">{value}</p>
    </div>
  );
}

function MetaRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between">
      <dt className="text-gray-500">{label}</dt>
      <dd className={`text-gray-300 text-right max-w-[160px] truncate ${mono ? 'font-mono' : ''}`} title={value}>{value}</dd>
    </div>
  );
}
