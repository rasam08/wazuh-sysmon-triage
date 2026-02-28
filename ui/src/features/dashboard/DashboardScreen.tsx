import React, { useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  KpiTile,
  Badge,
  Button,
  QueueBadge,
  ScoreBadge,
  ConfidenceBadge,
  EmptyState,
  LoadingSpinner,
  ErrorPanel,
} from '@/components';
import { SkeletonDashboard } from '@/components/Skeleton';
import { useRunsStore, useAlertsStore, useSettingsStore } from '@/stores';
import { fetchHealth } from '@/data/api';
import type { Alert, HealthStatus } from '@/types';
import { formatDateTime, formatTime } from '@/utils/datetime';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  AreaChart, Area, CartesianGrid,
  PieChart, Pie, Cell, Legend,
} from 'recharts';

const CHART_COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#6b7280', '#8b5cf6'];
const TOOLTIP_STYLE = { backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 6 };

function formatMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function buildAlertTrend(alerts: Alert[]) {
  if (alerts.length === 0) return { buckets: [], bucketLabel: '1h' };

  const times = alerts
    .map((a) => new Date(a.utc_time).getTime())
    .filter((t) => Number.isFinite(t));

  if (times.length === 0) return { buckets: [], bucketLabel: '1h' };

  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const rangeMs = maxTime - minTime;

  // Pick bucket granularity and count based on actual spread
  let bucketMs: number;
  let bucketLabel: string;
  if (rangeMs <= 30 * 60_000) {
    bucketMs = 2.5 * 60_000; bucketLabel = '2.5m';
  } else if (rangeMs <= 3 * 3_600_000) {
    bucketMs = 15 * 60_000; bucketLabel = '15m';
  } else if (rangeMs <= 12 * 3_600_000) {
    bucketMs = 3_600_000; bucketLabel = '1h';
  } else {
    bucketMs = 2 * 3_600_000; bucketLabel = '2h';
  }

  const BUCKET_COUNT = 12;
  const endAligned = Math.ceil(maxTime / bucketMs) * bucketMs;
  const startAligned = endAligned - (BUCKET_COUNT - 1) * bucketMs;

  const buckets = Array.from({ length: BUCKET_COUNT }, (_, idx) => {
    const t = startAligned + idx * bucketMs;
    return {
      key: String(t),
      label: new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      alerts: 0,
    };
  });

  for (const alert of alerts) {
    const ts = new Date(alert.utc_time).getTime();
    if (!Number.isFinite(ts)) continue;
    const idx = Math.floor((ts - startAligned) / bucketMs);
    if (idx >= 0 && idx < BUCKET_COUNT) buckets[idx].alerts += 1;
  }

  return { buckets, bucketLabel };
}

export default function DashboardScreen() {
  const navigate = useNavigate();
  const { runs, loading: runsLoading, error: runsError, fetchRuns } = useRunsStore();
  const { alerts, activeCaseId, loading: alertsLoading, fetchAlerts } = useAlertsStore();
  const thresholds = useSettingsStore((s) => s.thresholds);
  const monospaceCommands = useSettingsStore((s) => s.display.monospace_commands);
  const dateFormat = useSettingsStore((s) => s.display.date_format);
  const [health, setHealth] = React.useState<HealthStatus | null>(null);
  const [healthLoading, setHealthLoading] = React.useState(false);

  // Run selector — default to first completed run
  const completedRuns = useMemo(() => runs.filter((r) => Boolean(r.stats) && Boolean(r.metadata)), [runs]);
  const [selectedRunId, setSelectedRunId] = React.useState<string | null>(null);
  const [compareRunId, setCompareRunId] = React.useState<string | null>(null);

  useEffect(() => {
    if (!selectedRunId && completedRuns.length > 0) {
      setSelectedRunId(completedRuns[0].id);
    }
  }, [completedRuns, selectedRunId]);

  const dashboardRun = useMemo(
    () => completedRuns.find((r) => r.id === selectedRunId) ?? completedRuns[0] ?? null,
    [completedRuns, selectedRunId],
  );
  const compareRun = useMemo(
    () => completedRuns.find((r) => r.id === compareRunId) ?? null,
    [completedRuns, compareRunId],
  );
  const dashboardCaseId = dashboardRun?.params.case_id ?? null;

  useEffect(() => {
    void fetchRuns();
  }, [fetchRuns]);

  useEffect(() => {
    if (dashboardCaseId) {
      void fetchAlerts(dashboardCaseId);
    }
  }, [dashboardCaseId, fetchAlerts]);

  useEffect(() => {
    const profile = (dashboardRun?.params.profile ?? 'soc') as 'soc' | 'dev' | 'lab';
    let active = true;

    const check = () => {
      setHealthLoading(true);
      void fetchHealth(profile)
        .then((payload) => {
          if (active) setHealth(payload);
        })
        .catch(() => {
          if (active) {
            setHealth({
              checked_at: new Date().toISOString(),
              profile,
              opensearch_host: null,
              opensearch_connectivity: 'unknown',
              opensearch_http_status: null,
              tls_mode: 'unknown',
              last_successful_fetch_at: null,
              error: 'Unable to fetch health status',
            });
          }
        })
        .finally(() => {
          if (active) setHealthLoading(false);
        });
    };

    check();
    const interval = setInterval(check, 30_000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [dashboardRun?.params.profile]);

  const dashboardAlerts = useMemo(() => {
    if (!dashboardCaseId || activeCaseId !== dashboardCaseId) return [];
    return alerts;
  }, [dashboardCaseId, activeCaseId, alerts]);

  if (runsLoading && !runs.length) {
    return <SkeletonDashboard />;
  }

  if (runsError && !runs.length) {
    return <ErrorPanel message={runsError} onRetry={() => { void fetchRuns(); }} />;
  }

  if (!dashboardRun?.stats || !dashboardRun.metadata) {
    return (
      <EmptyState
        title="No completed runs yet"
        description="Start a triage run to populate dashboard analytics."
        action={<Button onClick={() => navigate('/new-run')}>New Run</Button>}
      />
    );
  }

  const stats = dashboardRun.stats;
  const meta = dashboardRun.metadata;
  const topAlerts = [...dashboardAlerts].sort((a, b) => b.score - a.score).slice(0, 8);
  const highConfidenceCount = dashboardAlerts.filter((a) => a.score >= thresholds.high_confidence_min_score).length;
  const trendData = buildAlertTrend(dashboardAlerts);
  const { buckets: trendBuckets, bucketLabel } = trendData;

  const queueData = Object.entries(stats.queues).map(([name, value]) => ({
    name: name.replace('soc_', ''),
    value,
  }));

  const categoryData = Object.entries(stats.categories).map(([name, value]) => ({
    name: name.replace(/_/g, ' '),
    value,
  }));

  const stageData = meta.stages.map((stage) => ({
    name: stage.name,
    ms: stage.duration_ms,
  }));

  const isLive = dashboardRun.params.mode === 'live';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Last run {meta.completed_at ? formatDateTime(meta.completed_at, dateFormat) : 'N/A'}
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {/* Run selector */}
          {completedRuns.length > 1 && (
            <select
              value={selectedRunId ?? ''}
              onChange={(e) => { setSelectedRunId(e.target.value); setCompareRunId(null); }}
              aria-label="Select run to display"
              className="bg-gray-800 border border-gray-700 text-sm text-gray-200 rounded-md px-2.5 py-1.5 focus:border-blue-500 focus:outline-none"
            >
              {completedRuns.map((r) => (
                <option key={r.id} value={r.id}>{r.params.case_id}</option>
              ))}
            </select>
          )}
          {/* Compare selector */}
          {completedRuns.length > 1 && (
            <select
              value={compareRunId ?? ''}
              onChange={(e) => setCompareRunId(e.target.value || null)}
              aria-label="Compare with run"
              className="bg-gray-800 border border-gray-700 text-sm text-gray-400 rounded-md px-2.5 py-1.5 focus:border-blue-500 focus:outline-none"
            >
              <option value="">Compare with…</option>
              {completedRuns
                .filter((r) => r.id !== (selectedRunId ?? completedRuns[0]?.id))
                .map((r) => (
                  <option key={r.id} value={r.id}>{r.params.case_id}</option>
                ))}
            </select>
          )}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-gray-900 border border-gray-800">
            <span className={`h-2 w-2 rounded-full ${isLive ? 'bg-emerald-400 animate-pulse' : 'bg-yellow-400'}`} />
            <span className="text-xs font-medium text-gray-300">{isLive ? 'Live' : 'Offline'}</span>
          </div>
          <Button size="sm" onClick={() => navigate('/new-run')}>New Run</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiTile
          label="Events Fetched"
          value={stats.total_events.toLocaleString()}
          subtext={`EIDs: ${Object.keys(stats.by_event_id).join(', ') || 'N/A'}`}
        />
        <KpiTile
          label="Alerts Emitted"
          value={stats.alerts_generated}
          variant="warning"
          subtext={`${Object.keys(stats.queues).length} queues`}
          onClick={() => navigate(`/alerts?case=${encodeURIComponent(dashboardRun.params.case_id)}`)}
        />
        <KpiTile
          label="High Confidence"
          value={highConfidenceCount}
          variant="danger"
          subtext={`Score >= ${thresholds.high_confidence_min_score}`}
          onClick={() => navigate(`/alerts?case=${encodeURIComponent(dashboardRun.params.case_id)}&confidence=high`)}
        />
        <KpiTile
          label="Suppressed"
          value={stats.alerts_suppressed}
          subtext={`${Object.keys(stats.suppression_hits).length} rules hit`}
        />
        <KpiTile
          label="Suspicious Dest."
          value={stats.suspicious_destinations}
          variant="warning"
          subtext={`of ${stats.network_connections} connections`}
        />
        <KpiTile
          label="Pipeline Time"
          value={formatMs(meta.duration_ms)}
          subtext={`${meta.stages.length} stages`}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title={`Alert Volume (per ${bucketLabel})`} className="lg:col-span-2">
          <div className="h-56">
            {alertsLoading && dashboardAlerts.length === 0 ? (
              <LoadingSpinner label="Loading alerts..." />
            ) : trendBuckets.length === 0 ? (
              <p className="text-sm text-gray-500">No alert timeline available</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendBuckets}>
                  <defs>
                    <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="label" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Area type="monotone" dataKey="alerts" stroke="#ef4444" fill="url(#alertGrad)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card title="Queue Distribution">
          <div className="h-56">
            {queueData.length === 0 ? (
              <p className="text-sm text-gray-500">No queue data available</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={queueData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={38}
                    outerRadius={68}
                    paddingAngle={3}
                  >
                    {queueData.map((_, i) => (
                      <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Category Breakdown">
          <div className="h-48">
            {categoryData.length === 0 ? (
              <p className="text-sm text-gray-500">No category data available</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryData} layout="vertical">
                  <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} allowDecimals={false} />
                  <YAxis
                    dataKey="name"
                    type="category"
                    tick={{ fill: '#9ca3af', fontSize: 11 }}
                    width={110}
                  />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {categoryData.map((_, i) => (
                      <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card title="Pipeline Stage Performance">
          <div className="h-48">
            {stageData.length === 0 ? (
              <p className="text-sm text-gray-500">No stage data available</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stageData}>
                  <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                  <YAxis
                    tick={{ fill: '#9ca3af', fontSize: 11 }}
                    allowDecimals={false}
                    label={{
                      value: 'ms',
                      position: 'insideTopLeft',
                      fill: '#6b7280',
                      fontSize: 10,
                      offset: -5,
                    }}
                  />
                  <Tooltip
                    contentStyle={TOOLTIP_STYLE}
                    formatter={(v) => [`${Number(v).toLocaleString()} ms`, 'Duration']}
                  />
                  <Bar dataKey="ms" radius={[4, 4, 0, 0]} fill="#3b82f6" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      <Card
        title="Recent Alerts"
        actions={
          <Button size="sm" variant="ghost" onClick={() => navigate(`/alerts?case=${encodeURIComponent(dashboardRun.params.case_id)}`)}>
            View All -&gt;
          </Button>
        }
      >
        {topAlerts.length === 0 ? (
          <p className="text-sm text-gray-500">No alerts were generated for this run.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                  <th className="px-3 py-2 w-10">#</th>
                  <th className="px-3 py-2">Score</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Queue</th>
                  <th className="px-3 py-2">Confidence</th>
                  <th className="px-3 py-2">Image</th>
                  <th className="px-3 py-2">Reason</th>
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2 w-8"></th>
                </tr>
              </thead>
              <tbody>
                {topAlerts.map((alert, rowIdx) => (
                  <tr
                    key={alert.alert_id}
                    className="border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer transition-colors"
                    onClick={() => navigate(`/alerts?case=${encodeURIComponent(dashboardRun.params.case_id)}&search=${encodeURIComponent(alert.alert_id)}`)}
                  >
                    <td className="px-3 py-2 text-xs text-gray-600 tabular-nums">{rowIdx + 1}</td>
                    <td className="px-3 py-2"><ScoreBadge score={alert.score} /></td>
                    <td className="px-3 py-2 text-xs text-gray-400">{alert.rule_name ?? alert.alert_type}</td>
                    <td className="px-3 py-2"><QueueBadge queue={alert.queue} /></td>
                    <td className="px-3 py-2"><ConfidenceBadge confidence={alert.confidence} /></td>
                    <td className={`px-3 py-2 text-xs text-gray-400 max-w-[180px] truncate ${monospaceCommands ? 'font-mono' : ''}`}>
                      {alert.image.split('\\').pop()}
                    </td>
                    <td className="px-3 py-2 text-xs text-gray-400 max-w-[260px] truncate">{alert.reason}</td>
                    <td className="px-3 py-2 text-xs text-gray-500 whitespace-nowrap">
                      {formatTime(alert.utc_time, dateFormat)}
                    </td>
                    <td className="px-3 py-2">
                      <span className="text-gray-600 hover:text-blue-400 text-base leading-none" aria-hidden="true">→</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Last Run">
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-500">Case ID</span>
              <span className="text-gray-200 font-mono text-xs">{dashboardRun.params.case_id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Mode</span>
              <Badge variant={dashboardRun.params.mode === 'live' ? 'success' : 'info'}>{dashboardRun.params.mode}</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Profile</span>
              <span className="text-gray-200">{dashboardRun.params.profile}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Time Window</span>
              <span className="text-gray-200">{dashboardRun.params.time_preset}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Duration</span>
              <span className="text-gray-200">{formatMs(meta.duration_ms)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Queues</span>
              <div className="flex gap-1 flex-wrap justify-end">
                {dashboardRun.params.queues.map((queue) => (
                  <QueueBadge key={queue} queue={queue} />
                ))}
              </div>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Min Score</span>
              <span className="text-gray-200">{dashboardRun.params.min_alert_score}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Schema</span>
              <span className="text-gray-400 text-xs">{meta.schema_version}</span>
            </div>
          </div>
        </Card>

        <Card title="Suppression Summary">
          {Object.keys(stats.suppression_hits).length === 0 ? (
            <p className="text-sm text-gray-500">No suppression rules triggered</p>
          ) : (
            <div className="space-y-2">
              {Object.entries(stats.suppression_hits).map(([rule, count]) => (
                <div key={rule} className="flex items-center justify-between">
                  <span className="text-sm text-gray-300 font-mono">{rule}</span>
                  <Badge variant="muted">{count} hit{count !== 1 ? 's' : ''}</Badge>
                </div>
              ))}
              <div className="border-t border-gray-800 pt-2 mt-2 flex justify-between">
                <span className="text-xs text-gray-500">Total suppressed</span>
                <span className="text-sm font-semibold text-gray-300">{stats.alerts_suppressed}</span>
              </div>
            </div>
          )}
        </Card>

        <Card title="Health">
          {healthLoading && !health ? (
            <p className="text-sm text-gray-500">Checking OpenSearch...</p>
          ) : !health ? (
            <p className="text-sm text-gray-500">Health data unavailable</p>
          ) : (
            <div className="space-y-2 text-sm">
              <div className="flex justify-between items-center">
                <span className="text-gray-500">OpenSearch</span>
                <Badge
                  variant={
                    health.opensearch_connectivity === 'reachable'
                      ? 'success'
                      : (health.opensearch_connectivity === 'unreachable' ? 'danger' : 'muted')
                  }
                >
                  {health.opensearch_connectivity}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">TLS Mode</span>
                <span className="text-gray-200">{health.tls_mode}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Last Successful Fetch</span>
                <span className="text-gray-200 text-xs">
                  {health.last_successful_fetch_at ? formatDateTime(health.last_successful_fetch_at, dateFormat) : 'N/A'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Host</span>
                <span className="text-gray-400 text-xs max-w-[170px] truncate" title={health.opensearch_host ?? ''}>
                  {health.opensearch_host ?? 'Not configured'}
                </span>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* Run comparison delta card */}
      {compareRun?.stats && (
        <Card
          title={`Δ vs ${compareRun.params.case_id}`}
          actions={
            <button
              onClick={() => setCompareRunId(null)}
              className="text-xs text-gray-600 hover:text-gray-400 transition-colors"
              aria-label="Clear comparison"
            >
              × clear
            </button>
          }
        >
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <DeltaMetric
              label="Alerts"
              current={stats.alerts_generated}
              prev={compareRun.stats.alerts_generated}
            />
            <DeltaMetric
              label="High Conf."
              current={highConfidenceCount}
              prev={compareRun.stats.confidence_distribution?.['high'] ?? 0}
            />
            <DeltaMetric
              label="Suppressed"
              current={stats.alerts_suppressed}
              prev={compareRun.stats.alerts_suppressed}
            />
            <DeltaMetric
              label="Susp. Dest."
              current={stats.suspicious_destinations}
              prev={compareRun.stats.suspicious_destinations}
            />
          </div>
        </Card>
      )}
    </div>
  );
}

function DeltaMetric({ label, current, prev }: { label: string; current: number; prev: number }) {
  const delta = current - prev;
  const pct = prev === 0 ? null : Math.round((delta / prev) * 100);
  const up = delta > 0;
  const neutral = delta === 0;
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-gray-500 uppercase tracking-wide">{label}</span>
      <div className="flex items-baseline gap-2">
        <span className="text-lg font-bold text-gray-100">{current}</span>
        {!neutral && (
          <span
            className={`text-xs font-medium ${
              up ? 'text-red-400' : 'text-emerald-400'
            }`}
            aria-label={`${delta > 0 ? 'increased' : 'decreased'} by ${Math.abs(delta)}`}
          >
            {up ? '+' : ''}{delta}{pct !== null ? ` (${pct > 0 ? '+' : ''}{pct}%)` : ''}
          </span>
        )}
        {neutral && <span className="text-xs text-gray-600">=</span>}
      </div>
      <span className="text-[10px] text-gray-600">prev: {prev}</span>
    </div>
  );
}
