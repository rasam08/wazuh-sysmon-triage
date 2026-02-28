import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useRunsStore, useCaseStore, useToastStore, useSettingsStore } from '@/stores';
import {
  Button, Card, Badge, StatusBadge, KpiTile, EmptyState, LoadingSpinner, useConfirmModal,
  SkeletonKpiRow, SkeletonTable,
} from '@/components';
import { formatDateTime } from '@/utils/datetime';
import { deleteCase as deleteCaseApi } from '@/data/api';

export default function CaseListScreen() {
  const navigate = useNavigate();
  const { runs, loading, fetchRuns } = useRunsStore();
  const { reviewedCases, isCaseReviewed, unmarkCaseReviewed } = useCaseStore();
  const addToast = useToastStore((s) => s.addToast);
  const dateFormat = useSettingsStore((s) => s.display.date_format);
  const { modal: confirmModal, confirm } = useConfirmModal();
  const [search, setSearch] = useState('');
  const [reviewedFilter, setReviewedFilter] = useState<'' | 'reviewed' | 'unreviewed'>('');
  const [deletingCaseId, setDeletingCaseId] = useState<string | null>(null);

  useEffect(() => {
    void fetchRuns();
  }, [fetchRuns]);

  // Derive cases from completed runs
  const cases = useMemo(() => {
    return runs
      .filter((run) => run.status === 'success' && run.params.case_id)
      .map((run) => ({
        case_id: run.params.case_id,
        run_id: run.id,
        mode: run.params.mode,
        profile: run.params.profile,
        time_preset: run.params.time_preset,
        alert_count: run.alert_count ?? 0,
        duration_ms: run.duration_ms,
        completed_at: run.completed_at ?? run.started_at,
        status: run.status,
        reviewed: isCaseReviewed(run.params.case_id),
      }));
  }, [runs, isCaseReviewed, reviewedCases]);

  const filtered = useMemo(() => {
    return cases.filter((c) => {
      if (search) {
        const q = search.toLowerCase();
        if (!c.case_id.toLowerCase().includes(q) && !c.run_id.toLowerCase().includes(q)) return false;
      }
      if (reviewedFilter === 'reviewed' && !c.reviewed) return false;
      if (reviewedFilter === 'unreviewed' && c.reviewed) return false;
      return true;
    });
  }, [cases, search, reviewedFilter]);

  const reviewedCount = cases.filter((c) => c.reviewed).length;

  const handleDeleteCase = async (caseId: string) => {
    const ok = await confirm(
      'Delete Case',
      `This will permanently delete case ${caseId} and all its artifacts from disk. This action cannot be undone.`,
    );
    if (!ok) return;

    setDeletingCaseId(caseId);
    try {
      await deleteCaseApi(caseId);
      unmarkCaseReviewed(caseId);
      await fetchRuns();
      addToast('success', `Case ${caseId} deleted`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      addToast('error', `Failed to delete case: ${message}`);
    } finally {
      setDeletingCaseId(null);
    }
  };

  if (loading && !runs.length) return (
    <div className="space-y-6 animate-fade-in-up">
      <SkeletonKpiRow count={3} />
      <SkeletonTable rows={5} cols={7} />
    </div>
  );

  if (!cases.length) {
    return (
      <EmptyState
        title="No cases yet"
        description="Complete a triage run to generate cases. Each successful run produces a case."
        action={<Button onClick={() => navigate('/new-run')}>Start a Run</Button>}
      />
    );
  }

  return (
    <>
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Cases</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {cases.length} case{cases.length !== 1 ? 's' : ''} from completed runs
          </p>
        </div>
        <Button size="sm" onClick={() => navigate('/new-run')}>New Run</Button>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <KpiTile label="Total Cases" value={cases.length} />
        <KpiTile label="Reviewed" value={reviewedCount} variant="success" subtext={cases.length > 0 ? `${Math.round((reviewedCount / cases.length) * 100)}%` : undefined} />
        <KpiTile
          label="Total Alerts"
          value={cases.reduce((sum, c) => sum + c.alert_count, 0)}
          variant="warning"
        />
      </div>

      <Card>
        <div className="flex items-center gap-3 mb-4">
          <input
            placeholder="Search cases..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 max-w-xs bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
            aria-label="Search cases"
          />
          <div className="flex items-center gap-1">
            {(['', 'reviewed', 'unreviewed'] as const).map((v) => (
              <button
                key={v || 'all'}
                onClick={() => setReviewedFilter(v)}
                aria-pressed={reviewedFilter === v}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                  reviewedFilter === v
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                }`}
              >
                {v === '' ? 'All' : v === 'reviewed' ? 'Reviewed' : 'Unreviewed'}
              </button>
            ))}
          </div>
          <span className="ml-auto text-xs text-gray-500">{filtered.length} results</span>
        </div>

        {filtered.length === 0 ? (
          <p className="text-sm text-gray-500 text-center py-8">No cases match your filters</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left table-dense">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                  <th className="px-3 py-2">Case ID</th>
                  <th className="px-3 py-2">Mode</th>
                  <th className="px-3 py-2">Profile</th>
                  <th className="px-3 py-2">Alerts</th>
                  <th className="px-3 py-2">Duration</th>
                  <th className="px-3 py-2">Completed</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c) => (
                  <tr
                    key={c.run_id}
                    className="border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer transition-colors"
                    onClick={() => navigate(`/cases/${encodeURIComponent(c.case_id)}`)}
                  >
                    <td className="px-3 py-2 text-sm font-mono text-gray-200">{c.case_id}</td>
                    <td className="px-3 py-2">
                      <Badge variant={c.mode === 'live' ? 'success' : 'info'}>{c.mode}</Badge>
                    </td>
                    <td className="px-3 py-2 text-xs text-gray-400">{c.profile}</td>
                    <td className="px-3 py-2 text-sm text-gray-300 tabular-nums">{c.alert_count}</td>
                    <td className="px-3 py-2 text-xs text-gray-400 tabular-nums">
                      {c.duration_ms ? `${(c.duration_ms / 1000).toFixed(1)}s` : '-'}
                    </td>
                    <td className="px-3 py-2 text-xs text-gray-500">{formatDateTime(c.completed_at, dateFormat)}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1.5">
                        <StatusBadge status={c.status} />
                        {c.reviewed && <Badge variant="success" size="sm">Reviewed</Badge>}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2 justify-end">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/alerts?case=${encodeURIComponent(c.case_id)}`);
                          }}
                        >
                          Alerts
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          loading={deletingCaseId === c.case_id}
                          disabled={Boolean(deletingCaseId && deletingCaseId !== c.case_id)}
                          onClick={(e) => {
                            e.stopPropagation();
                            void handleDeleteCase(c.case_id);
                          }}
                        >
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
    {confirmModal}
    </>
  );
}
