import React, { useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useCaseStore, useToastStore, useSettingsStore } from '@/stores';
import { Button, Card, KpiTile, LoadingSpinner, ErrorPanel, ConfidenceBadge, Badge, useConfirmModal } from '@/components';
import { exportReport, exportAlertsCsv, exportCaseBundle, exportAttackNavigatorLayer, exportReportPdf } from '@/utils/exports';
import { deleteCase as deleteCaseApi, fetchReport } from '@/data/api';
import { formatDateRange, formatTime } from '@/utils/datetime';
import { ProcessTreeGraph } from './ProcessTreeGraph';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#6b7280', '#8b5cf6'];

export default function CaseOverviewScreen() {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const { activeCase, loading, error, fetchCase, markCaseReviewed, isCaseReviewed, unmarkCaseReviewed } = useCaseStore();
  const addToast = useToastStore((s) => s.addToast);
  const thresholds = useSettingsStore((s) => s.thresholds);
  const monospaceCommands = useSettingsStore((s) => s.display.monospace_commands);
  const dateFormat = useSettingsStore((s) => s.display.date_format);
  const { modal: confirmModal, confirm } = useConfirmModal();
  const [deleting, setDeleting] = React.useState(false);

  useEffect(() => {
    if (caseId) void fetchCase(caseId);
  }, [caseId, fetchCase]);

  if (loading) return <LoadingSpinner label="Loading case..." />;
  if (error) return <ErrorPanel message={error} onRetry={() => caseId && void fetchCase(caseId)} />;
  if (!activeCase) return <ErrorPanel message="Case not found" />;

  const reviewed = caseId ? isCaseReviewed(caseId) : false;
  const { stats, alerts } = activeCase;
  const highConfAlerts = alerts.filter((a) => a.score >= thresholds.high_confidence_min_score).length;

  const queueData = Object.entries(stats.queues).map(([name, value]) => ({ name: name.replace('soc_', ''), value }));
  const categoryData = Object.entries(stats.categories).map(([name, value]) => ({ name: name.replace(/_/g, ' '), value }));
  const confidenceData = Object.entries(stats.confidence_distribution).map(([name, value]) => ({ name, value }));

  const narrativeBullets = [
    `Analyzed ${stats.total_events} Sysmon events across EID 1/3/11`,
    `Generated ${stats.alerts_generated} alerts, suppressed ${stats.alerts_suppressed}`,
    `${highConfAlerts} alerts at score >= ${thresholds.high_confidence_min_score} requiring immediate review`,
    `${stats.suspicious_destinations} suspicious destination IPs detected`,
    `${stats.network_connections} network connections observed`,
  ];

  const handleDeleteCase = async () => {
    if (!activeCase) return;
    const ok = await confirm(
      'Delete Case',
      `This will permanently delete case ${activeCase.case_id} and all its artifacts from disk. This action cannot be undone.`,
    );
    if (!ok) return;

    setDeleting(true);
    try {
      await deleteCaseApi(activeCase.case_id);
      if (caseId) unmarkCaseReviewed(caseId);
      addToast('success', `Case ${activeCase.case_id} deleted`);
      navigate('/cases');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      addToast('error', `Failed to delete case: ${message}`);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <>
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">{activeCase.case_id}</h1>
          <div className="flex items-center gap-3 mt-1 text-sm text-gray-500">
            <span>{formatDateRange(activeCase.time_range.start, activeCase.time_range.end, dateFormat)}</span>
            <span>Profile: {activeCase.profile}</span>
            <span>Mode: {activeCase.mode}</span>
            <span>Schema: {activeCase.schema_version}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              exportAttackNavigatorLayer(activeCase);
              addToast('success', 'MITRE ATT&CK layer downloaded');
            }}
          >
            Export ATT&CK Layer
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={async () => {
              try {
                const report = await fetchReport(activeCase.case_id);
                await exportReportPdf(activeCase, report || activeCase.report_md);
                addToast('success', 'PDF report downloaded');
              } catch {
                addToast('error', 'Failed to export PDF report');
              }
            }}
          >
            Export PDF
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={async () => {
              try {
                const report = await fetchReport(activeCase.case_id);
                exportReport(report, activeCase.case_id);
                addToast('success', 'Report downloaded');
              } catch {
                addToast('error', 'Failed to export report');
              }
            }}
          >
            Export Report
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              exportAlertsCsv(alerts, undefined, activeCase.case_id);
              addToast('success', `${alerts.length} alerts exported`);
            }}
          >
            Export Alerts CSV
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              exportCaseBundle(activeCase, undefined, activeCase.case_id);
              addToast('success', 'Case bundle downloaded');
            }}
          >
            Export Case Bundle
          </Button>
          <Button size="sm" onClick={() => navigate(`/alerts?case=${activeCase.case_id}`)}>
            Open in Alert Workbench
          </Button>
          <Button size="sm" variant="danger" loading={deleting} onClick={() => { void handleDeleteCase(); }}>
            Delete Case
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <KpiTile label="Total Events" value={stats.total_events} />
        <KpiTile label="Alerts" value={stats.alerts_generated} variant="warning" onClick={() => navigate(`/alerts?case=${activeCase.case_id}`)} />
        <KpiTile
          label="High Confidence"
          value={highConfAlerts}
          variant="danger"
          subtext={`Score >= ${thresholds.high_confidence_min_score}`}
          onClick={() => navigate(`/alerts?case=${activeCase.case_id}&confidence=high`)}
        />
        <KpiTile label="Suspicious Destinations" value={stats.suspicious_destinations} variant="warning" />
        <KpiTile label="Suppressed" value={stats.alerts_suppressed} />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Card title="Queue Summary">
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={queueData}>
                <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 6 }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {queueData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Category Distribution">
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={categoryData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={70} paddingAngle={2}>
                  {categoryData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 6 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Confidence Breakdown">
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={confidenceData} layout="vertical">
                <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} allowDecimals={false} />
                <YAxis dataKey="name" type="category" tick={{ fill: '#9ca3af', fontSize: 11 }} width={60} />
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 6 }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {confidenceData.map((entry, i) => (
                    <Cell key={i} fill={entry.name === 'high' ? '#ef4444' : entry.name === 'medium' ? '#eab308' : '#6b7280'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <Card title="Summary">
        <ul className="space-y-1.5">
          {narrativeBullets.map((bullet, idx) => (
            <li key={idx} className="flex items-start gap-2 text-sm text-gray-300">
              <span className="text-blue-400 mt-0.5">*</span>
              <span>{bullet}</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Report">
        <article
          data-testid="case-report-markdown"
          className="text-sm text-gray-300 whitespace-pre-wrap break-words"
        >
          {activeCase.report_md || 'No report available'}
        </article>
      </Card>

      <Card title="Process Tree">
        <ProcessTreeGraph tree={activeCase.process_tree} monospaceCommands={monospaceCommands} />
      </Card>

      <Card title="Artifacts & IOCs">
        {activeCase.artifacts.length === 0 ? (
          <p className="text-sm text-gray-500">No artifacts found</p>
        ) : (
          <table className="w-full table-dense text-left">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                <th className="px-3 py-2">Path</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2">Creating Image</th>
                <th className="px-3 py-2">Confidence</th>
                <th className="px-3 py-2">Tags</th>
              </tr>
            </thead>
            <tbody>
              {activeCase.artifacts.map((artifact, idx) => (
                <tr key={idx} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className={`px-3 py-2 text-xs text-gray-200 ${monospaceCommands ? 'font-mono' : ''}`}>{artifact.path}</td>
                  <td className="px-3 py-2 text-sm text-gray-400">{formatTime(artifact.created_at, dateFormat)}</td>
                  <td className={`px-3 py-2 text-sm text-gray-400 ${monospaceCommands ? 'font-mono text-xs' : ''}`}>{artifact.creating_image}</td>
                  <td className="px-3 py-2"><ConfidenceBadge confidence={artifact.confidence.toLowerCase()} /></td>
                  <td className="px-3 py-2 text-xs text-gray-500">{artifact.tags.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <div className="flex items-center gap-3">
        <Button
          variant={reviewed ? 'ghost' : 'secondary'}
          size="sm"
          onClick={() => {
            if (caseId) {
              markCaseReviewed(caseId);
              addToast('success', `Case ${caseId} marked as reviewed`);
            }
          }}
          disabled={reviewed}
        >
          {reviewed ? 'Reviewed' : 'Mark Case Reviewed'}
        </Button>
        {reviewed && <Badge variant="success">Reviewed</Badge>}
      </div>
    </div>
    {confirmModal}
    </>
  );
}
