import { useSettingsStore } from '@/stores';
import type { Alert, AlertBundle, Case, RunStats, TimelineEvent, Artifact } from '@/types';

type ExportKind =
  | 'alert'
  | 'alerts'
  | 'bundle'
  | 'case'
  | 'report'
  | 'run-log'
  | 'timeline'
  | 'artifacts'
  | 'attack-layer'
  | 'report-pdf';

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadText(content: string, filename: string, mime = 'text/plain') {
  downloadBlob(new Blob([content], { type: mime }), filename);
}

function getExportConfig() {
  return useSettingsStore.getState().exportConfig;
}

function nowParts() {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  const date = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
  const timestamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return { date, timestamp };
}

function resolveFilename(kind: ExportKind, ext: string, caseId?: string, explicitFilename?: string): string {
  if (explicitFilename?.trim()) return explicitFilename;
  const cfg = getExportConfig();
  const { date, timestamp } = nowParts();
  const substitutions: Array<[string, string]> = [
    ['{type}', kind],
    ['{case_id}', caseId ?? 'case'],
    ['{date}', date],
    ['{timestamp}', timestamp],
  ];
  const base = substitutions.reduce((acc, [token, value]) => acc.split(token).join(value), cfg.filename_template);
  if (base.toLowerCase().endsWith(`.${ext.toLowerCase()}`)) return base;
  return `${base}.${ext}`;
}

function stringifyJson(value: unknown): string {
  const cfg = getExportConfig();
  return cfg.pretty_print_json ? JSON.stringify(value, null, 2) : JSON.stringify(value);
}

function csvEscape(value: string | number | null | undefined, delimiter: string): string {
  const s = String(value ?? '');
  if (s.includes(delimiter) || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function toCsvRow(values: Array<string | number | null | undefined>, delimiter: string): string {
  return values.map((v) => csvEscape(v, delimiter)).join(delimiter);
}

const ALERT_CSV_HEADERS = [
  'alert_id', 'utc_time', 'score', 'alert_type', 'category', 'queue',
  'confidence', 'reason', 'routing_why', 'image', 'command_line',
  'parent_image', 'destination_ip', 'destination_port', 'process_guid', 'tags',
] as const;

export function exportAlertsCsv(alerts: Alert[], filename?: string, caseId?: string) {
  const cfg = getExportConfig();
  const delimiter = cfg.csv_delimiter;
  const rows = [ALERT_CSV_HEADERS.join(delimiter)];
  for (const alert of alerts) {
    rows.push(toCsvRow([
      alert.alert_id, alert.utc_time, alert.score, alert.alert_type, alert.category, alert.queue,
      alert.confidence, alert.reason, alert.routing_why, alert.image, alert.command_line,
      alert.parent_image, alert.destination_ip, alert.destination_port ?? '',
      alert.process_guid, (alert.tags ?? []).join(';'),
    ], delimiter));
  }
  const name = resolveFilename('alerts', 'csv', caseId, filename);
  downloadText(rows.join('\n'), name, 'text/csv');
}

function exportAlertJson(alert: Alert, filename?: string, caseId?: string) {
  const name = resolveFilename('alert', 'json', caseId, filename);
  downloadText(stringifyJson(alert), name, 'application/json');
}

function exportAlertNdjson(alert: Alert, filename?: string, caseId?: string) {
  const name = resolveFilename('alert', 'ndjson', caseId, filename);
  downloadText(JSON.stringify(alert), name, 'application/x-ndjson');
}

export function exportAlert(alert: Alert, caseId?: string, filename?: string) {
  const cfg = getExportConfig();
  if (cfg.default_alert_format === 'csv') {
    exportAlertsCsv([alert], filename, caseId);
    return;
  }
  if (cfg.default_alert_format === 'ndjson') {
    exportAlertNdjson(alert, filename, caseId);
    return;
  }
  exportAlertJson(alert, filename, caseId);
}

function exportBundleJson(bundle: AlertBundle, filename?: string, caseId?: string) {
  const cfg = getExportConfig();
  const payload = cfg.include_metadata_in_exports
    ? bundle
    : { alert: bundle.alert };
  const name = resolveFilename('bundle', 'json', caseId, filename ?? `bundle-${bundle.alert.alert_id}.json`);
  downloadText(stringifyJson(payload), name, 'application/json');
}

export function openBundleInTab(bundle: AlertBundle) {
  const blob = new Blob([stringifyJson(bundle)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  window.open(url, '_blank', 'noopener,noreferrer');
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function exportCaseBundle(c: Case, filename?: string, caseId?: string) {
  const cfg = getExportConfig();
  const payload = cfg.include_metadata_in_exports
    ? c
    : {
      case_id: c.case_id,
      run_id: c.run_id,
      profile: c.profile,
      mode: c.mode,
      stats: c.stats,
      alerts: c.alerts,
      artifacts: c.artifacts,
    };
  const name = resolveFilename('case', 'json', caseId ?? c.case_id, filename);
  downloadText(stringifyJson(payload), name, 'application/json');
}

export function exportReport(reportMd: string, caseId: string, filename?: string) {
  const cfg = getExportConfig();
  if (cfg.default_report_format === 'json') {
    const payload = cfg.include_metadata_in_exports
      ? { case_id: caseId, exported_at: new Date().toISOString(), report_markdown: reportMd }
      : { report_markdown: reportMd };
    const name = resolveFilename('report', 'json', caseId, filename);
    downloadText(stringifyJson(payload), name, 'application/json');
    return;
  }
  const name = resolveFilename('report', 'md', caseId, filename);
  downloadText(reportMd, name, 'text/markdown');
}

const ATTACK_TECHNIQUE_RE = /t\d{4}(?:\.\d{3})?/gi;

function extractTechniqueIds(alert: Alert): string[] {
  const techniques = new Set<string>();
  for (const tag of alert.tags ?? []) {
    const matches = tag.match(ATTACK_TECHNIQUE_RE);
    if (!matches) continue;
    for (const match of matches) techniques.add(match.toUpperCase());
  }
  return Array.from(techniques.values());
}

function attackTechniqueColor(score: number): string {
  if (score >= 80) return '#ef4444';
  if (score >= 60) return '#f97316';
  if (score >= 40) return '#eab308';
  return '#6b7280';
}

export function buildAttackNavigatorLayer(c: Case): Record<string, unknown> {
  const byTechnique = new Map<string, { totalScore: number; count: number; alertTypes: Set<string> }>();
  for (const alert of c.alerts) {
    const techniques = extractTechniqueIds(alert);
    for (const technique of techniques) {
      const current = byTechnique.get(technique) ?? { totalScore: 0, count: 0, alertTypes: new Set<string>() };
      current.totalScore += alert.score;
      current.count += 1;
      current.alertTypes.add(alert.alert_type);
      byTechnique.set(technique, current);
    }
  }

  const techniques = Array.from(byTechnique.entries())
    .map(([techniqueID, data]) => {
      const score = Math.round(data.totalScore / Math.max(1, data.count));
      return {
        techniqueID,
        score,
        color: attackTechniqueColor(score),
        comment: `${data.count} alert(s): ${Array.from(data.alertTypes).join(', ')}`,
        enabled: true,
      };
    })
    .sort((a, b) => b.score - a.score || a.techniqueID.localeCompare(b.techniqueID));

  return {
    version: '4.5',
    name: `WST ${c.case_id} ATT&CK Coverage`,
    description: `Auto-generated from ${c.alerts.length} alerts in case ${c.case_id}.`,
    domain: 'enterprise-attack',
    filters: { platforms: ['Windows'] },
    sorting: 0,
    hideDisabled: false,
    techniques,
    gradient: {
      colors: ['#6b7280', '#f59e0b', '#ef4444'],
      minValue: 0,
      maxValue: 100,
    },
    legendItems: [
      { label: 'High confidence detection', color: '#ef4444' },
      { label: 'Medium confidence detection', color: '#f97316' },
      { label: 'Low confidence detection', color: '#6b7280' },
    ],
    metadata: [
      { name: 'case_id', value: c.case_id },
      { name: 'profile', value: c.profile },
      { name: 'mode', value: c.mode },
      { name: 'generated_at', value: new Date().toISOString() },
    ],
    links: [],
    showTacticRowBackground: false,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: true,
    versions: {
      attack: '16',
      navigator: '5.1.0',
      layer: '4.5',
    },
  };
}

export function exportAttackNavigatorLayer(c: Case, filename?: string) {
  const layer = buildAttackNavigatorLayer(c);
  const name = resolveFilename('attack-layer', 'json', c.case_id, filename ?? `attack-layer-${c.case_id}.json`);
  downloadText(stringifyJson(layer), name, 'application/json');
}

export async function exportReportPdf(c: Case, reportMd: string, filename?: string): Promise<void> {
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const margin = 42;
  const lineHeight = 16;
  const maxWidth = doc.internal.pageSize.getWidth() - margin * 2;
  const maxY = doc.internal.pageSize.getHeight() - margin;
  let y = margin;

  const writeText = (text: string, options?: { size?: number; bold?: boolean; spacing?: number }) => {
    if (!text.trim()) {
      y += options?.spacing ?? lineHeight;
      return;
    }
    doc.setFont('helvetica', options?.bold ? 'bold' : 'normal');
    doc.setFontSize(options?.size ?? 11);
    const lines = doc.splitTextToSize(text, maxWidth);
    for (const line of lines) {
      if (y > maxY) {
        doc.addPage();
        y = margin;
      }
      doc.text(line, margin, y);
      y += lineHeight;
    }
    y += options?.spacing ?? 2;
  };

  writeText(`Case Report: ${c.case_id}`, { size: 16, bold: true, spacing: 6 });
  writeText(`Profile: ${c.profile} | Mode: ${c.mode}`, { size: 10 });
  writeText(`Window: ${c.time_range.start} -> ${c.time_range.end}`, { size: 10 });
  writeText(`Alerts: ${c.alerts.length} | Events: ${c.stats.total_events} | Suspicious destinations: ${c.stats.suspicious_destinations}`, { size: 10, spacing: 10 });

  writeText('Analyst Report', { size: 13, bold: true, spacing: 4 });
  const normalized = reportMd
    .replace(/\r\n/g, '\n')
    .replace(/^#{1,6}\s*/gm, '')
    .replace(/\*\*/g, '')
    .replace(/`/g, '');
  for (const block of normalized.split('\n\n')) {
    writeText(block.trim(), { size: 11, spacing: 6 });
  }

  const name = resolveFilename('report-pdf', 'pdf', c.case_id, filename ?? `report-${c.case_id}.pdf`);
  doc.save(name);
}

export function exportRunLogs(run: {
  id: string;
  params: Record<string, unknown>;
  stats?: RunStats | null;
  metadata?: Record<string, unknown> | null;
  error?: string | null;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  case_id?: string;
}, filename?: string) {
  const cfg = getExportConfig();
  const payload = {
    exported_at: new Date().toISOString(),
    run_id: run.id,
    started_at: run.started_at,
    completed_at: run.completed_at,
    duration_ms: run.duration_ms,
    params: run.params,
    stats: run.stats,
    ...(cfg.include_metadata_in_exports ? { metadata: run.metadata } : {}),
    ...(run.error ? { error: run.error } : {}),
  };
  const name = resolveFilename('run-log', 'json', run.case_id, filename);
  downloadText(stringifyJson(payload), name, 'application/json');
}

function exportTimelineCsv(events: TimelineEvent[], filename?: string, caseId?: string) {
  const cfg = getExportConfig();
  const delimiter = cfg.csv_delimiter;
  const headers = ['timestamp', 'event_id', 'image', 'command_line', 'parent_image', 'target_filename', 'user', 'rule_id', 'agent_name', 'agent_id'];
  const rows = [headers.join(delimiter)];
  for (const event of events) {
    rows.push(toCsvRow([
      event.timestamp,
      event.event_id,
      event.image,
      event.command_line ?? '',
      event.parent_image ?? '',
      event.target_filename ?? '',
      event.user ?? '',
      event.rule_id ?? '',
      event.agent_name ?? '',
      event.agent_id ?? '',
    ], delimiter));
  }
  const name = resolveFilename('timeline', 'csv', caseId, filename);
  downloadText(rows.join('\n'), name, 'text/csv');
}

function exportArtifactsCsv(artifacts: Artifact[], filename?: string, caseId?: string) {
  const cfg = getExportConfig();
  const delimiter = cfg.csv_delimiter;
  const headers = ['path', 'created_at', 'creating_image', 'confidence', 'tags'];
  const rows = [headers.join(delimiter)];
  for (const artifact of artifacts) {
    rows.push(toCsvRow([
      artifact.path,
      artifact.created_at,
      artifact.creating_image,
      artifact.confidence,
      artifact.tags.join(';'),
    ], delimiter));
  }
  const name = resolveFilename('artifacts', 'csv', caseId, filename);
  downloadText(rows.join('\n'), name, 'text/csv');
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  }
}
