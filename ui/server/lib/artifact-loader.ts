import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import type { AlertQueue, Profile, RunMode, RunParams } from './validators';
import { validateCaseId } from './validators';

export class ArtifactError extends Error {
  readonly status: number;

  constructor(message: string, status = 500) {
    super(message);
    this.name = 'ArtifactError';
    this.status = status;
  }
}

export interface ApiRunStage {
  name: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  status: 'success' | 'error';
}

export interface ApiRunMetadata {
  run_id: string;
  case_id: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  params: RunParams;
  schema_version: string;
  stages: ApiRunStage[];
}

export interface ApiRunStats {
  total_events: number;
  by_event_id: Record<string, number>;
  alerts_generated: number;
  alerts_suppressed: number;
  suppression_hits: Record<string, number>;
  dropped_events: number;
  dropped_by_reason: Record<string, number>;
  queues: Record<string, number>;
  categories: Record<string, number>;
  confidence_distribution: Record<string, number>;
  network_connections: number;
  suspicious_destinations: number;
}

export interface ApiRun {
  id: string;
  params: RunParams;
  status: 'pending' | 'running' | 'success' | 'failed';
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  alert_count?: number;
  error?: string;
  metadata?: ApiRunMetadata;
  stats?: ApiRunStats;
}

export interface ApiTimelineEvent {
  timestamp: string;
  event_id: number;
  image: string;
  command_line: string;
  parent_image: string;
  target_filename: string;
  user: string;
  rule_id: string;
  agent_name: string;
  agent_id: string;
}

export interface ApiProcessNode {
  guid: string;
  pid: number;
  image: string;
  cmdline: string;
  user: string;
  first_seen: string;
  last_seen: string;
  synthetic: boolean;
  tags: string[];
}

export interface ApiArtifact {
  path: string;
  created_at: string;
  creating_process_guid: string;
  creating_image: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  tags: string[];
}

export interface ApiProcessTree {
  schema_version: string;
  agent: { name: string; id: string };
  time_range: { start: string; end: string };
  nodes: ApiProcessNode[];
  edges: Array<{ parent_guid: string; child_guid: string; reason: string }>;
  artifacts: ApiArtifact[];
}

export interface ApiResolvedQuery {
  index: string;
  start: string;
  end: string;
  agent_id?: string;
  agent_name?: string;
  event_ids: number[];
  size: number;
}

export interface ApiAlert {
  alert_id: string;
  utc_time: string;
  score: number;
  alert_type: string;
  category: 'malware_execution' | 'c2_outbound' | 'persistence' | 'policy_violation' | 'developer_tooling' | 'unknown';
  queue: AlertQueue;
  confidence: 'low' | 'medium' | 'high';
  reason: string;
  routing_why: string;
  image: string;
  command_line: string;
  parent_image: string;
  destination_ip: string;
  destination_port: number | null;
  process_guid: string;
  tags: string[];
  rule_id?: string;
  rule_name?: string;
  suppressed_related_rules?: string[];
  suppressed_related_count?: number;
  derived_fields?: string[];
}

export interface ApiAlertBundle {
  alert: ApiAlert;
  related_events: ApiTimelineEvent[];
  process_context: ApiProcessNode[];
  network_context: Array<{
    process_guid: string;
    image: string;
    destination_ip: string;
    destination_port: number;
    protocol: string;
    suspicious: boolean;
  }>;
}

export interface ApiCase {
  case_id: string;
  run_id: string;
  time_range: { start: string; end: string };
  profile: Profile;
  mode: RunMode;
  schema_version: string;
  stats: ApiRunStats;
  alerts: ApiAlert[];
  timeline: ApiTimelineEvent[];
  process_tree: ApiProcessTree;
  report_md: string;
  query: ApiResolvedQuery;
  artifacts: ApiArtifact[];
}

interface CaseArtifacts {
  dir: string;
  caseId: string;
  metadata: Record<string, unknown> | null;
  statsRaw: Record<string, unknown> | null;
  queryRaw: Record<string, unknown> | null;
  reportMd: string;
  processTreeRaw: Record<string, unknown> | null;
  timelineRawRows: Record<string, string>[];
  alerts: ApiAlert[];
  bundlesById: Map<string, ApiAlertBundle>;
}

const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_CSV_BYTES = 8 * 1024 * 1024;
const MAX_REPORT_BYTES = 8 * 1024 * 1024;
const MAX_BUNDLE_FILES = 5000;

function safeText(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value);
}

function toNumber(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toNullableNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeSlashes(value: string): string {
  return value.replace(/\\/g, '/');
}

function inferCategory(alertType: string): ApiAlert['category'] {
  const normalized = alertType.toLowerCase();
  if (normalized.includes('powershell') || normalized.includes('malware')) return 'malware_execution';
  if (normalized.includes('outbound') || normalized.includes('network') || normalized.includes('c2')) return 'c2_outbound';
  if (normalized.includes('schtasks') || normalized.includes('persist')) return 'persistence';
  if (normalized.includes('policy') || normalized.includes('allowlist')) return 'policy_violation';
  if (normalized.includes('dev')) return 'developer_tooling';
  return 'unknown';
}

function inferQueue(category: ApiAlert['category']): AlertQueue {
  if (category === 'malware_execution' || category === 'c2_outbound') return 'soc_malware';
  if (category === 'developer_tooling') return 'soc_dev';
  if (category === 'policy_violation') return 'soc_policy';
  return 'soc_policy';
}

function inferConfidence(score: number): ApiAlert['confidence'] {
  if (score >= 80) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
}

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let current = '';
  let inQuotes = false;
  let i = 0;
  while (i < line.length) {
    const ch = line[i];
    if (ch === '"') {
      const next = line[i + 1];
      if (inQuotes && next === '"') {
        current += '"';
        i += 2;
        continue;
      }
      inQuotes = !inQuotes;
      i += 1;
      continue;
    }
    if (ch === ',' && !inQuotes) {
      out.push(current);
      current = '';
      i += 1;
      continue;
    }
    current += ch;
    i += 1;
  }
  out.push(current);
  return out;
}

function parseCsvRows(text: string): Record<string, string>[] {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean);
  if (lines.length < 2) return [];
  const headers = parseCsvLine(lines[0]).map((header) => header.trim());
  return lines.slice(1).map((line) => {
    const values = parseCsvLine(line);
    const row: Record<string, string> = {};
    for (let i = 0; i < headers.length; i += 1) {
      row[headers[i]] = values[i] ?? '';
    }
    return row;
  });
}

function resolveRealDirOrResolved(dirPath: string): string {
  const resolved = path.resolve(dirPath);
  if (!fs.existsSync(resolved)) return resolved;
  return fs.realpathSync(resolved);
}

function assertInsideBase(baseDir: string, targetPath: string): void {
  const relative = path.relative(baseDir, targetPath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new ArtifactError('Requested path is outside allowed output directory', 404);
  }
}

function resolveCaseDir(outDir: string, caseId: string, mustExist = true): string {
  const safeCaseId = validateCaseId(caseId);
  const realOutDir = resolveRealDirOrResolved(outDir);
  const candidate = path.resolve(realOutDir, safeCaseId);
  if (!fs.existsSync(candidate)) {
    if (mustExist) {
      throw new ArtifactError(`Case ${safeCaseId} not found`, 404);
    }
    assertInsideBase(realOutDir, candidate);
    return candidate;
  }
  const realCandidate = fs.realpathSync(candidate);
  assertInsideBase(realOutDir, realCandidate);
  return realCandidate;
}

function readTextFile(filePath: string, maxBytes: number): string {
  if (!fs.existsSync(filePath)) return '';
  const stat = fs.statSync(filePath);
  if (stat.size > maxBytes) {
    throw new ArtifactError(`File too large: ${path.basename(filePath)}`, 413);
  }
  return fs.readFileSync(filePath, 'utf-8');
}

function readJsonFile<T = Record<string, unknown>>(filePath: string): T | null {
  if (!fs.existsSync(filePath)) return null;
  const raw = readTextFile(filePath, MAX_JSON_BYTES);
  if (!raw.trim()) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new ArtifactError(`Invalid JSON in ${path.basename(filePath)}`);
  }
}

function deriveRunTiming(
  caseDir: string,
  metadata: Record<string, unknown> | null,
): { startedAt: string; completedAt: string; durationMs: number } {
  const metadataPath = path.resolve(caseDir, 'run_metadata.json');
  const stat = fs.existsSync(metadataPath) ? fs.statSync(metadataPath) : null;
  const completedAt = stat ? stat.mtime.toISOString() : new Date().toISOString();
  const durationMs = toNumber(metadata?.total_duration_ms ?? metadata?.duration_ms, 0);
  const startedAt = new Date(new Date(completedAt).getTime() - Math.max(durationMs, 0)).toISOString();
  return { startedAt, completedAt, durationMs };
}

function deriveTimePreset(start?: string, end?: string): RunParams['time_preset'] {
  if (!start || !end) return '2h';
  const startMs = new Date(start).getTime();
  const endMs = new Date(end).getTime();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs <= startMs) return 'custom';
  const diffMinutes = (endMs - startMs) / 60000;
  if (Math.abs(diffMinutes - 15) < 1) return '15m';
  if (Math.abs(diffMinutes - 120) < 2) return '2h';
  if (Math.abs(diffMinutes - 1440) < 5) return '24h';
  if (Math.abs(diffMinutes - 10080) < 30) return '7d';
  return 'custom';
}

function normalizeConfidence(value: string): ApiArtifact['confidence'] {
  const normalized = value.toUpperCase();
  if (normalized === 'HIGH' || normalized === 'MEDIUM' || normalized === 'LOW') return normalized;
  return 'LOW';
}

function toTimeline(rows: Record<string, string>[]): ApiTimelineEvent[] {
  return rows.map((row) => ({
    timestamp: safeText(row.ts || row.timestamp || ''),
    event_id: toNumber(row.event_id || row.eventID, 0),
    image: safeText(row.image),
    command_line: safeText(row.command_line),
    parent_image: safeText(row.parent_image),
    target_filename: safeText(row.target_filename),
    user: safeText(row.user),
    rule_id: safeText(row.rule_id),
    agent_name: safeText(row.agent_name),
    agent_id: safeText(row.agent_id),
  }));
}

function toProcessTree(raw: Record<string, unknown> | null): ApiProcessTree {
  const nodes = Array.isArray(raw?.nodes) ? raw.nodes : [];
  const edges = Array.isArray(raw?.edges) ? raw.edges : [];
  const artifacts = Array.isArray(raw?.artifacts) ? raw.artifacts : [];
  return {
    schema_version: safeText(raw?.schema_version || '1.1.0'),
    agent: {
      name: safeText((raw?.agent as Record<string, unknown> | undefined)?.name || ''),
      id: safeText((raw?.agent as Record<string, unknown> | undefined)?.id || ''),
    },
    time_range: {
      start: safeText((raw?.time_range as Record<string, unknown> | undefined)?.start || ''),
      end: safeText((raw?.time_range as Record<string, unknown> | undefined)?.end || ''),
    },
    nodes: nodes.map((node) => {
      const value = node as Record<string, unknown>;
      return {
        guid: safeText(value.guid),
        pid: toNumber(value.pid, 0),
        image: safeText(value.image),
        cmdline: safeText(value.cmdline),
        user: safeText(value.user),
        first_seen: safeText(value.first_seen),
        last_seen: safeText(value.last_seen),
        synthetic: Boolean(value.synthetic),
        tags: Array.isArray(value.tags) ? value.tags.map((item) => String(item)) : [],
      };
    }),
    edges: edges.map((edge) => {
      const value = edge as Record<string, unknown>;
      return {
        parent_guid: safeText(value.parent_guid),
        child_guid: safeText(value.child_guid),
        reason: safeText(value.reason),
      };
    }),
    artifacts: artifacts.map((artifact) => {
      const value = artifact as Record<string, unknown>;
      return {
        path: safeText(value.path),
        created_at: safeText(value.created_at),
        creating_process_guid: safeText(value.creating_process_guid),
        creating_image: safeText(value.creating_image),
        confidence: normalizeConfidence(safeText(value.confidence || 'LOW')),
        reason: safeText(value.reason),
        tags: Array.isArray(value.tags) ? value.tags.map((item) => String(item)) : [],
      };
    }),
  };
}

function toQuery(
  raw: Record<string, unknown> | null,
  metadata: Record<string, unknown> | null,
): ApiResolvedQuery {
  const query = raw ?? ((metadata?.query as Record<string, unknown> | undefined) ?? {});
  const rangeFilter = (
    Array.isArray(((query.query as Record<string, unknown> | undefined)?.bool as Record<string, unknown> | undefined)?.filter)
      ? ((((query.query as Record<string, unknown> | undefined)?.bool as Record<string, unknown> | undefined)?.filter as unknown[]).find((item) => Boolean((item as Record<string, unknown>).range)) as Record<string, unknown> | undefined)
      : undefined
  );
  const range = (rangeFilter?.range as Record<string, unknown> | undefined)?.['@timestamp'] as Record<string, unknown> | undefined;
  const should = (((query.query as Record<string, unknown> | undefined)?.bool as Record<string, unknown> | undefined)?.filter as unknown[] | undefined)?.find((item) => Boolean(((item as Record<string, unknown>).bool as Record<string, unknown> | undefined)?.should)) as Record<string, unknown> | undefined;
  const shouldTerms = (((should?.bool as Record<string, unknown> | undefined)?.should as unknown[] | undefined)?.find((entry) => Boolean((entry as Record<string, unknown>).terms)) as Record<string, unknown> | undefined)?.terms as Record<string, unknown> | undefined;
  const eventIdsRaw = shouldTerms ? Object.values(shouldTerms)[0] : undefined;
  const eventIds = Array.isArray(eventIdsRaw)
    ? eventIdsRaw.map((value) => Number(value)).filter((value) => Number.isFinite(value))
    : [1, 3, 11];
  return {
    index: safeText(query.index || metadata?.index_pattern || 'wazuh-alerts-*'),
    start: safeText(range?.gte || metadata?.start || ''),
    end: safeText(range?.lte || metadata?.end || ''),
    agent_id: safeText(metadata?.agent_id || '') || undefined,
    agent_name: safeText(metadata?.agent_name || '') || undefined,
    event_ids: eventIds.length ? eventIds : [1, 3, 11],
    size: toNumber(query.size, 10000),
  };
}

function toRunParams(
  metadata: Record<string, unknown> | null,
  statsRaw: Record<string, unknown> | null,
  caseDir: string,
): RunParams {
  const queueFilter = (
    (metadata?.queue_filter as Record<string, unknown> | undefined) ??
    (statsRaw?.queue_filter as Record<string, unknown> | undefined) ??
    {}
  );
  const query = (metadata?.query as Record<string, unknown> | undefined) ?? {};
  const inputFile = safeText(query.input_ndjson || '');
  const mode: RunMode = inputFile ? 'offline' : 'live';
  const start = safeText(metadata?.start || '');
  const end = safeText(metadata?.end || '');

  let caseId = safeText(metadata?.case_id || path.basename(caseDir));
  try {
    caseId = validateCaseId(caseId);
  } catch {
    caseId = validateCaseId(path.basename(caseDir));
  }

  return {
    mode,
    profile: (safeText(metadata?.profile || 'soc') as Profile) || 'soc',
    time_preset: deriveTimePreset(start || undefined, end || undefined),
    start: start || undefined,
    end: end || undefined,
    agent_name: safeText(metadata?.agent_name || '') || undefined,
    agent_id: safeText(metadata?.agent_id || '') || undefined,
    input_file: inputFile || undefined,
    queues: (
      Array.isArray(queueFilter.alert_queues)
        ? queueFilter.alert_queues.map((item) => String(item))
        : ['soc_malware', 'soc_policy']
    ) as AlertQueue[],
    include_dev_queue: Boolean(queueFilter.include_dev_queue),
    min_alert_score: toNumber(metadata?.min_alert_score, 70),
    out_dir: normalizeSlashes(path.dirname(caseDir)),
    case_id: caseId,
    dry_run: false,
    alerts_only: false,
    print_stats: true,
    verify_tls: typeof metadata?.verify_tls === 'boolean' ? Boolean(metadata.verify_tls) : undefined,
    allowlist_images: [],
    allow_overwrite: false,
    force: false,
  };
}

function computeStats(artifacts: CaseArtifacts): ApiRunStats {
  const byEventId: Record<string, number> = {};
  for (const row of artifacts.timelineRawRows) {
    const eventId = safeText(row.event_id || row.eventID || '').trim();
    if (!eventId) continue;
    byEventId[eventId] = (byEventId[eventId] ?? 0) + 1;
  }

  const queues: Record<string, number> = {};
  const categories: Record<string, number> = {};
  const confidenceDistribution: Record<string, number> = {};
  const suspiciousIps = new Set<string>();

  for (const alert of artifacts.alerts) {
    queues[alert.queue] = (queues[alert.queue] ?? 0) + 1;
    categories[alert.category] = (categories[alert.category] ?? 0) + 1;
    confidenceDistribution[alert.confidence] = (confidenceDistribution[alert.confidence] ?? 0) + 1;
    if (alert.destination_ip) suspiciousIps.add(alert.destination_ip);
  }

  const raw = artifacts.statsRaw ?? {};
  const counts = (artifacts.metadata?.counts as Record<string, unknown> | undefined) ?? {};

  return {
    total_events: toNumber(raw.total_events ?? counts.normalized_events, artifacts.timelineRawRows.length),
    by_event_id: byEventId,
    alerts_generated: toNumber(counts.alerts ?? raw.alert_count, artifacts.alerts.length),
    alerts_suppressed: toNumber(raw.suppressed_alerts ?? counts.suppressed_alerts, 0),
    suppression_hits: (raw.suppression_hits as Record<string, number> | undefined) ?? {},
    dropped_events: toNumber(raw.dropped_count ?? artifacts.metadata?.dropped_count, 0),
    dropped_by_reason: (raw.dropped_by_reason as Record<string, number> | undefined) ?? {},
    queues,
    categories,
    confidence_distribution: confidenceDistribution,
    network_connections: toNumber((raw.events_by_type as Record<string, unknown> | undefined)?.network_connect, 0),
    suspicious_destinations: suspiciousIps.size,
  };
}

function toRun(caseArtifacts: CaseArtifacts): ApiRun {
  const metadataRaw = caseArtifacts.metadata ?? {};
  const params = toRunParams(caseArtifacts.metadata, caseArtifacts.statsRaw, caseArtifacts.dir);
  const timing = deriveRunTiming(caseArtifacts.dir, caseArtifacts.metadata);
  const stats = computeStats(caseArtifacts);
  const runId = safeText(metadataRaw.run_id || metadataRaw.case_id || caseArtifacts.caseId);
  const metadata: ApiRunMetadata = {
    run_id: runId,
    case_id: params.case_id,
    started_at: timing.startedAt,
    completed_at: timing.completedAt,
    duration_ms: timing.durationMs,
    params,
    schema_version: safeText(metadataRaw.schema_version || '1.1.0'),
    stages: [
      { name: 'fetch', started_at: timing.startedAt, completed_at: timing.completedAt, duration_ms: toNumber(metadataRaw.fetch_duration_ms, 0), status: 'success' },
      { name: 'normalize', started_at: timing.startedAt, completed_at: timing.completedAt, duration_ms: toNumber(metadataRaw.normalize_duration_ms, 0), status: 'success' },
      { name: 'correlate', started_at: timing.startedAt, completed_at: timing.completedAt, duration_ms: toNumber(metadataRaw.correlate_duration_ms, 0), status: 'success' },
      { name: 'detect', started_at: timing.startedAt, completed_at: timing.completedAt, duration_ms: toNumber(metadataRaw.detect_duration_ms, 0), status: 'success' },
      { name: 'render', started_at: timing.startedAt, completed_at: timing.completedAt, duration_ms: toNumber(metadataRaw.render_duration_ms, 0), status: 'success' },
    ],
  };
  return {
    id: runId,
    params,
    status: 'success',
    started_at: timing.startedAt,
    completed_at: timing.completedAt,
    duration_ms: timing.durationMs,
    alert_count: stats.alerts_generated,
    metadata,
    stats,
  };
}

function toCase(caseArtifacts: CaseArtifacts): ApiCase {
  const stats = computeStats(caseArtifacts);
  const params = toRunParams(caseArtifacts.metadata, caseArtifacts.statsRaw, caseArtifacts.dir);
  const processTree = toProcessTree(caseArtifacts.processTreeRaw);
  const runId = safeText(caseArtifacts.metadata?.run_id || params.case_id);
  return {
    case_id: params.case_id,
    run_id: runId,
    time_range: processTree.time_range,
    profile: params.profile,
    mode: params.mode,
    schema_version: safeText(caseArtifacts.metadata?.schema_version || processTree.schema_version || '1.1.0'),
    stats,
    alerts: caseArtifacts.alerts,
    timeline: toTimeline(caseArtifacts.timelineRawRows),
    process_tree: processTree,
    report_md: caseArtifacts.reportMd,
    query: toQuery(caseArtifacts.queryRaw, caseArtifacts.metadata),
    artifacts: processTree.artifacts,
  };
}

function buildBundleFromRaw(raw: Record<string, unknown>, alertIdFallback: string): ApiAlertBundle | null {
  const alertPart = (raw.alert ?? {}) as Record<string, unknown>;
  const alertId = safeText(alertPart.alert_id || alertIdFallback).trim();
  if (!alertId) return null;

  const score = toNumber(alertPart.score, 0);
  const alertType = safeText(alertPart.alert_type || '');
  const derivedFields: string[] = [];
  const categoryRaw = safeText(alertPart.category || '').trim();
  const category = (categoryRaw || inferCategory(alertType)) as ApiAlert['category'];
  if (!categoryRaw) derivedFields.push('category');
  const queueRaw = safeText(alertPart.queue || '').trim();
  const queue = (queueRaw || inferQueue(category)) as AlertQueue;
  if (!queueRaw) derivedFields.push('queue');
  const confidenceRaw = safeText(alertPart.confidence || '').trim();
  const confidence = (confidenceRaw || inferConfidence(score)) as ApiAlert['confidence'];
  if (!confidenceRaw) derivedFields.push('confidence');
  const routingWhy = safeText(alertPart.routing_why || '');
  if (!routingWhy.trim()) derivedFields.push('routing_why');
  const alert: ApiAlert = {
    alert_id: alertId,
    utc_time: safeText(alertPart.utc_time || ''),
    score,
    alert_type: alertType,
    category,
    queue,
    confidence,
    reason: safeText(alertPart.reason || ''),
    routing_why: routingWhy,
    image: safeText((raw.anchor_event as Record<string, unknown> | undefined)?.image || ''),
    command_line: safeText((raw.anchor_event as Record<string, unknown> | undefined)?.command_line || ''),
    parent_image: safeText((raw.anchor_event as Record<string, unknown> | undefined)?.parent_image || ''),
    destination_ip: safeText((raw.anchor_event as Record<string, unknown> | undefined)?.destination_ip || ''),
    destination_port: toNullableNumber((raw.anchor_event as Record<string, unknown> | undefined)?.destination_port),
    process_guid: safeText(alertPart.process_guid || ''),
    tags: [],
    rule_id: safeText(alertPart.rule_id || ''),
    rule_name: safeText(alertPart.rule_name || ''),
    suppressed_related_count: toNumber((raw.suppression_context as Record<string, unknown> | undefined)?.suppressed_related_event_count, 0),
    suppressed_related_rules: Array.isArray((raw.suppression_context as Record<string, unknown> | undefined)?.matched_rules)
      ? ((raw.suppression_context as Record<string, unknown>).matched_rules as unknown[]).map((value) => String(value))
      : [],
    derived_fields: derivedFields,
  };

  const relatedEvents = [
    raw.anchor_event,
    ...(Array.isArray(raw.process_ancestry) ? raw.process_ancestry : []),
    ...(Array.isArray(raw.sibling_spawns) ? raw.sibling_spawns : []),
    ...(Array.isArray(raw.related_processes) ? raw.related_processes : []),
    ...(Array.isArray(raw.file_artifacts) ? raw.file_artifacts : []),
    ...(Array.isArray(raw.network_connections) ? raw.network_connections : []),
  ]
    .filter(Boolean)
    .map((eventRaw) => {
      const event = eventRaw as Record<string, unknown>;
      return {
        timestamp: safeText(event.timestamp || event.ts || ''),
        event_id: toNumber(event.event_id, 0),
        image: safeText(event.image || ''),
        command_line: safeText(event.command_line || ''),
        parent_image: safeText(event.parent_image || ''),
        target_filename: safeText(event.target_filename || ''),
        user: safeText(event.user || ''),
        rule_id: safeText(event.rule_id || ''),
        agent_name: safeText(event.agent_name || ''),
        agent_id: safeText(event.agent_id || ''),
      } satisfies ApiTimelineEvent;
    });

  const processContext: ApiProcessNode[] = relatedEvents
    .filter((event) => event.event_id === 1 && Boolean(event.image))
    .slice(0, 6)
    .map((event, index) => ({
      guid: index === 0 ? alert.process_guid : `${alert.process_guid}-ctx-${index}`,
      pid: index + 1,
      image: event.image,
      cmdline: event.command_line,
      user: event.user,
      first_seen: event.timestamp,
      last_seen: event.timestamp,
      synthetic: index > 0,
      tags: [],
    }));

  const networkContext = (Array.isArray(raw.network_connections) ? raw.network_connections : [])
    .map((entry) => {
      const net = entry as Record<string, unknown>;
      return {
        process_guid: safeText(net.process_guid || alert.process_guid),
        image: safeText(net.image || alert.image),
        destination_ip: safeText(net.destination_ip || ''),
        destination_port: toNumber(net.destination_port, 0),
        protocol: safeText(net.protocol || 'tcp'),
        suspicious: Boolean(net.suspicious ?? true),
      };
    })
    .filter((entry) => Boolean(entry.destination_ip));

  return {
    alert,
    related_events: relatedEvents,
    process_context: processContext,
    network_context: networkContext,
  };
}

function parseAlerts(
  alertRows: Record<string, string>[],
  bundlesById: Map<string, ApiAlertBundle>,
): ApiAlert[] {
  return alertRows.map((row, index) => {
    const generatedId = row.alert_id?.trim() || `A${String(index + 1).padStart(3, '0')}`;
    const fromBundle = bundlesById.get(generatedId)?.alert;
    const score = toNumber(row.score, fromBundle?.score ?? 0);
    const alertType = safeText(row.alert_type || fromBundle?.alert_type || '');
    const derivedFields = new Set<string>(fromBundle?.derived_fields ?? []);

    const categoryRaw = safeText(row.category || fromBundle?.category || '').trim();
    const category = (categoryRaw || inferCategory(alertType)) as ApiAlert['category'];
    if (!categoryRaw) derivedFields.add('category');

    const queueRaw = safeText(row.queue || fromBundle?.queue || '').trim();
    const queue = (queueRaw || inferQueue(category)) as AlertQueue;
    if (!queueRaw) derivedFields.add('queue');

    const confidenceRaw = safeText(row.confidence || fromBundle?.confidence || '').trim();
    const confidence = (confidenceRaw || inferConfidence(score)) as ApiAlert['confidence'];
    if (!confidenceRaw) derivedFields.add('confidence');

    const routingWhy = safeText(row.routing_why || fromBundle?.routing_why || '');
    if (!routingWhy.trim()) derivedFields.add('routing_why');

    return {
      alert_id: generatedId,
      utc_time: safeText(row.utc_time || fromBundle?.utc_time || ''),
      score,
      alert_type: alertType,
      category,
      queue,
      confidence,
      reason: safeText(row.reason || fromBundle?.reason || ''),
      routing_why: routingWhy,
      image: safeText(row.image || fromBundle?.image || ''),
      command_line: safeText(row.command_line || fromBundle?.command_line || ''),
      parent_image: safeText(row.parent_image || fromBundle?.parent_image || ''),
      destination_ip: safeText(row.destination_ip || fromBundle?.destination_ip || ''),
      destination_port: toNullableNumber(row.destination_port) ?? fromBundle?.destination_port ?? null,
      process_guid: safeText(row.process_guid || fromBundle?.process_guid || ''),
      tags: row.tags
        ? row.tags.split(';').map((value) => value.trim()).filter(Boolean)
        : (fromBundle?.tags ?? []),
      rule_id: fromBundle?.rule_id,
      rule_name: fromBundle?.rule_name,
      suppressed_related_count: fromBundle?.suppressed_related_count ?? 0,
      suppressed_related_rules: fromBundle?.suppressed_related_rules ?? [],
      derived_fields: Array.from(derivedFields),
    };
  });
}

function looksLikeCaseDir(caseDir: string): boolean {
  return [
    'run_metadata.json',
    'alerts.csv',
    'timeline.csv',
    'report.md',
    'process_tree.json',
  ].some((fileName) => fs.existsSync(path.resolve(caseDir, fileName)));
}

function toFailedRun(outDir: string, caseId: string, error: unknown): ApiRun {
  const caseDir = path.resolve(outDir, caseId);
  const time = fs.existsSync(caseDir)
    ? fs.statSync(caseDir).mtime.toISOString()
    : new Date().toISOString();
  const message = error instanceof Error ? error.message : 'Failed to load case artifacts';
  return {
    id: caseId,
    params: {
      mode: 'offline',
      profile: 'soc',
      time_preset: '2h',
      queues: ['soc_malware', 'soc_policy'],
      include_dev_queue: false,
      min_alert_score: 70,
      out_dir: normalizeSlashes(path.resolve(outDir)),
      case_id: caseId,
      dry_run: false,
      alerts_only: false,
      print_stats: true,
      allowlist_images: [],
      allow_overwrite: false,
      force: false,
    },
    status: 'failed',
    started_at: time,
    completed_at: time,
    error: `artifact_load_failed: ${message}`,
  };
}

function readCaseArtifacts(caseDir: string): CaseArtifacts {
  const caseId = path.basename(caseDir);
  const metadata = readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'run_metadata.json'));
  const statsRaw = readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'stats.json'));
  const queryRaw = readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'query.json'));
  const reportMd = readTextFile(path.resolve(caseDir, 'report.md'), MAX_REPORT_BYTES);
  const processTreeRaw = readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'process_tree.json'));
  const timelineCsv = readTextFile(path.resolve(caseDir, 'timeline.csv'), MAX_CSV_BYTES);
  const timelineRawRows = parseCsvRows(timelineCsv);
  const alertsCsv = readTextFile(path.resolve(caseDir, 'alerts.csv'), MAX_CSV_BYTES);
  const alertRows = parseCsvRows(alertsCsv);

  const entries = fs.readdirSync(caseDir, { withFileTypes: true });
  const bundleFiles = entries
    .filter((entry) => entry.isFile() && /^alert_.+_bundle\.json$/i.test(entry.name))
    .slice(0, MAX_BUNDLE_FILES)
    .map((entry) => path.resolve(caseDir, entry.name));

  const bundlesById = new Map<string, ApiAlertBundle>();
  for (const filePath of bundleFiles) {
    const raw = readJsonFile<Record<string, unknown>>(filePath);
    if (!raw) continue;
    const fromName = safeText(path.basename(filePath).match(/^alert_(.+)_bundle\.json$/i)?.[1] || '').trim();
    const bundle = buildBundleFromRaw(raw, fromName);
    if (!bundle) continue;
    bundlesById.set(bundle.alert.alert_id, bundle);
  }

  const alerts = parseAlerts(alertRows, bundlesById);
  for (const alert of alerts) {
    const bundle = bundlesById.get(alert.alert_id);
    if (!bundle) continue;
    bundle.alert = { ...bundle.alert, ...alert };
  }

  return {
    dir: caseDir,
    caseId,
    metadata,
    statsRaw,
    queryRaw,
    reportMd,
    processTreeRaw,
    timelineRawRows,
    alerts,
    bundlesById,
  };
}

export function resolveSafeCaseDir(outDir: string, caseId: string, mustExist = true): string {
  return resolveCaseDir(outDir, caseId, mustExist);
}

export async function listCaseIds(outDir: string): Promise<string[]> {
  const resolvedOutDir = resolveRealDirOrResolved(outDir);
  if (!fs.existsSync(resolvedOutDir)) return [];
  const entries = await fsp.readdir(resolvedOutDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
}

export function loadCaseArtifacts(outDir: string, caseId: string): CaseArtifacts {
  const caseDir = resolveCaseDir(outDir, caseId, true);
  return readCaseArtifacts(caseDir);
}

export async function loadAllRuns(outDir: string): Promise<ApiRun[]> {
  const caseIds = await listCaseIds(outDir);
  const runs: ApiRun[] = [];
  for (const caseId of caseIds) {
    try {
      const artifacts = loadCaseArtifacts(outDir, caseId);
      if (!artifacts.metadata) continue;
      runs.push(toRun(artifacts));
    } catch (error) {
      const caseDir = path.resolve(outDir, caseId);
      if (!looksLikeCaseDir(caseDir)) continue;
      runs.push(toFailedRun(outDir, caseId, error));
    }
  }
  runs.sort((a, b) => {
    const left = new Date(b.completed_at || b.started_at).getTime();
    const right = new Date(a.completed_at || a.started_at).getTime();
    return left - right;
  });
  return runs;
}

export function loadRun(outDir: string, caseId: string): ApiRun {
  const artifacts = loadCaseArtifacts(outDir, caseId);
  return toRun(artifacts);
}

export function loadCase(outDir: string, caseId: string): ApiCase {
  const artifacts = loadCaseArtifacts(outDir, caseId);
  return toCase(artifacts);
}

export async function deleteCase(outDir: string, caseId: string): Promise<void> {
  const caseDir = resolveCaseDir(outDir, caseId, true);
  try {
    await fsp.rm(caseDir, { recursive: true, force: false, maxRetries: 2 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new ArtifactError(`Case ${caseId} not found`, 404);
    }
    throw new ArtifactError(`Failed to delete case ${caseId}`);
  }
}

export function loadAlerts(outDir: string, caseId: string): ApiAlert[] {
  const artifacts = loadCaseArtifacts(outDir, caseId);
  return artifacts.alerts;
}

export function loadAlertBundle(outDir: string, caseId: string, alertId: string): ApiAlertBundle {
  const artifacts = loadCaseArtifacts(outDir, caseId);
  const normalizedAlertId = safeText(alertId).trim();
  const bundle = artifacts.bundlesById.get(normalizedAlertId);
  if (!bundle) {
    throw new ArtifactError(`Bundle ${normalizedAlertId} not found in case ${caseId}`, 404);
  }
  return bundle;
}

export function loadReport(outDir: string, caseId: string): string {
  const artifacts = loadCaseArtifacts(outDir, caseId);
  return artifacts.reportMd;
}
