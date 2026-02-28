import path from 'node:path';

export class ValidationError extends Error {
  readonly status: number;

  constructor(message: string, status = 400) {
    super(message);
    this.name = 'ValidationError';
    this.status = status;
  }
}

export type RunMode = 'live' | 'offline';
export type Profile = 'soc' | 'dev' | 'lab';
export type TimePreset = '15m' | '2h' | '24h' | '7d' | 'today' | 'yesterday' | 'custom';
export type AlertQueue = 'soc_malware' | 'soc_policy' | 'soc_dev' | 'soc_info';

export interface RunParams {
  mode: RunMode;
  profile: Profile;
  time_preset: TimePreset;
  start?: string;
  end?: string;
  agent_name?: string;
  agent_id?: string;
  input_file?: string;
  queues: AlertQueue[];
  include_dev_queue: boolean;
  min_alert_score: number;
  out_dir: string;
  case_id: string;
  dry_run: boolean;
  alerts_only: boolean;
  print_stats: boolean;
  verify_tls?: boolean;
  allowlist_images: string[];
  allow_overwrite: boolean;
  force: boolean;
}

interface ValidateRunParamsOptions {
  defaultOutDir: string;
  rootDir?: string;
  allowedOfflineInputRoots?: string[];
  defaultCaseId?: () => string;
}

const CASE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/;
const ENCODED_TRAVERSAL_PATTERN = /%2e|%2f|%5c|%252e|%252f|%255c/i;

const VALID_MODES = new Set<RunMode>(['live', 'offline']);
const VALID_PROFILES = new Set<Profile>(['soc', 'dev', 'lab']);
const VALID_TIME_PRESETS = new Set<TimePreset>(['15m', '2h', '24h', '7d', 'today', 'yesterday', 'custom']);
const VALID_QUEUES = new Set<AlertQueue>(['soc_malware', 'soc_policy', 'soc_dev', 'soc_info']);

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ValidationError('Invalid run parameters');
  }
  return value as Record<string, unknown>;
}

function toOptionalString(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function toBoolean(value: unknown, fallback: boolean): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
    if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  }
  if (typeof value === 'number') {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  return fallback;
}

function toNumberInRange(value: unknown, fallback: number, min: number, max: number, fieldName: string): number {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new ValidationError(`${fieldName} must be a number`);
  }
  if (parsed < min || parsed > max) {
    throw new ValidationError(`${fieldName} must be between ${min} and ${max}`);
  }
  return Math.round(parsed);
}

function parseEnum<T extends string>(
  raw: unknown,
  valid: Set<T>,
  fallback: T,
  fieldName: string,
): T {
  if (raw === undefined || raw === null || raw === '') return fallback;
  const value = String(raw).trim() as T;
  if (!valid.has(value)) {
    throw new ValidationError(`${fieldName} is invalid`);
  }
  return value;
}

function parseQueues(raw: unknown): AlertQueue[] {
  if (raw === undefined || raw === null) return ['soc_malware', 'soc_policy'];
  if (!Array.isArray(raw)) {
    throw new ValidationError('queues must be an array');
  }

  const deduped = new Set<AlertQueue>();
  for (const item of raw) {
    const queue = String(item).trim() as AlertQueue;
    if (!VALID_QUEUES.has(queue)) {
      throw new ValidationError(`Unsupported queue: ${String(item)}`);
    }
    deduped.add(queue);
  }

  if (!deduped.size) {
    throw new ValidationError('At least one queue is required');
  }
  return Array.from(deduped);
}

function normalizeAllowlistImage(value: string): string | null {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return null;
  const parts = trimmed.split(/[\\/]/);
  const basename = parts[parts.length - 1]?.trim();
  if (!basename) return null;
  return basename;
}

function parseAllowlistImages(raw: unknown): string[] {
  if (raw === undefined || raw === null) return [];

  const values = Array.isArray(raw) ? raw : [raw];
  const deduped = new Set<string>();

  for (const item of values) {
    if (typeof item !== 'string') {
      throw new ValidationError('allowlist_images must be an array of strings');
    }
    const normalized = normalizeAllowlistImage(item);
    if (!normalized) continue;
    deduped.add(normalized);
    if (deduped.size > 200) {
      throw new ValidationError('allowlist_images exceeds maximum of 200 entries');
    }
  }

  return Array.from(deduped);
}

function isValidDate(value: string): boolean {
  const date = new Date(value);
  return Number.isFinite(date.getTime());
}

function isInsideRoot(rootDir: string, candidatePath: string): boolean {
  const relative = path.relative(rootDir, candidatePath);
  return !relative.startsWith('..') && !path.isAbsolute(relative);
}

function normalizeAllowedOfflineRoots(options: ValidateRunParamsOptions): string[] {
  const rootDir = path.resolve(options.rootDir ?? '.');
  const configuredRoots = options.allowedOfflineInputRoots?.length
    ? options.allowedOfflineInputRoots
    : ['samples'];
  return configuredRoots.map((entry) => path.resolve(rootDir, entry));
}

function validateOfflineInputFile(
  value: string | undefined,
  options: ValidateRunParamsOptions,
): string | undefined {
  if (!value) return undefined;
  if (value.includes('\0')) {
    throw new ValidationError('input_file contains invalid characters');
  }
  if (path.isAbsolute(value)) {
    throw new ValidationError('offline input_file must be a relative path');
  }

  const normalized = path.normalize(value);
  const parts = normalized.split(/[\\/]+/).filter(Boolean);
  if (parts.includes('..')) {
    throw new ValidationError('offline input_file contains path traversal segments');
  }

  const rootDir = path.resolve(options.rootDir ?? '.');
  const resolved = path.resolve(rootDir, normalized);
  const allowedRoots = normalizeAllowedOfflineRoots(options);
  const allowed = allowedRoots.some((allowedRoot) => isInsideRoot(allowedRoot, resolved));
  if (!allowed) {
    throw new ValidationError('offline input_file must resolve under an allowed input root');
  }

  return normalized;
}

function defaultCaseId(): string {
  return `incident-${Date.now()}`;
}

export function validateCaseId(caseId: string): string {
  if (typeof caseId !== 'string') {
    throw new ValidationError('case_id must be a string');
  }
  const normalized = caseId.trim();
  if (!normalized) {
    throw new ValidationError('case_id is required');
  }
  const lower = normalized.toLowerCase();
  if (
    normalized.includes('/') ||
    normalized.includes('\\') ||
    normalized.includes('..') ||
    normalized.includes('%') ||
    ENCODED_TRAVERSAL_PATTERN.test(lower)
  ) {
    throw new ValidationError('case_id contains disallowed path characters');
  }
  if (!CASE_ID_PATTERN.test(normalized)) {
    throw new ValidationError('case_id must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$');
  }
  return normalized;
}

export function validateRunParams(body: unknown, options: ValidateRunParamsOptions): RunParams {
  const root = asRecord(body);
  const raw = root.params && typeof root.params === 'object' && !Array.isArray(root.params)
    ? (root.params as Record<string, unknown>)
    : root;

  const mode = parseEnum<RunMode>(raw.mode, VALID_MODES, 'live', 'mode');
  const profile = parseEnum<Profile>(raw.profile, VALID_PROFILES, 'soc', 'profile');
  const timePreset = parseEnum<TimePreset>(raw.time_preset, VALID_TIME_PRESETS, '2h', 'time_preset');
  const start = toOptionalString(raw.start);
  const end = toOptionalString(raw.end);

  if (timePreset === 'custom') {
    if (!start || !end) {
      throw new ValidationError('custom time_preset requires start and end');
    }
    if (!isValidDate(start) || !isValidDate(end)) {
      throw new ValidationError('start and end must be valid datetime values');
    }
    if (new Date(end).getTime() <= new Date(start).getTime()) {
      throw new ValidationError('end must be greater than start');
    }
  } else if (start || end) {
    throw new ValidationError('start/end are only allowed when time_preset is custom');
  }

  const queues = parseQueues(raw.queues);
  const includeDevQueue = toBoolean(raw.include_dev_queue, false);
  const minAlertScore = toNumberInRange(raw.min_alert_score, 70, 0, 100, 'min_alert_score');
  const verifyTls = (raw.verify_tls === undefined || raw.verify_tls === null || raw.verify_tls === '')
    ? undefined
    : toBoolean(raw.verify_tls, true);
  const allowlistImages = parseAllowlistImages(raw.allowlist_images ?? raw.allowlist_image);

  const outDir = path.resolve(options.defaultOutDir);
  const requestedOutDir = toOptionalString(raw.out_dir);
  if (requestedOutDir) {
    const normalizedRequestedOutDir = path.resolve(requestedOutDir);
    if (normalizedRequestedOutDir !== outDir) {
      throw new ValidationError(
        `out_dir is managed by the server and must match ${outDir}`,
      );
    }
  }
  const caseId = validateCaseId(
    toOptionalString(raw.case_id) ?? (options.defaultCaseId ? options.defaultCaseId() : defaultCaseId()),
  );

  const params: RunParams = {
    mode,
    profile,
    time_preset: timePreset,
    start,
    end,
    agent_name: toOptionalString(raw.agent_name),
    agent_id: toOptionalString(raw.agent_id),
    input_file: mode === 'offline'
      ? validateOfflineInputFile(toOptionalString(raw.input_file), options)
      : undefined,
    queues,
    include_dev_queue: includeDevQueue,
    min_alert_score: minAlertScore,
    out_dir: outDir,
    case_id: caseId,
    dry_run: toBoolean(raw.dry_run, false),
    alerts_only: toBoolean(raw.alerts_only, false),
    print_stats: toBoolean(raw.print_stats, true),
    verify_tls: verifyTls,
    allowlist_images: allowlistImages,
    allow_overwrite: toBoolean(raw.allow_overwrite, false),
    force: toBoolean(raw.force, false),
  };

  return params;
}
