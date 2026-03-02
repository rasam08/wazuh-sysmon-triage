import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { ApiRun } from './artifact-loader';
import { createRunExecutor, type RunExecutor } from './run-executor';
import { RunnerError, type Runner } from './runner';
import type { RunParams } from './validators';

type QueueJobStatus = 'queued' | 'running' | 'success' | 'failed' | 'cancelled';
type QueueJobStage = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

interface QueueJob {
  job_id: string;
  case_id: string;
  params: RunParams;
  status: QueueJobStatus;
  stage: QueueJobStage;
  progress_pct: number;
  accepted_at: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  message?: string;
  cancel_reason?: string;
}

interface QueueJobRecord extends QueueJob {
  request_hash: string;
  idempotency_key?: string;
  accepted_at_ms: number;
  cancel_requested: boolean;
}

interface PersistedQueueState {
  version: 1;
  active_job_id: string | null;
  queue: string[];
  jobs: QueueJobRecord[];
}

interface QueueJobEvent {
  event: 'progress' | 'terminal';
  job_id: string;
  case_id: string;
  stage: string;
  progress_pct: number;
  status: QueueJobStatus;
  ts: string;
  message?: string;
  cancel_reason?: string;
}

interface RunQueueServiceOptions {
  outDir: string;
  executor?: RunExecutor;
  // Backward-compatible option path for existing callers.
  runner?: Runner;
  now?: () => number;
  idempotencyWindowMs?: number;
}

interface SubmitRunOptions {
  idempotencyKey?: string | null;
  requestBody?: unknown;
}

const DEFAULT_IDEMPOTENCY_WINDOW_MS = 24 * 60 * 60 * 1000;
const QUEUE_DB_FILENAME = 'run_queue.sqlite3';
const LEGACY_QUEUE_STATE_FILENAME = 'run_queue_state.json';
const JOB_STATE_FILENAME = 'job_state.json';
const RUN_QUEUE_DIR = '.run-queue';
const ACTIVE_RUN_RETRY_MS = 500;
const TERMINAL_JOB_STATUSES = new Set<QueueJobStatus>(['success', 'failed', 'cancelled']);
const SQLITE_STATE_KEY = 'queue_state_v1';
const SQLITE_READ_STATE_SCRIPT = [
  'import os, sqlite3, sys',
  'db_path = sys.argv[1]',
  'if not os.path.exists(db_path):',
  '    sys.exit(0)',
  'conn = sqlite3.connect(db_path)',
  'try:',
  '    conn.execute("CREATE TABLE IF NOT EXISTS queue_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL)")',
  `    row = conn.execute("SELECT state_json FROM queue_state WHERE state_key = ?", ("${SQLITE_STATE_KEY}",)).fetchone()`,
  '    if row and row[0]:',
  '        sys.stdout.write(row[0])',
  'finally:',
  '    conn.close()',
].join('\n');
const SQLITE_WRITE_STATE_SCRIPT = [
  'import os, sqlite3, sys',
  'db_path = sys.argv[1]',
  'payload = sys.stdin.read()',
  'db_dir = os.path.dirname(db_path)',
  'if db_dir:',
  '    os.makedirs(db_dir, exist_ok=True)',
  'conn = sqlite3.connect(db_path)',
  'try:',
  '    conn.execute("PRAGMA journal_mode=WAL")',
  '    conn.execute("CREATE TABLE IF NOT EXISTS queue_state (state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL)")',
  `    conn.execute("INSERT OR REPLACE INTO queue_state (state_key, state_json) VALUES (?, ?)", ("${SQLITE_STATE_KEY}", payload))`,
  '    conn.commit()',
  'finally:',
  '    conn.close()',
].join('\n');
const LEGACY_READ_STATE_SCRIPT = [
  'import os, sys',
  'state_path = sys.argv[1]',
  'if not os.path.exists(state_path):',
  '    sys.exit(0)',
  'with open(state_path, encoding="utf-8") as handle:',
  '    sys.stdout.write(handle.read())',
].join('\n');

function writeJsonAtomic(targetPath: string, payload: unknown): void {
  const tmpPath = `${targetPath}.${process.pid}.${randomUUID()}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), 'utf-8');
  try {
    fs.renameSync(tmpPath, targetPath);
    return;
  } catch {
    // Fallback path for environments that lock rename destinations (for example synced folders on Windows).
    fs.copyFileSync(tmpPath, targetPath);
    fs.rmSync(tmpPath, { force: true });
  }
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hashPayload(value: unknown): string {
  return createHash('sha256').update(stableStringify(value ?? null)).digest('hex');
}

function normalizeProgress(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function isTerminalStatus(status: QueueJobStatus): boolean {
  return TERMINAL_JOB_STATUSES.has(status);
}

function parsePersistedJob(raw: QueueJobRecord): QueueJobRecord {
  return {
    ...raw,
    status: raw.status,
    stage: raw.stage,
    progress_pct: normalizeProgress(raw.progress_pct),
    accepted_at_ms: Number(raw.accepted_at_ms) || Date.now(),
    cancel_requested: Boolean(raw.cancel_requested),
  };
}

export class RunQueueService {
  private readonly outDir: string;

  private readonly queueDir: string;

  private readonly dbPath: string;

  private readonly legacyStatePath: string;

  private executor: RunExecutor;

  private readonly now: () => number;

  private readonly idempotencyWindowMs: number;

  private readonly jobs = new Map<string, QueueJobRecord>();

  private readonly queue: string[] = [];

  private activeJobId: string | null = null;

  private processing = false;

  private drainTimer: NodeJS.Timeout | null = null;

  private readonly events = new EventEmitter();

  constructor(options: RunQueueServiceOptions) {
    this.outDir = path.resolve(options.outDir);
    this.queueDir = path.resolve(this.outDir, RUN_QUEUE_DIR);
    this.dbPath = path.resolve(this.queueDir, QUEUE_DB_FILENAME);
    this.legacyStatePath = path.resolve(this.queueDir, LEGACY_QUEUE_STATE_FILENAME);
    if (options.executor) {
      this.executor = options.executor;
    } else if (options.runner) {
      this.executor = createRunExecutor(options.runner);
    } else {
      throw new RunnerError('RunQueueService requires executor or runner', 500);
    }
    this.now = options.now ?? Date.now;
    this.idempotencyWindowMs = options.idempotencyWindowMs ?? DEFAULT_IDEMPOTENCY_WINDOW_MS;
    this.loadState();
    this.scheduleDrain(0);
  }

  setExecutor(executor: RunExecutor): void {
    this.executor = executor;
    this.scheduleDrain(0);
  }

  setRunner(runner: Runner): void {
    this.setExecutor(createRunExecutor(runner));
  }

  subscribe(jobId: string, listener: (event: QueueJobEvent) => void): () => void {
    const handler = (event: QueueJobEvent) => {
      if (event.job_id === jobId) {
        listener(event);
      }
    };
    this.events.on('job_event', handler);
    return () => {
      this.events.off('job_event', handler);
    };
  }

  listJobs(): QueueJob[] {
    return [...this.jobs.values()]
      .sort((a, b) => b.accepted_at_ms - a.accepted_at_ms)
      .map((job) => this.toPublicJob(job));
  }

  listNonTerminalRuns(): ApiRun[] {
    return this.listJobs()
      .filter((job) => job.status !== 'success')
      .map((job) => this.toApiRun(job));
  }

  getJob(jobId: string): QueueJob {
    const job = this.jobs.get(jobId);
    if (!job) {
      throw new RunnerError(`Job ${jobId} not found`, 404);
    }
    return this.toPublicJob(job);
  }

  submitRun(params: RunParams, options: SubmitRunOptions = {}): QueueJob {
    const acceptedAtMs = this.now();
    const acceptedAt = new Date(acceptedAtMs).toISOString();
    const requestHash = hashPayload(options.requestBody ?? { params });
    const idempotencyKey = options.idempotencyKey?.trim() || undefined;

    if (idempotencyKey) {
      this.pruneIdempotency();
      const prior = [...this.jobs.values()]
        .filter((job) => job.idempotency_key === idempotencyKey)
        .sort((a, b) => b.accepted_at_ms - a.accepted_at_ms)[0];
      if (prior) {
        if (prior.request_hash !== requestHash) {
          throw new RunnerError('Idempotency-Key replay must use an identical request body', 409);
        }
        return this.toPublicJob(prior);
      }
    }

    const jobId = randomUUID();
    const record: QueueJobRecord = {
      job_id: jobId,
      case_id: params.case_id,
      params,
      status: 'queued',
      stage: 'queued',
      progress_pct: 0,
      accepted_at: acceptedAt,
      accepted_at_ms: acceptedAtMs,
      request_hash: requestHash,
      idempotency_key: idempotencyKey,
      cancel_requested: false,
      message: 'Queued',
    };
    this.jobs.set(jobId, record);
    this.queue.push(jobId);
    this.persistState();
    this.writeJobState(record);
    this.emitJobEvent(record, 'progress');
    this.scheduleDrain(0);
    return this.toPublicJob(record);
  }

  cancelJob(jobId: string, reason = 'user'): QueueJob {
    const job = this.jobs.get(jobId);
    if (!job) {
      throw new RunnerError(`Job ${jobId} not found`, 404);
    }
    if (isTerminalStatus(job.status)) {
      throw new RunnerError(`Job ${jobId} is already ${job.status}`, 409);
    }

    if (job.status === 'queued') {
      job.status = 'cancelled';
      job.stage = 'cancelled';
      job.cancel_reason = reason;
      job.completed_at = new Date(this.now()).toISOString();
      job.duration_ms = 0;
      job.message = `Cancelled (${reason})`;
      this.removeFromQueue(job.job_id);
      this.persistState();
      this.writeJobState(job);
      this.emitJobEvent(job, 'terminal');
      return this.toPublicJob(job);
    }

    job.cancel_requested = true;
    job.cancel_reason = reason;
    job.message = 'Cancellation requested';
    try {
      this.executor.cancelRun(job.case_id);
    } catch {
      // Best effort cancellation for in-flight subprocess.
    }
    this.persistState();
    this.writeJobState(job);
    this.emitJobEvent(job, 'progress');
    return this.toPublicJob(job);
  }

  cancelCase(caseId: string, reason = 'user'): QueueJob | null {
    const candidate = [...this.jobs.values()]
      .filter((job) => job.case_id === caseId && !isTerminalStatus(job.status))
      .sort((a, b) => b.accepted_at_ms - a.accepted_at_ms)[0];
    if (!candidate) return null;
    return this.cancelJob(candidate.job_id, reason);
  }

  private loadState(): void {
    const parsed = this.readStateFromSqlite() ?? this.readLegacyState();
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.jobs)) {
      return;
    }

    for (const job of parsed.jobs) {
      const normalized = parsePersistedJob(job);
      if (normalized.status === 'running') {
        normalized.status = 'failed';
        normalized.stage = 'failed';
        normalized.completed_at = new Date(this.now()).toISOString();
        normalized.duration_ms = normalized.started_at
          ? Math.max(0, this.now() - new Date(normalized.started_at).getTime())
          : 0;
        normalized.message = 'Recovered after restart while running';
      }
      this.jobs.set(normalized.job_id, normalized);
    }

    const queueIds = Array.isArray(parsed.queue) ? parsed.queue : [];
    for (const jobId of queueIds) {
      const job = this.jobs.get(jobId);
      if (!job || job.status !== 'queued') continue;
      this.queue.push(jobId);
    }

    this.activeJobId = null;
    this.persistState();
  }

  private readStateFromSqlite(): PersistedQueueState | null {
    const result = spawnSync(this.resolvePythonExe(), ['-c', SQLITE_READ_STATE_SCRIPT, this.dbPath], {
      encoding: 'utf-8',
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      return null;
    }
    const raw = result.stdout.trim();
    if (!raw) return null;
    try {
      return JSON.parse(raw) as PersistedQueueState;
    } catch {
      return null;
    }
  }

  private readLegacyState(): PersistedQueueState | null {
    const result = spawnSync(this.resolvePythonExe(), ['-c', LEGACY_READ_STATE_SCRIPT, this.legacyStatePath], {
      encoding: 'utf-8',
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      return null;
    }
    const raw = result.stdout.trim();
    if (!raw) return null;
    try {
      return JSON.parse(raw) as PersistedQueueState;
    } catch {
      return null;
    }
  }

  private resolvePythonExe(): string {
    const configured = process.env.TRIAGE_PYTHON_EXE?.trim();
    if (configured) return configured;
    return 'python';
  }

  private writeStateToSqlite(state: PersistedQueueState): boolean {
    const result = spawnSync(this.resolvePythonExe(), ['-c', SQLITE_WRITE_STATE_SCRIPT, this.dbPath], {
      input: JSON.stringify(state),
      encoding: 'utf-8',
      windowsHide: true,
    });
    return !result.error && result.status === 0;
  }

  private persistState(): void {
    fs.mkdirSync(this.queueDir, { recursive: true });
    const state: PersistedQueueState = {
      version: 1,
      active_job_id: this.activeJobId,
      queue: [...this.queue],
      jobs: [...this.jobs.values()],
    };
    const sqlitePersisted = this.writeStateToSqlite(state);
    if (!sqlitePersisted) {
      writeJsonAtomic(this.legacyStatePath, state);
      return;
    }
    if (fs.existsSync(this.legacyStatePath)) {
      fs.rmSync(this.legacyStatePath, { force: true });
    }
  }

  private writeJobState(job: QueueJobRecord): void {
    const caseDir = path.resolve(this.outDir, job.case_id);
    const targetPath = fs.existsSync(caseDir)
      ? path.resolve(caseDir, JOB_STATE_FILENAME)
      : path.resolve(this.queueDir, 'jobs', `${job.case_id}.job_state.json`);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    const payload = {
      job_id: job.job_id,
      case_id: job.case_id,
      status: job.status,
      stage: job.stage,
      progress_pct: job.progress_pct,
      accepted_at: job.accepted_at,
      started_at: job.started_at ?? null,
      completed_at: job.completed_at ?? null,
      duration_ms: job.duration_ms ?? null,
      message: job.message ?? null,
      cancel_reason: job.cancel_reason ?? null,
    };
    writeJsonAtomic(targetPath, payload);
  }

  private emitJobEvent(job: QueueJobRecord, event: QueueJobEvent['event']): void {
    const payload: QueueJobEvent = {
      event,
      job_id: job.job_id,
      case_id: job.case_id,
      stage: job.stage,
      progress_pct: job.progress_pct,
      status: job.status,
      ts: new Date(this.now()).toISOString(),
      ...(job.message ? { message: job.message } : {}),
      ...(job.cancel_reason ? { cancel_reason: job.cancel_reason } : {}),
    };
    this.events.emit('job_event', payload);
  }

  private toPublicJob(job: QueueJobRecord): QueueJob {
    return {
      job_id: job.job_id,
      case_id: job.case_id,
      params: job.params,
      status: job.status,
      stage: job.stage,
      progress_pct: job.progress_pct,
      accepted_at: job.accepted_at,
      ...(job.started_at ? { started_at: job.started_at } : {}),
      ...(job.completed_at ? { completed_at: job.completed_at } : {}),
      ...(typeof job.duration_ms === 'number' ? { duration_ms: job.duration_ms } : {}),
      ...(job.message ? { message: job.message } : {}),
      ...(job.cancel_reason ? { cancel_reason: job.cancel_reason } : {}),
    };
  }

  private toApiRun(job: QueueJob): ApiRun {
    const status: ApiRun['status'] = job.status === 'queued' ? 'pending' : job.status;
    const error = status === 'failed' && job.message ? job.message : undefined;
    return {
      id: job.case_id,
      params: job.params,
      status,
      started_at: job.started_at ?? job.accepted_at,
      ...(job.completed_at ? { completed_at: job.completed_at } : {}),
      ...(typeof job.duration_ms === 'number' ? { duration_ms: job.duration_ms } : {}),
      progress_pct: job.progress_pct,
      job_id: job.job_id,
      queued_at: job.accepted_at,
      ...(job.cancel_reason ? { cancel_reason: job.cancel_reason } : {}),
      ...(error ? { error } : {}),
    };
  }

  private scheduleDrain(delayMs: number): void {
    if (this.drainTimer) return;
    this.drainTimer = setTimeout(() => {
      this.drainTimer = null;
      void this.drainQueue();
    }, Math.max(0, delayMs));
    if (typeof this.drainTimer.unref === 'function') {
      this.drainTimer.unref();
    }
  }

  private async drainQueue(): Promise<void> {
    if (this.processing) return;
    this.processing = true;
    try {
      while (this.queue.length > 0) {
        if (this.executor.getActiveCaseId()) {
          this.scheduleDrain(ACTIVE_RUN_RETRY_MS);
          return;
        }

        const nextJobId = this.queue.shift();
        if (!nextJobId) continue;
        const job = this.jobs.get(nextJobId);
        if (!job || job.status !== 'queued') {
          this.persistState();
          continue;
        }

        this.activeJobId = nextJobId;
        job.status = 'running';
        job.stage = 'running';
        job.progress_pct = 10;
        job.started_at = new Date(this.now()).toISOString();
        job.message = 'Running';
        this.persistState();
        this.writeJobState(job);
        this.emitJobEvent(job, 'progress');

        try {
          await this.executor.startRun(job.params);
          job.status = 'success';
          job.stage = 'completed';
          job.progress_pct = 100;
          job.completed_at = new Date(this.now()).toISOString();
          job.duration_ms = Math.max(0, this.now() - new Date(job.started_at).getTime());
          job.message = 'Completed successfully';
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          const looksCancelled = job.cancel_requested
            || /cancelled/i.test(message)
            || /cancellation/i.test(message);
          if (looksCancelled) {
            job.status = 'cancelled';
            job.stage = 'cancelled';
            job.progress_pct = Math.max(0, job.progress_pct);
            job.message = message || 'Cancelled';
            job.completed_at = new Date(this.now()).toISOString();
            job.duration_ms = job.started_at
              ? Math.max(0, this.now() - new Date(job.started_at).getTime())
              : 0;
          } else {
            job.status = 'failed';
            job.stage = 'failed';
            job.progress_pct = Math.max(0, job.progress_pct);
            job.message = message || 'Job failed';
            job.completed_at = new Date(this.now()).toISOString();
            job.duration_ms = job.started_at
              ? Math.max(0, this.now() - new Date(job.started_at).getTime())
              : 0;
          }
        } finally {
          this.activeJobId = null;
          this.persistState();
          this.writeJobState(job);
          this.emitJobEvent(job, isTerminalStatus(job.status) ? 'terminal' : 'progress');
        }
      }
    } finally {
      this.processing = false;
    }
  }

  private removeFromQueue(jobId: string): void {
    const index = this.queue.indexOf(jobId);
    if (index >= 0) {
      this.queue.splice(index, 1);
    }
  }

  private pruneIdempotency(): void {
    const thresholdMs = this.now() - this.idempotencyWindowMs;
    for (const job of this.jobs.values()) {
      if (!job.idempotency_key) continue;
      if (job.accepted_at_ms >= thresholdMs) continue;
      job.idempotency_key = undefined;
      this.jobs.set(job.job_id, job);
    }
    this.persistState();
  }
}
