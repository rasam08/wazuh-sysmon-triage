import { spawn, type SpawnOptionsWithoutStdio } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { RunParams } from './validators';

export class RunnerError extends Error {
  readonly status: number;

  constructor(message: string, status = 500) {
    super(message);
    this.name = 'RunnerError';
    this.status = status;
  }
}

export interface ApiRunPreview {
  params: RunParams;
  cli_args: string[];
  command: string;
  warnings: string[];
}

export interface RunExecutionResult {
  case_id: string;
  case_dir: string;
  log_path: string;
  exit_code: number | null;
  stdout_tail: string;
  stderr_tail: string;
  cancelled: boolean;
  cancel_reason: 'user' | 'timeout' | null;
}

export interface CancelRunResult {
  cancelled: boolean;
  case_id: string;
  reason: 'user';
}

export interface SpawnedProcess {
  stdout: NodeJS.ReadableStream;
  stderr: NodeJS.ReadableStream;
  kill?: (signal?: NodeJS.Signals | number) => boolean;
  on(event: string, listener: (...args: unknown[]) => void): this;
}

type SpawnProcess = (
  command: string,
  args: string[],
  options: SpawnOptionsWithoutStdio,
) => SpawnedProcess;

interface RunnerOptions {
  rootDir: string;
  configPath?: string;
  spawnProcess?: SpawnProcess;
  resolvePythonExe?: () => string;
  runTimeoutMs?: number;
}

export interface Runner {
  previewRun: (params: RunParams) => ApiRunPreview;
  startRun: (params: RunParams) => Promise<RunExecutionResult>;
  cancelRun: (caseId: string) => CancelRunResult;
  isCaseActive: (caseId: string) => boolean;
  getActiveCaseId: () => string | null;
}

const STDIO_TAIL_LIMIT = 64 * 1024;
const DEFAULT_RUN_TIMEOUT_MS = 15 * 60 * 1000;
const KILL_GRACE_PERIOD_MS = 5000;

function shellQuote(arg: string): string {
  if (/^[a-zA-Z0-9_./:-]+$/.test(arg)) return arg;
  return `"${arg.replace(/"/g, '\\"')}"`;
}

function datetimeLocalToIso(value?: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().replace('.000', '');
}

function appendTail(current: string, chunk: string): string {
  if (!chunk) return current;
  const combined = current + chunk;
  if (combined.length <= STDIO_TAIL_LIMIT) return combined;
  return combined.slice(combined.length - STDIO_TAIL_LIMIT);
}

function parseRunTimeoutMs(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1000) {
    return fallback;
  }
  return Math.round(parsed);
}

function resolvePythonExe(rootDir: string): string {
  const candidates = [
    path.resolve(rootDir, '.venv', 'Scripts', 'python.exe'),
    path.resolve(rootDir, '.venv-5', 'Scripts', 'python.exe'),
    path.resolve(rootDir, '.venv-2', 'Scripts', 'python.exe'),
    path.resolve(rootDir, '.venv-1', 'Scripts', 'python.exe'),
    'python',
  ];
  for (const candidate of candidates) {
    if (candidate === 'python' || fs.existsSync(candidate)) return candidate;
  }
  return 'python';
}

function buildCliArgs(params: RunParams, configPath: string): string[] {
  const args = ['-m', 'wazuh_sysmon_triage', params.mode];
  if (fs.existsSync(configPath)) {
    args.push('--config', configPath);
  }
  args.push('--profile', params.profile);
  args.push('--case-id', params.case_id);
  args.push('--out-dir', params.out_dir);
  args.push('--min-alert-score', String(params.min_alert_score));
  args.push(params.print_stats ? '--print-stats' : '--no-print-stats');
  args.push(params.alerts_only ? '--alerts-only' : '--no-alerts-only');
  args.push(params.include_dev_queue ? '--include-dev-queue' : '--no-include-dev-queue');
  for (const queue of params.queues) {
    args.push('--queue', queue);
  }
  for (const image of params.allowlist_images ?? []) {
    args.push('--allowlist-image', image);
  }

  if (params.mode === 'offline') {
    args.push('--input-ndjson', params.input_file || 'samples/scenario_gym/encoded_powershell.ndjson');
  } else {
    if (params.verify_tls === true) {
      args.push('--verify-tls');
    } else if (params.verify_tls === false) {
      args.push('--no-verify-tls');
    }
    if (params.time_preset === 'today') {
      args.push('--today');
    } else if (params.time_preset === 'yesterday') {
      args.push('--yesterday');
    } else if (params.time_preset === 'custom') {
      const start = datetimeLocalToIso(params.start);
      const end = datetimeLocalToIso(params.end);
      if (start && end) {
        args.push('--start', start, '--end', end);
      } else {
        args.push('--last', '2h');
      }
    } else {
      args.push('--last', params.time_preset);
    }

    if (params.agent_name) args.push('--agent-name', params.agent_name);
    if (params.agent_id) args.push('--agent-id', params.agent_id);
  }

  return args;
}

export function createRunner(options: RunnerOptions): Runner {
  const rootDir = path.resolve(options.rootDir);
  const configPath = options.configPath ?? path.resolve(rootDir, 'config.local.yaml');
  const defaultSpawn: SpawnProcess = (command, args, spawnOptions) => (
    spawn(command, args, spawnOptions) as unknown as SpawnedProcess
  );
  const spawnProcess = options.spawnProcess ?? defaultSpawn;
  const getPythonExe = options.resolvePythonExe ?? (() => resolvePythonExe(rootDir));
  const runTimeoutMs = options.runTimeoutMs ?? parseRunTimeoutMs(
    process.env.TRIAGE_RUN_TIMEOUT_MS,
    DEFAULT_RUN_TIMEOUT_MS,
  );

  type CancelReason = 'user' | 'timeout';
  interface ActiveRunState {
    caseId: string;
    cancelReason: CancelReason | null;
    requestCancel: (reason: CancelReason) => boolean;
  }
  let activeRun: ActiveRunState | null = null;

  const previewRun = (params: RunParams): ApiRunPreview => {
    const pythonExe = getPythonExe();
    const cliArgs = buildCliArgs(params, configPath);
    const warnings: string[] = [];

    if (params.mode === 'offline' && !params.input_file) {
      warnings.push('Offline mode selected without input file; default sample path will be used.');
    }
    if (params.time_preset === 'custom' && (!params.start || !params.end)) {
      warnings.push('Custom time preset requires start and end; fallback --last 2h will be used.');
    }
    if (params.mode === 'live' && params.verify_tls === undefined) {
      warnings.push('TLS mode is auto; CLI will resolve verify_tls from env/profile settings.');
    }
    if (!params.queues.length) {
      warnings.push('No queues selected; default queue behavior may apply.');
    }
    if (params.dry_run) {
      warnings.push('dry_run is preview-only; no run will be executed from /api/runs.');
    }
    return {
      params,
      cli_args: cliArgs,
      command: `${shellQuote(pythonExe)} ${cliArgs.map(shellQuote).join(' ')}`,
      warnings,
    };
  };

  const startRun = async (params: RunParams): Promise<RunExecutionResult> => {
    if (params.dry_run) {
      throw new RunnerError('dry_run is preview-only; use /api/runs/preview', 400);
    }
    if (activeRun) {
      throw new RunnerError('run already in progress', 409);
    }

    const outDir = path.resolve(params.out_dir);
    const caseDir = path.resolve(outDir, params.case_id);
    const allowOverwrite = Boolean(params.allow_overwrite || params.force);
    if (fs.existsSync(caseDir) && !allowOverwrite) {
      throw new RunnerError(
        `Case ${params.case_id} already exists; set allow_overwrite=true (or force=true) to overwrite`,
        409,
      );
    }

    fs.mkdirSync(outDir, { recursive: true });
    const tempRunDir = path.resolve(outDir, '.tmp-runs', `${params.case_id}-${Date.now()}`);
    const logDir = fs.existsSync(caseDir) ? caseDir : tempRunDir;
    fs.mkdirSync(logDir, { recursive: true });
    const logPath = path.resolve(logDir, 'middleware-run.log');
    const logStream = fs.createWriteStream(logPath, { flags: 'a' });

    const pythonExe = getPythonExe();
    const cliArgs = buildCliArgs(params, configPath);
    const runState: ActiveRunState = {
      caseId: params.case_id,
      cancelReason: null,
      requestCancel: () => false,
    };
    activeRun = runState;
    try {
      const result = await new Promise<RunExecutionResult>((resolve, reject) => {
        let stdoutTail = '';
        let stderrTail = '';
        let child: SpawnedProcess | null = null;
        let timeoutHandle: NodeJS.Timeout | null = null;
        let forceKillHandle: NodeJS.Timeout | null = null;

        const cleanupTimers = () => {
          if (timeoutHandle) {
            clearTimeout(timeoutHandle);
            timeoutHandle = null;
          }
          if (forceKillHandle) {
            clearTimeout(forceKillHandle);
            forceKillHandle = null;
          }
        };

        const terminateChild = () => {
          if (!child || typeof child.kill !== 'function') return;
          try {
            child.kill('SIGTERM');
          } catch {
            return;
          }
          forceKillHandle = setTimeout(() => {
            if (!child || typeof child.kill !== 'function') return;
            try {
              child.kill('SIGKILL');
            } catch {
              // Best effort only.
            }
          }, KILL_GRACE_PERIOD_MS);
          if (typeof forceKillHandle.unref === 'function') {
            forceKillHandle.unref();
          }
        };

        runState.requestCancel = (reason: CancelReason) => {
          if (runState.cancelReason) return false;
          runState.cancelReason = reason;
          terminateChild();
          return true;
        };

        child = spawnProcess(pythonExe, cliArgs, {
          cwd: rootDir,
          env: { ...process.env, PYTHONPATH: path.resolve(rootDir, 'src') },
          windowsHide: true,
        });

        if (runTimeoutMs > 0) {
          timeoutHandle = setTimeout(() => {
            runState.requestCancel('timeout');
          }, runTimeoutMs);
          if (typeof timeoutHandle.unref === 'function') {
            timeoutHandle.unref();
          }
        }
        if (runState.cancelReason) {
          terminateChild();
        }

        (child.stdout as NodeJS.ReadableStream).on('data', (chunk: Buffer | string) => {
          const text = chunk.toString();
          stdoutTail = appendTail(stdoutTail, text);
          logStream.write(`[${new Date().toISOString()}] [stdout] ${text}`);
        });

        (child.stderr as NodeJS.ReadableStream).on('data', (chunk: Buffer | string) => {
          const text = chunk.toString();
          stderrTail = appendTail(stderrTail, text);
          logStream.write(`[${new Date().toISOString()}] [stderr] ${text}`);
        });

        child.on('error', (error: unknown) => {
          cleanupTimers();
          const message = error instanceof Error ? error.message : String(error);
          reject(new RunnerError(`Failed to start run: ${message}`));
        });

        child.on('close', (code: unknown) => {
          cleanupTimers();
          resolve({
            case_id: params.case_id,
            case_dir: caseDir,
            log_path: logPath,
            exit_code: typeof code === 'number' || code === null ? code : null,
            stdout_tail: stdoutTail,
            stderr_tail: stderrTail,
            cancelled: runState.cancelReason !== null,
            cancel_reason: runState.cancelReason,
          });
        });
      });

      if (logDir !== caseDir && fs.existsSync(caseDir)) {
        const caseLogPath = path.resolve(caseDir, path.basename(logPath));
        fs.copyFileSync(logPath, caseLogPath);
      }

      if (result.cancelled) {
        if (result.cancel_reason === 'timeout') {
          const timeoutSeconds = Math.ceil(runTimeoutMs / 1000);
          throw new RunnerError(`Run timed out after ${timeoutSeconds} seconds`, 408);
        }
        throw new RunnerError(`Run ${params.case_id} cancelled`, 409);
      }
      if (result.exit_code !== 0) {
        throw new RunnerError(result.stderr_tail || result.stdout_tail || 'Run failed');
      }
      return result;
    } finally {
      logStream.end();
      if (activeRun === runState) {
        activeRun = null;
      }
    }
  };

  const cancelRun = (caseId: string): CancelRunResult => {
    const active = activeRun;
    if (!active) {
      throw new RunnerError('No active run to cancel', 409);
    }
    if (active.caseId !== caseId) {
      throw new RunnerError(`Case ${caseId} is not active; active case is ${active.caseId}`, 409);
    }
    if (active.cancelReason) {
      throw new RunnerError(`Cancellation already requested for case ${caseId}`, 409);
    }
    active.requestCancel('user');
    return { cancelled: true, case_id: caseId, reason: 'user' };
  };

  const isCaseActive = (caseId: string): boolean => (
    Boolean(activeRun && activeRun.caseId === caseId)
  );

  const getActiveCaseId = (): string | null => activeRun?.caseId ?? null;

  return {
    previewRun,
    startRun,
    cancelRun,
    isCaseActive,
    getActiveCaseId,
  };
}
