import type {
  Alert,
  AlertBundle,
  Case,
  HealthStatus,
  Run,
  RunParams,
} from '@/types';

export interface RunPreview {
  params: RunParams;
  cli_args: string[];
  command: string;
  warnings: string[];
}

export interface RunJob {
  job_id: string;
  case_id: string;
  params: RunParams;
  status: 'queued' | 'running' | 'success' | 'failed' | 'cancelled';
  stage: string;
  progress_pct: number;
  accepted_at: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  message?: string;
  cancel_reason?: string;
}

interface AsyncRunSubmitResponse {
  job_id: string;
  case_id: string;
  accepted_at: string;
}

export type RunSubmitResult =
  | {
    execution_mode: 'async';
    job_id: string;
    case_id: string;
    accepted_at: string;
  }
  | {
    execution_mode: 'sync';
    case_id: string;
    run: Run;
  };

interface RunJobEvent {
  event: 'progress' | 'terminal';
  job_id: string;
  case_id: string;
  stage: string;
  progress_pct: number;
  status: 'queued' | 'running' | 'success' | 'failed' | 'cancelled';
  ts: string;
  message?: string;
  cancel_reason?: string;
}

class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// UI client always targets the local middleware API mounted at /api.
// Settings store endpoint fields are informational and do not alter these routes.
const LOCAL_API_BASE = '/api';

function apiPath(pathname: string): string {
  return `${LOCAL_API_BASE}${pathname}`;
}

async function requestJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
  const requestInit = mutating
    ? (() => {
      const headers = new Headers(init?.headers);
      if (!headers.has('X-Requested-With')) {
        headers.set('X-Requested-With', 'XMLHttpRequest');
      }
      return {
        ...init,
        headers,
      } as RequestInit;
    })()
    : init;
  const response = await fetch(input, requestInit);
  const raw = await response.text();
  let payload: unknown;
  try {
    payload = raw ? JSON.parse(raw) : {};
  } catch {
    if (!response.ok) {
      throw new ApiError(response.status, `Request failed (${response.status})`);
    }
    throw new ApiError(response.status, 'Invalid JSON in response');
  }
  if (!response.ok) {
    const message = typeof (payload as Record<string, unknown>)?.error === 'string'
      ? (payload as Record<string, string>).error
      : `Request failed (${response.status})`;
    throw new ApiError(response.status, message);
  }
  return payload as T;
}

function isNotFound(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

function isAsyncSubmitRouteUnavailable(err: unknown): boolean {
  if (!(err instanceof ApiError) || err.status !== 404) return false;
  const normalized = err.message.toLowerCase();
  return normalized.includes('/api/runs/submit') || normalized.includes('async runs disabled');
}

export async function fetchRuns(): Promise<Run[]> {
  const payload = await requestJson<{ runs: Run[] }>(apiPath('/runs'));
  return payload.runs;
}

export async function startRun(params: RunParams, init?: RequestInit): Promise<Run> {
  const payload = await requestJson<{ run: Run }>(apiPath('/runs'), {
    ...init,
    method: 'POST',
    headers: {
      ...(init?.headers ?? {}),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ params }),
  });
  return payload.run;
}

export async function submitRun(params: RunParams, init?: RequestInit): Promise<RunSubmitResult> {
  try {
    const payload = await requestJson<AsyncRunSubmitResponse>(apiPath('/runs/submit'), {
      ...init,
      method: 'POST',
      headers: {
        ...(init?.headers ?? {}),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ params }),
    });
    return {
      execution_mode: 'async',
      ...payload,
    };
  } catch (error) {
    if (!isAsyncSubmitRouteUnavailable(error)) {
      throw error;
    }
    const run = await startRun(params, init);
    return {
      execution_mode: 'sync',
      case_id: run.id,
      run,
    };
  }
}

export async function fetchJobStatus(jobId: string): Promise<RunJob> {
  const payload = await requestJson<{ job: RunJob }>(apiPath(`/runs/jobs/${encodeURIComponent(jobId)}`));
  return payload.job;
}

export async function cancelJob(jobId: string): Promise<RunJob> {
  const payload = await requestJson<{ cancelled: boolean; job: RunJob }>(
    apiPath(`/runs/jobs/${encodeURIComponent(jobId)}/cancel`),
    { method: 'POST' },
  );
  return payload.job;
}

export function subscribeRunProgress(
  jobId: string,
  onEvent: (event: RunJobEvent) => void,
  onError?: (error: unknown) => void,
): () => void {
  if (typeof EventSource === 'undefined') {
    return () => undefined;
  }
  const source = new EventSource(apiPath(`/runs/jobs/${encodeURIComponent(jobId)}/stream`));
  const handleMessage = (event: MessageEvent) => {
    try {
      const payload = JSON.parse(event.data) as RunJobEvent;
      onEvent(payload);
    } catch (error) {
      onError?.(error);
    }
  };
  source.addEventListener('progress', handleMessage as EventListener);
  source.addEventListener('terminal', handleMessage as EventListener);
  source.onerror = (error) => {
    onError?.(error);
  };
  return () => {
    source.close();
  };
}

export async function cancelRun(caseId: string): Promise<void> {
  await requestJson<{ cancelled: boolean; case_id: string; reason: string }>(
    apiPath(`/runs/${encodeURIComponent(caseId)}/cancel`),
    {
      method: 'POST',
    },
  );
}

export async function fetchRunPreview(params: RunParams): Promise<RunPreview> {
  const payload = await requestJson<{ preview: RunPreview }>(apiPath('/runs/preview'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ params }),
  });
  return payload.preview;
}

export async function fetchCase(caseId: string): Promise<Case | undefined> {
  try {
    const payload = await requestJson<{ case: Case }>(apiPath(`/cases/${encodeURIComponent(caseId)}`));
    return payload.case;
  } catch (err) {
    if (isNotFound(err)) return undefined;
    throw err;
  }
}

export async function deleteCase(caseId: string): Promise<void> {
  await requestJson<{ deleted: boolean; case_id: string }>(apiPath(`/cases/${encodeURIComponent(caseId)}`), {
    method: 'DELETE',
  });
}

export async function fetchAlerts(caseId?: string, init?: RequestInit): Promise<{ alerts: Alert[]; case_id: string | null }> {
  const q = caseId ? `?case=${encodeURIComponent(caseId)}` : '';
  return requestJson<{ alerts: Alert[]; case_id: string | null }>(`${apiPath('/alerts')}${q}`, init);
}

export async function fetchAlertBundle(alertId: string, caseId: string): Promise<AlertBundle | undefined> {
  try {
    const payload = await requestJson<{ bundle: AlertBundle }>(
      `${apiPath(`/alerts/${encodeURIComponent(alertId)}/bundle`)}?case=${encodeURIComponent(caseId)}`,
    );
    return payload.bundle;
  } catch (err) {
    if (isNotFound(err)) return undefined;
    throw err;
  }
}

export async function fetchReport(caseId: string): Promise<string> {
  const payload = await requestJson<{ report: string }>(`${apiPath('/report')}?case=${encodeURIComponent(caseId)}`);
  return payload.report;
}

export async function fetchHealth(profile: 'soc' | 'dev' | 'lab' = 'soc'): Promise<HealthStatus> {
  const payload = await requestJson<{ health: HealthStatus }>(
    `${apiPath('/health')}?profile=${encodeURIComponent(profile)}`,
  );
  return payload.health;
}
