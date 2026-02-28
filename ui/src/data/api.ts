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
  const response = await fetch(input, init);
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

export async function fetchRuns(): Promise<Run[]> {
  const payload = await requestJson<{ runs: Run[] }>(apiPath('/runs'));
  return payload.runs;
}

export async function fetchRun(id: string): Promise<Run | undefined> {
  const runs = await fetchRuns();
  return runs.find((run) => run.id === id);
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
