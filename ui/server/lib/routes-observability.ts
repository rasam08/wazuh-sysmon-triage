import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { RunQueueService } from './run-queue-service';
import { normalizeApiPath, type RateLimitBucket } from './routes-common';

interface RequestLogLine {
  ts: string;
  event: 'api_request';
  request_id: string;
  client_key: string;
  method: string;
  route: string;
  path: string;
  status: number;
  duration_ms: number;
  rate_limited: boolean;
}

interface ApiRouteMetric {
  count: number;
  error_count: number;
  duration_total_ms: number;
  duration_max_ms: number;
}

interface ApiMetricsState {
  started_at_ms: number;
  total_requests: number;
  total_errors: number;
  rate_limited_requests: number;
  run_submissions_total: number;
  run_submit_errors_total: number;
  run_cancellations_total: number;
  health_requests_total: number;
}

const routeMetrics = new Map<string, ApiRouteMetric>();
const metricsState: ApiMetricsState = {
  started_at_ms: Date.now(),
  total_requests: 0,
  total_errors: 0,
  rate_limited_requests: 0,
  run_submissions_total: 0,
  run_submit_errors_total: 0,
  run_cancellations_total: 0,
  health_requests_total: 0,
};

export function resolveRequestId(req: IncomingMessage): string {
  const incoming = req.headers['x-request-id'];
  const headerValue = Array.isArray(incoming) ? incoming[0] : incoming;
  if (typeof headerValue === 'string' && headerValue.trim().length > 0) {
    return headerValue.trim();
  }
  return randomUUID();
}

export function sanitizeClientKey(value: string | undefined): string {
  const trimmed = (value ?? '').trim();
  if (!trimmed) return 'unknown';
  return trimmed.slice(0, 128).replace(/[^a-zA-Z0-9:._-]/g, '?');
}

export function resolveDefaultClientKey(req: IncomingMessage): string {
  const forwardedFor = req.headers['x-forwarded-for'];
  const headerValue = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
  if (typeof headerValue === 'string' && headerValue.trim().length > 0) {
    const first = headerValue.split(',')[0]?.trim();
    return sanitizeClientKey(first);
  }
  const remoteAddress = req.socket?.remoteAddress;
  if (typeof remoteAddress === 'string' && remoteAddress.trim().length > 0) {
    return sanitizeClientKey(remoteAddress);
  }
  return 'unknown';
}

export function normalizeRouteKey(pathname: string): string {
  if (pathname === '/metrics' || pathname === '/api/metrics') return '/metrics';
  const route = normalizeApiPath(pathname);
  if (!route) return pathname;
  if (route === '/api/runs/submit') return '/api/runs/submit';
  if (route.startsWith('/api/runs/jobs/') && route.endsWith('/cancel')) {
    return '/api/runs/jobs/:jobId/cancel';
  }
  if (route.startsWith('/api/runs/jobs/') && route.endsWith('/stream')) {
    return '/api/runs/jobs/:jobId/stream';
  }
  if (route.startsWith('/api/runs/jobs/')) return '/api/runs/jobs/:jobId';
  if (route.startsWith('/api/runs/') && route.endsWith('/cancel')) {
    return '/api/runs/:caseId/cancel';
  }
  if (route.startsWith('/api/cases/')) return '/api/cases/:caseId';
  if (route.startsWith('/api/alerts/') && route.endsWith('/bundle')) {
    return '/api/alerts/:alertId/bundle';
  }
  return route;
}

function sanitizePrometheusLabel(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

export function recordRequestMetrics(
  routeKey: string,
  method: string,
  status: number,
  durationMs: number,
  rateLimited: boolean,
): void {
  metricsState.total_requests += 1;
  if (status >= 400) {
    metricsState.total_errors += 1;
  }
  if (rateLimited) {
    metricsState.rate_limited_requests += 1;
  }
  if (routeKey === '/api/runs/submit') {
    metricsState.run_submissions_total += 1;
    if (status >= 400) {
      metricsState.run_submit_errors_total += 1;
    }
  }
  if (routeKey === '/api/runs/:caseId/cancel' || routeKey === '/api/runs/jobs/:jobId/cancel') {
    if (status < 500) {
      metricsState.run_cancellations_total += 1;
    }
  }
  if (routeKey === '/api/health') {
    metricsState.health_requests_total += 1;
  }

  const key = `${method} ${routeKey}`;
  const existing = routeMetrics.get(key) ?? {
    count: 0,
    error_count: 0,
    duration_total_ms: 0,
    duration_max_ms: 0,
  };
  existing.count += 1;
  if (status >= 400) {
    existing.error_count += 1;
  }
  existing.duration_total_ms += durationMs;
  existing.duration_max_ms = Math.max(existing.duration_max_ms, durationMs);
  routeMetrics.set(key, existing);
}

export function renderMetricsPrometheus(queueService: RunQueueService): string {
  const nowMs = Date.now();
  const uptimeSeconds = Math.max(0, Math.floor((nowMs - metricsState.started_at_ms) / 1000));
  const successRate = metricsState.total_requests > 0
    ? (metricsState.total_requests - metricsState.total_errors) / metricsState.total_requests
    : 1;
  const jobs = queueService.listJobs();
  const queuedCount = jobs.filter((job) => job.status === 'queued').length;
  const runningCount = jobs.filter((job) => job.status === 'running').length;
  const jobsByStatus = new Map<string, number>();
  for (const job of jobs) {
    jobsByStatus.set(job.status, (jobsByStatus.get(job.status) ?? 0) + 1);
  }

  const lines: string[] = [
    '# HELP triage_up Whether the API middleware is running.',
    '# TYPE triage_up gauge',
    'triage_up 1',
    '# HELP triage_uptime_seconds Process uptime in seconds.',
    '# TYPE triage_uptime_seconds gauge',
    `triage_uptime_seconds ${uptimeSeconds}`,
    '# HELP triage_api_requests_total Total API and metrics requests.',
    '# TYPE triage_api_requests_total counter',
    `triage_api_requests_total ${metricsState.total_requests}`,
    '# HELP triage_api_errors_total Total API requests returning 4xx/5xx.',
    '# TYPE triage_api_errors_total counter',
    `triage_api_errors_total ${metricsState.total_errors}`,
    '# HELP triage_api_success_rate_ratio Success ratio across all requests.',
    '# TYPE triage_api_success_rate_ratio gauge',
    `triage_api_success_rate_ratio ${successRate.toFixed(6)}`,
    '# HELP triage_api_rate_limited_total Total rate-limited requests.',
    '# TYPE triage_api_rate_limited_total counter',
    `triage_api_rate_limited_total ${metricsState.rate_limited_requests}`,
    '# HELP triage_run_submissions_total Total async run submissions.',
    '# TYPE triage_run_submissions_total counter',
    `triage_run_submissions_total ${metricsState.run_submissions_total}`,
    '# HELP triage_run_submit_errors_total Failed async run submissions.',
    '# TYPE triage_run_submit_errors_total counter',
    `triage_run_submit_errors_total ${metricsState.run_submit_errors_total}`,
    '# HELP triage_run_cancellations_total Successful run cancellation requests.',
    '# TYPE triage_run_cancellations_total counter',
    `triage_run_cancellations_total ${metricsState.run_cancellations_total}`,
    '# HELP triage_health_requests_total Total health endpoint requests.',
    '# TYPE triage_health_requests_total counter',
    `triage_health_requests_total ${metricsState.health_requests_total}`,
    '# HELP triage_run_queue_depth Current queue depth by state.',
    '# TYPE triage_run_queue_depth gauge',
    `triage_run_queue_depth{state="queued"} ${queuedCount}`,
    `triage_run_queue_depth{state="running"} ${runningCount}`,
    '# HELP triage_run_jobs_total Job count by status.',
    '# TYPE triage_run_jobs_total gauge',
  ];

  const orderedStatuses = ['queued', 'running', 'success', 'failed', 'cancelled'];
  for (const status of orderedStatuses) {
    lines.push(`triage_run_jobs_total{status="${status}"} ${jobsByStatus.get(status) ?? 0}`);
  }

  lines.push('# HELP triage_api_route_requests_total Request totals by normalized route.');
  lines.push('# TYPE triage_api_route_requests_total counter');
  lines.push('# HELP triage_api_route_duration_ms_total Aggregate request duration by route.');
  lines.push('# TYPE triage_api_route_duration_ms_total counter');
  lines.push('# HELP triage_api_route_duration_ms_max Max request duration by route.');
  lines.push('# TYPE triage_api_route_duration_ms_max gauge');
  for (const [key, metric] of [...routeMetrics.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const separator = key.indexOf(' ');
    const method = key.slice(0, separator);
    const route = key.slice(separator + 1);
    const safeMethod = sanitizePrometheusLabel(method);
    const safeRoute = sanitizePrometheusLabel(route);
    lines.push(`triage_api_route_requests_total{method="${safeMethod}",route="${safeRoute}"} ${metric.count}`);
    lines.push(`triage_api_route_duration_ms_total{method="${safeMethod}",route="${safeRoute}"} ${metric.duration_total_ms}`);
    lines.push(`triage_api_route_duration_ms_max{method="${safeMethod}",route="${safeRoute}"} ${metric.duration_max_ms}`);
  }

  lines.push('');
  return lines.join('\n');
}

export function consumeRateLimit(
  buckets: Map<string, RateLimitBucket>,
  key: string,
  nowMs: number,
  maxRequests: number,
  windowMs: number,
): { allowed: boolean; retryAfterSeconds?: number } {
  const bucket = buckets.get(key);
  if (!bucket || nowMs - bucket.windowStartMs >= windowMs) {
    buckets.set(key, { windowStartMs: nowMs, count: 1 });
    return { allowed: true };
  }

  bucket.count += 1;
  if (bucket.count > maxRequests) {
    const retryAfterSeconds = Math.max(1, Math.ceil((bucket.windowStartMs + windowMs - nowMs) / 1000));
    return { allowed: false, retryAfterSeconds };
  }
  return { allowed: true };
}

export function pruneRateLimitBuckets(
  buckets: Map<string, RateLimitBucket>,
  nowMs: number,
  windowMs: number,
): void {
  if (buckets.size < 128) return;
  for (const [key, bucket] of buckets.entries()) {
    if (nowMs - bucket.windowStartMs >= windowMs) {
      buckets.delete(key);
    }
  }
}

export function writeStructuredLog(line: RequestLogLine): void {
  try {
    process.stdout.write(`${JSON.stringify(line)}\n`);
  } catch {
    // Keep API handling resilient even if stdout is unavailable.
  }
}
