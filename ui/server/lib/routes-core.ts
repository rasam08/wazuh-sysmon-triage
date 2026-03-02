import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  ArtifactError,
  deleteCase,
  loadAlertBundle,
  loadAlerts,
  loadAllRuns,
  loadCase,
  loadReport,
  loadRun,
  type ApiRun,
} from './artifact-loader';
import { getHealthSnapshot } from './health';
import { resolveContext } from './routes-context';
import {
  DEFAULT_IDEMPOTENCY_WINDOW_MS,
  DEFAULT_RATE_LIMIT_MAX_REQUESTS,
  DEFAULT_RATE_LIMIT_WINDOW_MS,
  getLatestCaseId,
  mapQueueStatusToRunStatus,
  normalizeApiPath,
  parseBooleanFlag,
  parseJobRoute,
  parseNonNegativeIntQuery,
  parsePositiveInt,
  type ApiDispatchRequest,
  type ApiDispatchResponse,
  type MiddlewareOptions,
  type RateLimitBucket,
  type RouteOptions,
} from './routes-common';
import { toErrorResponse } from './routes-errors';
import { enforceCsrfGuard, parseRequestBody, sendJson, sendText } from './routes-http';
import {
  cloneResponse,
  getIdempotencyRecord,
  hashPayload,
  parseIdempotencyKey,
  pruneIdempotencyRecords,
  setIdempotencyRecord,
} from './routes-idempotency';
import {
  consumeRateLimit,
  normalizeRouteKey,
  pruneRateLimitBuckets,
  recordRequestMetrics,
  renderMetricsPrometheus,
  resolveDefaultClientKey,
  resolveRequestId,
  sanitizeClientKey,
  writeStructuredLog,
} from './routes-observability';
import { startJobProgressStream } from './routes-sse';
import { RunnerError } from './runner';
import { validateCaseId, validateRunParams, ValidationError } from './validators';

function asyncRunsDisabledResponse(route: string): ApiDispatchResponse {
  return {
    status: 404,
    body: {
      error: `Async runs disabled; ${route} is unavailable. Use POST /api/runs or set TRIAGE_ASYNC_RUNS_ENABLED=true.`,
    },
  };
}

export async function dispatchApiRequest(
  request: ApiDispatchRequest,
  options: RouteOptions = {},
): Promise<ApiDispatchResponse | null> {
  const context = resolveContext(options);

  try {
    const parsedUrl = new URL(request.url, 'http://localhost');
    const route = normalizeApiPath(parsedUrl.pathname);
    if (!route) return null;
    const method = request.method.toUpperCase();
    const idempotencyWindowMs = parsePositiveInt(
      process.env.TRIAGE_IDEMPOTENCY_WINDOW_MS,
      DEFAULT_IDEMPOTENCY_WINDOW_MS,
    );
    const asyncRunsEnabled = parseBooleanFlag(process.env.TRIAGE_ASYNC_RUNS_ENABLED, false);
    const jobRoute = parseJobRoute(route);

    if (route === '/api/runs' && method === 'GET') {
      const persistedRuns = await context.runIndexService.listRuns(() => loadAllRuns(context.outDir));
      const queuedRuns = context.runQueueService.listNonTerminalRuns();
      const mergedByCaseId = new Map<string, ApiRun>();
      for (const run of persistedRuns) {
        mergedByCaseId.set(run.params.case_id, run);
      }
      for (const queuedRun of queuedRuns) {
        if (!mergedByCaseId.has(queuedRun.params.case_id)) {
          mergedByCaseId.set(queuedRun.params.case_id, queuedRun);
        }
      }
      let runs = [...mergedByCaseId.values()];

      const statusFilter = parsedUrl.searchParams.get('status');
      const modeFilter = parsedUrl.searchParams.get('mode');
      if (statusFilter) {
        runs = runs.filter((run) => run.status === mapQueueStatusToRunStatus(statusFilter));
      }
      if (modeFilter) {
        runs = runs.filter((run) => run.params.mode === modeFilter);
      }
      const offset = parseNonNegativeIntQuery(parsedUrl.searchParams.get('offset'), 0);
      const limitRaw = parsedUrl.searchParams.get('limit');
      const limit = limitRaw ? parseNonNegativeIntQuery(limitRaw, runs.length) : runs.length;
      runs = runs.slice(offset, offset + limit);

      return { status: 200, body: { runs } };
    }

    if (route === '/api/runs' && method === 'POST') {
      const idempotencyKey = parseIdempotencyKey(request.headers);
      if (idempotencyKey) {
        const nowMs = Date.now();
        pruneIdempotencyRecords(nowMs, idempotencyWindowMs);
        const requestHash = hashPayload(request.body);
        const prior = getIdempotencyRecord(idempotencyKey);
        if (prior) {
          if (prior.requestHash !== requestHash) {
            throw new ValidationError('Idempotency-Key replay must use an identical request body', 409);
          }
          return cloneResponse(prior.response);
        }
      }

      const params = validateRunParams(request.body, {
        defaultOutDir: context.outDir,
        rootDir: context.rootDir,
        allowedOfflineInputRoots: context.offlineInputRoots,
      });
      if (params.dry_run) {
        throw new ValidationError('dry_run is preview-only; use POST /api/runs/preview');
      }
      await context.runner.startRun(params);
      let run;
      try {
        run = await loadRun(context.outDir, params.case_id);
      } catch (error) {
        if (error instanceof ArtifactError && error.status === 404) {
          throw new RunnerError('CLI run succeeded but output artifacts were not found');
        }
        throw error;
      }
      const response = { status: 200, body: { run } };
      context.runIndexService.invalidate();
      if (idempotencyKey) {
        setIdempotencyRecord(idempotencyKey, {
          requestHash: hashPayload(request.body),
          response: cloneResponse(response),
          createdAtMs: Date.now(),
        });
      }
      return response;
    }

    if (route === '/api/runs/submit' && method === 'POST') {
      if (!asyncRunsEnabled) {
        return asyncRunsDisabledResponse(route);
      }
      const params = validateRunParams(request.body, {
        defaultOutDir: context.outDir,
        rootDir: context.rootDir,
        allowedOfflineInputRoots: context.offlineInputRoots,
      });
      if (params.dry_run) {
        throw new ValidationError('dry_run is preview-only; use POST /api/runs/preview');
      }
      const job = context.runQueueService.submitRun(params, {
        idempotencyKey: parseIdempotencyKey(request.headers),
        requestBody: request.body,
      });
      context.runIndexService.invalidate();
      return {
        status: 202,
        body: {
          job_id: job.job_id,
          case_id: job.case_id,
          accepted_at: job.accepted_at,
        },
      };
    }

    if (jobRoute?.kind === 'status' && method === 'GET') {
      if (!asyncRunsEnabled) {
        return asyncRunsDisabledResponse(route);
      }
      const job = context.runQueueService.getJob(jobRoute.jobId);
      return { status: 200, body: { job } };
    }

    if (jobRoute?.kind === 'cancel' && method === 'POST') {
      if (!asyncRunsEnabled) {
        return asyncRunsDisabledResponse(route);
      }
      const job = context.runQueueService.cancelJob(jobRoute.jobId, 'user');
      context.runIndexService.invalidate();
      return { status: 202, body: { cancelled: true, job } };
    }

    if (jobRoute?.kind === 'stream' && method === 'GET' && !asyncRunsEnabled) {
      return asyncRunsDisabledResponse(route);
    }

    if (
      route.startsWith('/api/runs/')
      && !route.startsWith('/api/runs/jobs/')
      && route.endsWith('/cancel')
      && method === 'POST'
    ) {
      const encodedCaseId = route.slice('/api/runs/'.length, route.length - '/cancel'.length);
      const caseId = validateCaseId(decodeURIComponent(encodedCaseId));
      const queuedJob = context.runQueueService.cancelCase(caseId, 'user');
      if (queuedJob) {
        context.runIndexService.invalidate();
        return {
          status: 202,
          body: {
            cancelled: true,
            case_id: caseId,
            reason: 'user',
            job_id: queuedJob.job_id,
          },
        };
      }
      const cancelled = context.runner.cancelRun(caseId);
      context.runIndexService.invalidate();
      return { status: 202, body: cancelled };
    }

    if (route === '/api/runs/preview' && method === 'POST') {
      const params = validateRunParams(request.body, {
        defaultOutDir: context.outDir,
        rootDir: context.rootDir,
        allowedOfflineInputRoots: context.offlineInputRoots,
      });
      const preview = context.runner.previewRun(params);
      return { status: 200, body: { preview } };
    }

    if (route === '/api/health' && method === 'GET') {
      const rawProfile = parsedUrl.searchParams.get('profile') || 'soc';
      const VALID_PROFILES = new Set(['soc', 'dev', 'lab']);
      if (!VALID_PROFILES.has(rawProfile)) {
        return { status: 400, body: { error: `Invalid profile: ${rawProfile}` } };
      }
      const profile = rawProfile as 'soc' | 'dev' | 'lab';
      const health = await getHealthSnapshot({
        rootDir: context.rootDir,
        outDir: context.outDir,
        profile,
      });
      return { status: 200, body: { health } };
    }

    if (route.startsWith('/api/cases/') && method === 'GET') {
      const encodedCaseId = route.slice('/api/cases/'.length);
      const caseId = validateCaseId(decodeURIComponent(encodedCaseId));
      const casePayload = await loadCase(context.outDir, caseId);
      return { status: 200, body: { case: casePayload } };
    }

    if (route.startsWith('/api/cases/') && method === 'DELETE') {
      const encodedCaseId = route.slice('/api/cases/'.length);
      const caseId = validateCaseId(decodeURIComponent(encodedCaseId));
      if (context.runner.isCaseActive(caseId)) {
        throw new RunnerError(`Cannot delete case ${caseId} while run is active`, 409);
      }
      await deleteCase(context.outDir, caseId);
      context.runIndexService.invalidate();
      return { status: 200, body: { deleted: true, case_id: caseId } };
    }

    if (route === '/api/alerts' && method === 'GET') {
      const requestedCase = parsedUrl.searchParams.get('case');
      let caseId = requestedCase ? validateCaseId(requestedCase) : null;
      if (!caseId) {
        const runs = await context.runIndexService.listRuns(() => loadAllRuns(context.outDir));
        caseId = getLatestCaseId(runs);
      }
      if (!caseId) {
        return { status: 200, body: { alerts: [], case_id: null } };
      }
      const alerts = await loadAlerts(context.outDir, caseId);
      return { status: 200, body: { alerts, case_id: caseId } };
    }

    if (route.startsWith('/api/alerts/') && route.endsWith('/bundle') && method === 'GET') {
      const encodedAlertId = route.slice('/api/alerts/'.length, route.length - '/bundle'.length);
      const alertId = decodeURIComponent(encodedAlertId);
      const caseId = validateCaseId(parsedUrl.searchParams.get('case') || '');
      const bundle = await loadAlertBundle(context.outDir, caseId, alertId);
      return { status: 200, body: { bundle } };
    }

    if (route === '/api/report' && method === 'GET') {
      const caseId = validateCaseId(parsedUrl.searchParams.get('case') || '');
      const report = await loadReport(context.outDir, caseId);
      return { status: 200, body: { report } };
    }

    return { status: 404, body: { error: `Unknown API route: ${route}` } };
  } catch (error) {
    return toErrorResponse(error);
  }
}

export function createTriageApiMiddleware(options: MiddlewareOptions = {}) {
  const context = resolveContext(options);
  const rateLimitBuckets = new Map<string, RateLimitBucket>();
  const rateLimitMaxRequests = options.rateLimitMaxRequests ?? DEFAULT_RATE_LIMIT_MAX_REQUESTS;
  const rateLimitWindowMs = options.rateLimitWindowMs ?? DEFAULT_RATE_LIMIT_WINDOW_MS;
  const enforceCsrf = parseBooleanFlag(process.env.TRIAGE_ENFORCE_CSRF, false);
  const asyncRunsEnabled = parseBooleanFlag(process.env.TRIAGE_ASYNC_RUNS_ENABLED, false);
  const now = options.now ?? Date.now;
  const resolveClientKey = options.clientKeyResolver ?? resolveDefaultClientKey;

  return (req: IncomingMessage, res: ServerResponse, next: () => void): void => {
    if (!req.url) {
      next();
      return;
    }

    const pathName = req.url.split('?')[0];
    const method = (req.method || 'GET').toUpperCase();
    const routeKey = normalizeRouteKey(pathName);
    const clientKey = sanitizeClientKey(resolveClientKey(req));
    const requestId = resolveRequestId(req);
    const startedAtMs = now();
    res.setHeader('X-Request-Id', requestId);

    const logRequest = (status: number, rateLimited: boolean): void => {
      const durationMs = Math.max(0, now() - startedAtMs);
      recordRequestMetrics(routeKey, method, status, durationMs, rateLimited);
      writeStructuredLog({
        ts: new Date().toISOString(),
        event: 'api_request',
        request_id: requestId,
        client_key: clientKey,
        method,
        route: routeKey,
        path: pathName,
        status,
        duration_ms: durationMs,
        rate_limited: rateLimited,
      });
    };

    if (pathName === '/metrics' || pathName === '/api/metrics') {
      if (method !== 'GET') {
        sendText(res, 405, 'Method Not Allowed\n', 'text/plain; charset=utf-8');
        logRequest(405, false);
        return;
      }
      const payload = renderMetricsPrometheus(context.runQueueService);
      sendText(res, 200, payload);
      logRequest(200, false);
      return;
    }

    const normalizedApiRoute = normalizeApiPath(pathName);
    if (!normalizedApiRoute) {
      next();
      return;
    }
    const rateLimitKey = `${routeKey}::${clientKey}`;

    const nowMs = now();
    pruneRateLimitBuckets(rateLimitBuckets, nowMs, rateLimitWindowMs);
    const limit = consumeRateLimit(
      rateLimitBuckets,
      rateLimitKey,
      nowMs,
      rateLimitMaxRequests,
      rateLimitWindowMs,
    );
    if (!limit.allowed) {
      if (limit.retryAfterSeconds) {
        res.setHeader('Retry-After', String(limit.retryAfterSeconds));
      }
      sendJson(res, 429, {
        error: `Rate limit exceeded for route ${routeKey}. Max ${rateLimitMaxRequests} requests per ${Math.round(rateLimitWindowMs / 1000)} seconds.`,
      });
      logRequest(429, true);
      return;
    }

    const handle = async () => {
      let body: unknown = undefined;
      const streamRoute = parseJobRoute(normalizedApiRoute);
      if (asyncRunsEnabled && method === 'GET' && streamRoute?.kind === 'stream') {
        try {
          startJobProgressStream({
            req,
            res,
            runQueueService: context.runQueueService,
            jobId: streamRoute.jobId,
            onStatusLogged: (status) => logRequest(status, false),
          });
          return;
        } catch (error) {
          const response = toErrorResponse(error);
          sendJson(res, response.status, response.body);
          logRequest(response.status, false);
          return;
        }
      }
      if (enforceCsrf) {
        enforceCsrfGuard(req, method);
      }
      if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        body = await parseRequestBody(req);
      }
      const response = await dispatchApiRequest(
        { method, url: req.url || '/', body, headers: req.headers },
        {
          rootDir: context.rootDir,
          outDir: context.outDir,
          offlineInputRoots: context.offlineInputRoots,
          runner: context.runner,
          runQueueService: context.runQueueService,
          runIndexService: context.runIndexService,
        },
      );
      if (!response) {
        next();
        return;
      }
      sendJson(res, response.status, response.body);
      logRequest(response.status, false);
    };

    void handle().catch((error) => {
      const response = toErrorResponse(error);
      sendJson(res, response.status, response.body);
      logRequest(response.status, false);
    });
  };
}
