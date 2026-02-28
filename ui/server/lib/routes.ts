import path from 'node:path';
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
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
import { createRunner, RunnerError, type Runner } from './runner';
import { validateCaseId, validateRunParams, ValidationError } from './validators';

interface RouteOptions {
  rootDir?: string;
  outDir?: string;
  runner?: Runner;
}

interface MiddlewareOptions extends RouteOptions {
  rateLimitMaxRequests?: number;
  rateLimitWindowMs?: number;
  now?: () => number;
}

export interface ApiDispatchRequest {
  method: string;
  url: string;
  body?: unknown;
}

interface ApiDispatchResponse {
  status: number;
  body: unknown;
}

interface RouteContext {
  rootDir: string;
  outDir: string;
  runner: Runner;
}

interface RateLimitBucket {
  windowStartMs: number;
  count: number;
}

interface RequestLogLine {
  ts: string;
  event: 'api_request';
  request_id: string;
  method: string;
  route: string;
  path: string;
  status: number;
  duration_ms: number;
  rate_limited: boolean;
}

function hasCaseArtifacts(outDir: string): boolean {
  if (!fs.existsSync(outDir)) return false;
  let entries: fs.Dirent[] = [];
  try {
    entries = fs.readdirSync(outDir, { withFileTypes: true });
  } catch {
    return false;
  }
  return entries.some((entry) => {
    if (!entry.isDirectory() || entry.name.startsWith('.')) return false;
    return fs.existsSync(path.resolve(outDir, entry.name, 'run_metadata.json'));
  });
}

function resolveDefaultOutDir(rootDir: string): string {
  const outDir = path.resolve(rootDir, 'out');
  const outputDir = path.resolve(rootDir, 'output');
  if (hasCaseArtifacts(outDir)) return outDir;
  if (hasCaseArtifacts(outputDir)) return outputDir;
  if (fs.existsSync(outDir)) return outDir;
  if (fs.existsSync(outputDir)) return outputDir;
  return outDir;
}

function normalizeApiPath(pathname: string): string | null {
  if (pathname === '/api/v1') return '/api';
  if (pathname.startsWith('/api/v1/')) {
    return `/api/${pathname.slice('/api/v1/'.length)}`;
  }
  if (pathname === '/api' || pathname.startsWith('/api/')) return pathname;
  return null;
}

function getLatestCaseId(runs: ApiRun[]): string | null {
  if (!runs.length) return null;
  return runs[0].params.case_id;
}

function toErrorResponse(error: unknown): ApiDispatchResponse {
  if (error instanceof URIError) {
    return { status: 400, body: { error: 'Invalid URL encoding' } };
  }
  if (error instanceof ValidationError) {
    return { status: error.status, body: { error: error.message } };
  }
  if (error instanceof RunnerError) {
    return { status: error.status, body: { error: error.message } };
  }
  if (error instanceof ArtifactError) {
    return { status: error.status, body: { error: error.message } };
  }
  if (error instanceof Error) {
    // Redact internal paths and stack details from 500 responses
    return { status: 500, body: { error: 'Internal server error' } };
  }
  return { status: 500, body: { error: 'Internal server error' } };
}

function resolveContext(options: RouteOptions = {}): RouteContext {
  const rootDir = options.rootDir ? path.resolve(options.rootDir) : path.resolve(__dirname, '..', '..', '..');
  const outDir = options.outDir ? path.resolve(options.outDir) : resolveDefaultOutDir(rootDir);
  const runner = options.runner ?? createRunner({ rootDir });
  return { rootDir, outDir, runner };
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

    if (route === '/api/runs' && method === 'GET') {
      const runs = await loadAllRuns(context.outDir);
      return { status: 200, body: { runs } };
    }

    if (route === '/api/runs' && method === 'POST') {
      const params = validateRunParams(request.body, { defaultOutDir: context.outDir });
      if (params.dry_run) {
        throw new ValidationError('dry_run is preview-only; use POST /api/runs/preview');
      }
      await context.runner.startRun(params);
      let run;
      try {
        run = loadRun(context.outDir, params.case_id);
      } catch (error) {
        if (error instanceof ArtifactError && error.status === 404) {
          throw new RunnerError('CLI run succeeded but output artifacts were not found');
        }
        throw error;
      }
      return { status: 200, body: { run } };
    }

    if (route === '/api/runs/preview' && method === 'POST') {
      const params = validateRunParams(request.body, { defaultOutDir: context.outDir });
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
      const casePayload = loadCase(context.outDir, caseId);
      return { status: 200, body: { case: casePayload } };
    }

    if (route.startsWith('/api/cases/') && method === 'DELETE') {
      const encodedCaseId = route.slice('/api/cases/'.length);
      const caseId = validateCaseId(decodeURIComponent(encodedCaseId));
      await deleteCase(context.outDir, caseId);
      return { status: 200, body: { deleted: true, case_id: caseId } };
    }

    if (route === '/api/alerts' && method === 'GET') {
      const requestedCase = parsedUrl.searchParams.get('case');
      let caseId = requestedCase ? validateCaseId(requestedCase) : null;
      if (!caseId) {
        const runs = await loadAllRuns(context.outDir);
        caseId = getLatestCaseId(runs);
      }
      if (!caseId) {
        return { status: 200, body: { alerts: [], case_id: null } };
      }
      const alerts = loadAlerts(context.outDir, caseId);
      return { status: 200, body: { alerts, case_id: caseId } };
    }

    if (route.startsWith('/api/alerts/') && route.endsWith('/bundle') && method === 'GET') {
      const encodedAlertId = route.slice('/api/alerts/'.length, route.length - '/bundle'.length);
      const alertId = decodeURIComponent(encodedAlertId);
      const caseId = validateCaseId(parsedUrl.searchParams.get('case') || '');
      const bundle = loadAlertBundle(context.outDir, caseId, alertId);
      return { status: 200, body: { bundle } };
    }

    if (route === '/api/report' && method === 'GET') {
      const caseId = validateCaseId(parsedUrl.searchParams.get('case') || '');
      const report = loadReport(context.outDir, caseId);
      return { status: 200, body: { report } };
    }

    return { status: 404, body: { error: `Unknown API route: ${route}` } };
  } catch (error) {
    return toErrorResponse(error);
  }
}

const MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024; // 1 MB
const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 100;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60 * 1000;

function parseRequestBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    req.on('data', (chunk) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.length;
      if (totalBytes > MAX_REQUEST_BODY_BYTES) {
        req.destroy();
        reject(new ValidationError('Request body too large', 413));
        return;
      }
      chunks.push(buf);
    });
    req.on('error', reject);
    req.on('end', () => {
      if (!chunks.length) {
        resolve(null);
        return;
      }
      const raw = Buffer.concat(chunks).toString('utf-8');
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new ValidationError('Invalid JSON request body'));
      }
    });
  });
}

function setSecurityHeaders(res: ServerResponse): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'");
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.statusCode = status;
  setSecurityHeaders(res);
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(payload));
}

function resolveRequestId(req: IncomingMessage): string {
  const incoming = req.headers['x-request-id'];
  const headerValue = Array.isArray(incoming) ? incoming[0] : incoming;
  if (typeof headerValue === 'string' && headerValue.trim().length > 0) {
    return headerValue.trim();
  }
  return randomUUID();
}

function normalizeRouteKey(pathname: string): string {
  const route = normalizeApiPath(pathname);
  if (!route) return pathname;
  if (route.startsWith('/api/cases/')) return '/api/cases/:caseId';
  if (route.startsWith('/api/alerts/') && route.endsWith('/bundle')) {
    return '/api/alerts/:alertId/bundle';
  }
  return route;
}

function consumeRateLimit(
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

function pruneRateLimitBuckets(
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

function writeStructuredLog(line: RequestLogLine): void {
  try {
    process.stdout.write(`${JSON.stringify(line)}\n`);
  } catch {
    // Keep API handling resilient even if stdout is unavailable.
  }
}

export function createTriageApiMiddleware(options: MiddlewareOptions = {}) {
  const context = resolveContext(options);
  const rateLimitBuckets = new Map<string, RateLimitBucket>();
  const rateLimitMaxRequests = options.rateLimitMaxRequests ?? DEFAULT_RATE_LIMIT_MAX_REQUESTS;
  const rateLimitWindowMs = options.rateLimitWindowMs ?? DEFAULT_RATE_LIMIT_WINDOW_MS;
  const now = options.now ?? Date.now;

  return (req: IncomingMessage, res: ServerResponse, next: () => void): void => {
    if (!req.url) {
      next();
      return;
    }

    const pathName = req.url.split('?')[0];
    if (!normalizeApiPath(pathName)) {
      next();
      return;
    }

    const method = (req.method || 'GET').toUpperCase();
    const routeKey = normalizeRouteKey(pathName);
    const requestId = resolveRequestId(req);
    const startedAtMs = now();
    res.setHeader('X-Request-Id', requestId);

    const logRequest = (status: number, rateLimited: boolean): void => {
      writeStructuredLog({
        ts: new Date().toISOString(),
        event: 'api_request',
        request_id: requestId,
        method,
        route: routeKey,
        path: pathName,
        status,
        duration_ms: Math.max(0, now() - startedAtMs),
        rate_limited: rateLimited,
      });
    };

    const nowMs = now();
    pruneRateLimitBuckets(rateLimitBuckets, nowMs, rateLimitWindowMs);
    const limit = consumeRateLimit(rateLimitBuckets, routeKey, nowMs, rateLimitMaxRequests, rateLimitWindowMs);
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
      if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        body = await parseRequestBody(req);
      }
      const response = await dispatchApiRequest(
        { method, url: req.url || '/', body },
        { rootDir: context.rootDir, outDir: context.outDir, runner: context.runner },
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
