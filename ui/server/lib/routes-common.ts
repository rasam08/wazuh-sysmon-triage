import fs from 'node:fs';
import path from 'node:path';
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http';
import type { ApiRun } from './artifact-loader';
import type { RunIndexService } from './run-index-service';
import type { RunQueueService } from './run-queue-service';
import type { Runner } from './runner';

export interface RouteOptions {
  rootDir?: string;
  outDir?: string;
  offlineInputRoots?: string[];
  runner?: Runner;
  runQueueService?: RunQueueService;
  runIndexService?: RunIndexService;
}

export interface MiddlewareOptions extends RouteOptions {
  rateLimitMaxRequests?: number;
  rateLimitWindowMs?: number;
  now?: () => number;
  clientKeyResolver?: (req: IncomingMessage) => string;
}

export interface ApiDispatchRequest {
  method: string;
  url: string;
  body?: unknown;
  headers?: IncomingHttpHeaders;
}

export interface ApiDispatchResponse {
  status: number;
  body: unknown;
}

export interface RouteContext {
  rootDir: string;
  outDir: string;
  offlineInputRoots: string[];
  runner: Runner;
  runQueueService: RunQueueService;
  runIndexService: RunIndexService;
}

export interface RateLimitBucket {
  windowStartMs: number;
  count: number;
}

export const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 100;
export const DEFAULT_RATE_LIMIT_WINDOW_MS = 60 * 1000;
export const DEFAULT_IDEMPOTENCY_WINDOW_MS = 24 * 60 * 60 * 1000;

export function resolveDefaultOutDir(rootDir: string): string {
  const outDir = path.resolve(rootDir, 'out');
  const outputDir = path.resolve(rootDir, 'output');
  if (fs.existsSync(outDir)) return outDir;
  if (fs.existsSync(outputDir)) return outputDir;
  return outDir;
}

export function resolveOfflineInputRoots(rootDir: string, options: RouteOptions): string[] {
  if (options.offlineInputRoots?.length) {
    return options.offlineInputRoots.map((entry) => path.resolve(rootDir, entry));
  }
  const configured = process.env.TRIAGE_OFFLINE_INPUT_ROOTS;
  if (configured) {
    const values = configured
      .split(path.delimiter)
      .map((value) => value.trim())
      .filter(Boolean);
    if (values.length) {
      return values.map((entry) => path.resolve(rootDir, entry));
    }
  }
  return [path.resolve(rootDir, 'samples')];
}

export function normalizeApiPath(pathname: string): string | null {
  if (pathname === '/api/v1') return '/api';
  if (pathname.startsWith('/api/v1/')) {
    return `/api/${pathname.slice('/api/v1/'.length)}`;
  }
  if (pathname === '/api' || pathname.startsWith('/api/')) return pathname;
  return null;
}

export function getLatestCaseId(runs: ApiRun[]): string | null {
  if (!runs.length) return null;
  return runs[0].params.case_id;
}

export function parseNonNegativeIntQuery(raw: string | null, fallback: number): number {
  if (raw === null || raw === undefined || raw === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0) return fallback;
  return parsed;
}

export function mapQueueStatusToRunStatus(status: string): ApiRun['status'] {
  if (status === 'pending') return 'pending';
  if (status === 'queued') return 'pending';
  if (status === 'cancelled') return 'cancelled';
  if (status === 'running' || status === 'success' || status === 'failed') {
    return status;
  }
  return 'failed';
}

export function parseJobRoute(route: string):
  | { kind: 'status' | 'cancel' | 'stream'; jobId: string }
  | null {
  if (!route.startsWith('/api/runs/jobs/')) return null;
  if (route.endsWith('/cancel')) {
    const jobId = route.slice('/api/runs/jobs/'.length, route.length - '/cancel'.length);
    return { kind: 'cancel', jobId: decodeURIComponent(jobId) };
  }
  if (route.endsWith('/stream')) {
    const jobId = route.slice('/api/runs/jobs/'.length, route.length - '/stream'.length);
    return { kind: 'stream', jobId: decodeURIComponent(jobId) };
  }
  const jobId = route.slice('/api/runs/jobs/'.length);
  return { kind: 'status', jobId: decodeURIComponent(jobId) };
}

export function writeSseEvent(res: ServerResponse, event: string, payload: unknown): void {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

export function parseBooleanFlag(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (!normalized) return fallback;
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

export function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0 || !Number.isInteger(parsed)) {
    return fallback;
  }
  return parsed;
}
