import { spawn } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { Profile } from './validators';

type Connectivity = 'reachable' | 'unreachable' | 'not_configured' | 'unknown';

interface ApiHealth {
  checked_at: string;
  profile: Profile;
  cli_available: boolean;
  opensearch_host: string | null;
  opensearch_connectivity: Connectivity;
  opensearch_http_status: number | null;
  tls_mode: 'verify' | 'insecure' | 'unknown';
  last_successful_fetch_at: string | null;
  error?: string;
}

interface HealthOptions {
  rootDir: string;
  outDir: string;
  profile: Profile;
  timeoutMs?: number;
}

interface HealthCacheEntry {
  value: ApiHealth;
  expiresAtMs: number;
  refreshPromise: Promise<void> | null;
}

const DEFAULT_HEALTH_CACHE_MS = 30_000;
const OPENSEARCH_HOST_ALLOWLIST_ENV = 'TRIAGE_OPENSEARCH_HOST_ALLOWLIST';
const healthSnapshotCache = new Map<string, HealthCacheEntry>();

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

function parseDryRunPayload(stdout: string): Record<string, unknown> | null {
  const start = stdout.indexOf('{');
  if (start < 0) return null;
  try {
    return JSON.parse(stdout.slice(start)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function runDryRunProbe(
  rootDir: string,
  profile: Profile,
): Promise<{ host: string | null; verifyTls: boolean | null; cliAvailable: boolean; error?: string }> {
  return new Promise((resolve) => {
    const pythonExe = resolvePythonExe(rootDir);
    const probeOutDir = path.resolve(rootDir, '.tmp-health-probe');
    const args = [
      '-m',
      'wazuh_sysmon_triage',
      'live',
      '--dry-run-query',
      '--profile',
      profile,
      '--agent-name',
      'health-probe',
      '--last',
      '2h',
      '--case-id',
      'health-probe',
      '--out-dir',
      probeOutDir,
    ];
    const configPath = path.resolve(rootDir, 'config.local.yaml');
    if (fs.existsSync(configPath)) {
      args.push('--config', configPath);
    }

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(pythonExe, args, {
        cwd: rootDir,
        env: { ...process.env, PYTHONPATH: path.resolve(rootDir, 'src') },
        windowsHide: true,
      });
    } catch (error) {
      if (fs.existsSync(probeOutDir)) {
        fs.rmSync(probeOutDir, { recursive: true, force: true });
      }
      resolve({
        host: null,
        verifyTls: null,
        cliAvailable: false,
        error: `probe_failed:${String(error)}`,
      });
      return;
    }

    let stdout = '';
    let stderr = '';
    if (child.stdout) {
      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString();
      });
    }
    if (child.stderr) {
      child.stderr.on('data', (chunk) => {
        stderr += chunk.toString();
      });
    }

    child.on('error', (error) => {
      if (fs.existsSync(probeOutDir)) {
        fs.rmSync(probeOutDir, { recursive: true, force: true });
      }
      resolve({
        host: null,
        verifyTls: null,
        cliAvailable: false,
        error: `probe_failed:${String(error)}`,
      });
    });

    child.on('close', (code) => {
      if (fs.existsSync(probeOutDir)) {
        fs.rmSync(probeOutDir, { recursive: true, force: true });
      }
      if (code !== 0) {
        resolve({
          host: null,
          verifyTls: null,
          cliAvailable: true,
          error: `probe_exit_${code}:${stderr || stdout || 'unknown'}`,
        });
        return;
      }

      const payload = parseDryRunPayload(stdout);
      const resolved = (payload?.resolved ?? {}) as Record<string, unknown>;
      const host = typeof resolved.host === 'string'
        ? resolved.host
        : (typeof process.env.WAZUH_OS_HOST === 'string' ? process.env.WAZUH_OS_HOST : null);
      const verifyTls = typeof resolved.verify_tls === 'boolean' ? resolved.verify_tls : null;
      resolve({ host: host || null, verifyTls, cliAvailable: true });
    });
  });
}

async function loadLastSuccessfulFetch(outDir: string): Promise<string | null> {
  const summaryPath = path.resolve(outDir, 'telemetry_summary.json');
  if (!fs.existsSync(summaryPath)) return null;
  try {
    const payload = JSON.parse(await fsp.readFile(summaryPath, 'utf-8')) as Record<string, unknown>;
    return typeof payload.last_successful_live_fetch_at === 'string'
      ? payload.last_successful_live_fetch_at
      : null;
  } catch {
    return null;
  }
}

function parseNonNegativeInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0 || !Number.isInteger(parsed)) {
    return fallback;
  }
  return parsed;
}

function parseIpv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const parsed = Number(part);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) return null;
    value = (value << 8) + parsed;
  }
  return value >>> 0;
}

function parseIpv4Cidr(raw: string): { network: number; mask: number } | null {
  const [base, prefixRaw] = raw.split('/');
  if (!base || !prefixRaw) return null;
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const baseInt = parseIpv4ToInt(base);
  if (baseInt === null) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: baseInt & mask, mask };
}

function parseAllowlistRules(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[,\n;\s]+/)
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function isHostAllowedByRule(hostname: string, rule: string): boolean {
  if (rule === '*') return true;
  if (rule.includes('/')) {
    if (net.isIP(hostname) !== 4) return false;
    const cidr = parseIpv4Cidr(rule);
    const hostInt = parseIpv4ToInt(hostname);
    if (!cidr || hostInt === null) return false;
    return (hostInt & cidr.mask) === cidr.network;
  }
  if (rule.startsWith('*.')) {
    const suffix = rule.slice(2);
    if (!suffix) return false;
    return hostname === suffix || hostname.endsWith(`.${suffix}`);
  }
  return hostname === rule;
}

function validateOpenSearchHostAllowlist(hostname: string): { allowed: boolean; error?: string } {
  const rules = parseAllowlistRules(process.env[OPENSEARCH_HOST_ALLOWLIST_ENV]);
  if (!rules.length) return { allowed: true };
  const normalizedHost = hostname.trim().toLowerCase();
  if (!normalizedHost) return { allowed: false, error: 'empty_host' };
  for (const rule of rules) {
    if (isHostAllowedByRule(normalizedHost, rule)) {
      return { allowed: true };
    }
  }
  return {
    allowed: false,
    error: `host_not_allowlisted:${normalizedHost}`,
  };
}

function buildCacheKey(options: HealthOptions): string {
  return [
    path.resolve(options.rootDir),
    path.resolve(options.outDir),
    options.profile,
  ].join('::');
}

function probeOpenSearch(
  host: string | null,
  verifyTls: boolean | null,
  timeoutMs: number,
): Promise<{ connectivity: Connectivity; httpStatus: number | null; error?: string }> {
  if (!host) {
    return Promise.resolve({ connectivity: 'not_configured', httpStatus: null });
  }

  let parsed: URL;
  try {
    parsed = new URL(host);
  } catch {
    return Promise.resolve({ connectivity: 'unreachable', httpStatus: null, error: 'invalid_host_url' });
  }

  const allowlistDecision = validateOpenSearchHostAllowlist(parsed.hostname);
  if (!allowlistDecision.allowed) {
    return Promise.resolve({
      connectivity: 'unreachable',
      httpStatus: null,
      error: allowlistDecision.error ?? 'host_not_allowlisted',
    });
  }

  return new Promise((resolve) => {
    const onResponse = (res: http.IncomingMessage) => {
      res.resume();
      const statusCode = res.statusCode ?? null;
      const reachable = statusCode !== null && statusCode >= 200 && statusCode < 300;
      resolve({
        connectivity: reachable ? 'reachable' : 'unreachable',
        httpStatus: statusCode,
        ...(reachable ? {} : { error: `http_${String(statusCode)}` }),
      });
    };
    const onError = (error: unknown) => {
      resolve({
        connectivity: 'unreachable',
        httpStatus: null,
        error: String(error),
      });
    };

    const requestPath = `${parsed.pathname || '/'}${parsed.search || ''}`;
    if (parsed.protocol === 'https:') {
      const req = https.request(
        {
          method: 'GET',
          hostname: parsed.hostname,
          port: parsed.port ? Number(parsed.port) : 443,
          path: requestPath,
          timeout: timeoutMs,
          rejectUnauthorized: verifyTls !== false,
        },
        onResponse,
      );
      req.on('error', onError);
      req.on('timeout', () => {
        req.destroy(new Error('timeout'));
      });
      req.end();
      return;
    }

    if (parsed.protocol === 'http:') {
      const req = http.request(
        {
          method: 'GET',
          hostname: parsed.hostname,
          port: parsed.port ? Number(parsed.port) : 80,
          path: requestPath,
          timeout: timeoutMs,
        },
        onResponse,
      );
      req.on('error', onError);
      req.on('timeout', () => {
        req.destroy(new Error('timeout'));
      });
      req.end();
      return;
    }

    resolve({ connectivity: 'unreachable', httpStatus: null, error: 'unsupported_protocol' });
  });
}

export async function getHealthSnapshot(options: HealthOptions): Promise<ApiHealth> {
  const cacheTtlMs = parseNonNegativeInt(process.env.TRIAGE_HEALTH_CACHE_MS, DEFAULT_HEALTH_CACHE_MS);
  if (cacheTtlMs <= 0) {
    return computeHealthSnapshot(options);
  }
  const cacheKey = buildCacheKey(options);
  const nowMs = Date.now();
  const cached = healthSnapshotCache.get(cacheKey);
  if (cached && nowMs < cached.expiresAtMs) {
    return cached.value;
  }
  if (cached) {
    if (!cached.refreshPromise) {
      cached.refreshPromise = computeHealthSnapshot(options)
        .then((next) => {
          cached.value = next;
          cached.expiresAtMs = Date.now() + cacheTtlMs;
        })
        .finally(() => {
          cached.refreshPromise = null;
        });
    }
    return cached.value;
  }

  const fresh = await computeHealthSnapshot(options);
  healthSnapshotCache.set(cacheKey, {
    value: fresh,
    expiresAtMs: Date.now() + cacheTtlMs,
    refreshPromise: null,
  });
  return fresh;
}

export function resetHealthSnapshotCache(): void {
  healthSnapshotCache.clear();
}

async function computeHealthSnapshot(options: HealthOptions): Promise<ApiHealth> {
  const checkedAt = new Date().toISOString();
  const timeoutMs = options.timeoutMs ?? 2500;
  const lastSuccessfulFetch = await loadLastSuccessfulFetch(options.outDir);

  const dryRun = await runDryRunProbe(options.rootDir, options.profile);
  if (dryRun.error) {
    return {
      checked_at: checkedAt,
      profile: options.profile,
      cli_available: dryRun.cliAvailable,
      opensearch_host: dryRun.host,
      opensearch_connectivity: 'unknown',
      opensearch_http_status: null,
      tls_mode: 'unknown',
      last_successful_fetch_at: lastSuccessfulFetch,
      error: dryRun.error,
    };
  }

  const connectivity = await probeOpenSearch(dryRun.host, dryRun.verifyTls, timeoutMs);
  return {
    checked_at: checkedAt,
    profile: options.profile,
    cli_available: dryRun.cliAvailable,
    opensearch_host: dryRun.host,
    opensearch_connectivity: connectivity.connectivity,
    opensearch_http_status: connectivity.httpStatus,
    tls_mode: dryRun.verifyTls === null ? 'unknown' : (dryRun.verifyTls ? 'verify' : 'insecure'),
    last_successful_fetch_at: lastSuccessfulFetch,
    ...(connectivity.error ? { error: connectivity.error } : {}),
  };
}
