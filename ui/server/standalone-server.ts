import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type NextFunction, type Request, type Response } from 'express';
import { createTriageApiMiddleware } from './lib/routes';

export interface StandaloneServerOptions {
  rootDir?: string;
  outDir?: string;
  distDir?: string;
  port?: number;
  bindHost?: string;
  publicBind?: boolean;
  allowInsecurePublicBind?: boolean;
  authUser?: string;
  authPass?: string;
  authMaxFailures?: number;
  authFailureWindowMs?: number;
  authLockoutMs?: number;
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  const parsed = Number(raw);
  if (Number.isFinite(parsed) && parsed > 0 && Number.isInteger(parsed)) {
    return parsed;
  }
  return fallback;
}

function parseBoolean(raw: string | undefined, fallback = false): boolean {
  if (raw === undefined) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (!normalized) return fallback;
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

interface AuthThrottleOptions {
  maxFailures: number;
  windowMs: number;
  lockoutMs: number;
}

interface AuthFailureBucket {
  windowStartMs: number;
  failures: number;
  lockedUntilMs: number;
}

const DEFAULT_AUTH_MAX_FAILURES = 8;
const DEFAULT_AUTH_FAILURE_WINDOW_MS = 5 * 60 * 1000;
const DEFAULT_AUTH_LOCKOUT_MS = 2 * 60 * 1000;

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return normalized === '127.0.0.1'
    || normalized === 'localhost'
    || normalized === '::1'
    || normalized === '[::1]';
}

function resolveBindConfig(options: StandaloneServerOptions): { bindHost: string; publicBind: boolean } {
  const publicBind = options.publicBind ?? parseBoolean(process.env.PUBLIC_BIND, false);
  const hostFromOptions = options.bindHost?.trim();
  const hostFromEnv = process.env.BIND_HOST?.trim() || process.env.HOST?.trim();
  const bindHost = hostFromOptions || hostFromEnv || (publicBind ? '0.0.0.0' : '127.0.0.1');
  if (!publicBind && !isLoopbackHost(bindHost)) {
    throw new Error(`Non-local bind host "${bindHost}" requires PUBLIC_BIND=true.`);
  }
  return { bindHost, publicBind };
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let index = 0; index < a.length; index += 1) {
    result |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return result === 0;
}

function parseBasicAuth(header: string | undefined): { user: string; pass: string } | null {
  if (!header || !header.startsWith('Basic ')) return null;
  const encoded = header.slice('Basic '.length).trim();
  if (!encoded) return null;

  let decoded: string;
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf-8');
  } catch {
    return null;
  }
  const separator = decoded.indexOf(':');
  if (separator < 0) return null;
  return {
    user: decoded.slice(0, separator),
    pass: decoded.slice(separator + 1),
  };
}

function sendUnauthorized(req: Request, res: Response): void {
  res.setHeader('WWW-Authenticate', 'Basic realm="Wazuh Sysmon Triage", charset="UTF-8"');
  if (req.path.startsWith('/api/')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  res.status(401).send('Authentication required');
}

function sendAuthRateLimited(req: Request, res: Response, retryAfterSeconds: number): void {
  res.setHeader('Retry-After', String(retryAfterSeconds));
  if (req.path.startsWith('/api/')) {
    res.status(429).json({ error: 'Too many authentication attempts; retry later.' });
    return;
  }
  res.status(429).send('Too many authentication attempts; retry later.');
}

function sanitizeAuthClientKey(value: string | undefined): string {
  const trimmed = (value ?? '').trim();
  if (!trimmed) return 'unknown';
  return trimmed.slice(0, 128).replace(/[^a-zA-Z0-9:._-]/g, '?');
}

function resolveAuthClientKey(req: Request): string {
  const forwardedFor = req.header('x-forwarded-for');
  if (forwardedFor) {
    return sanitizeAuthClientKey(forwardedFor.split(',')[0]);
  }
  return sanitizeAuthClientKey(req.socket.remoteAddress);
}

function consumeAuthFailure(
  buckets: Map<string, AuthFailureBucket>,
  key: string,
  nowMs: number,
  options: AuthThrottleOptions,
): AuthFailureBucket {
  const existing = buckets.get(key);
  if (!existing || nowMs - existing.windowStartMs >= options.windowMs) {
    const next = {
      windowStartMs: nowMs,
      failures: 1,
      lockedUntilMs: 0,
    };
    buckets.set(key, next);
    return next;
  }
  existing.failures += 1;
  if (existing.failures >= options.maxFailures) {
    existing.lockedUntilMs = nowMs + options.lockoutMs;
  }
  return existing;
}

function pruneAuthFailureBuckets(
  buckets: Map<string, AuthFailureBucket>,
  nowMs: number,
  options: AuthThrottleOptions,
): void {
  if (buckets.size < 128) return;
  for (const [key, bucket] of buckets.entries()) {
    if (bucket.lockedUntilMs > nowMs) continue;
    if (nowMs - bucket.windowStartMs >= options.windowMs) {
      buckets.delete(key);
    }
  }
}

function buildAuthMiddleware(user: string, pass: string, throttleOptions: AuthThrottleOptions) {
  const failures = new Map<string, AuthFailureBucket>();
  return (req: Request, res: Response, next: NextFunction): void => {
    const nowMs = Date.now();
    const clientKey = resolveAuthClientKey(req);
    pruneAuthFailureBuckets(failures, nowMs, throttleOptions);
    const bucket = failures.get(clientKey);
    if (bucket && bucket.lockedUntilMs > nowMs) {
      const retryAfterSeconds = Math.max(1, Math.ceil((bucket.lockedUntilMs - nowMs) / 1000));
      sendAuthRateLimited(req, res, retryAfterSeconds);
      return;
    }

    const parsed = parseBasicAuth(req.header('authorization'));
    if (!parsed || !safeEqual(parsed.user, user) || !safeEqual(parsed.pass, pass)) {
      const nextBucket = consumeAuthFailure(failures, clientKey, nowMs, throttleOptions);
      if (nextBucket.lockedUntilMs > nowMs) {
        const retryAfterSeconds = Math.max(1, Math.ceil((nextBucket.lockedUntilMs - nowMs) / 1000));
        sendAuthRateLimited(req, res, retryAfterSeconds);
        return;
      }
      sendUnauthorized(req, res);
      return;
    }
    failures.delete(clientKey);
    next();
  };
}

function resolvePaths(options: StandaloneServerOptions): { rootDir: string; distDir: string; outDir?: string } {
  const rootDir = options.rootDir
    ? path.resolve(options.rootDir)
    : path.resolve(fileURLToPath(new URL('..', import.meta.url)), '..');
  const uiDir = path.resolve(rootDir, 'ui');
  const distDir = options.distDir ? path.resolve(options.distDir) : path.resolve(uiDir, 'dist');
  const outDir = options.outDir ? path.resolve(options.outDir) : undefined;
  return { rootDir, distDir, outDir };
}

export function createStandaloneApp(options: StandaloneServerOptions = {}) {
  const { rootDir, distDir, outDir } = resolvePaths(options);
  const app = express();
  app.disable('x-powered-by');

  const authUser = options.authUser ?? process.env.AUTH_USER;
  const authPass = options.authPass ?? process.env.AUTH_PASS;
  const authThrottle: AuthThrottleOptions = {
    maxFailures: options.authMaxFailures ?? parsePositiveInt(process.env.TRIAGE_AUTH_MAX_FAILURES, DEFAULT_AUTH_MAX_FAILURES),
    windowMs: options.authFailureWindowMs ?? parsePositiveInt(process.env.TRIAGE_AUTH_WINDOW_MS, DEFAULT_AUTH_FAILURE_WINDOW_MS),
    lockoutMs: options.authLockoutMs ?? parsePositiveInt(process.env.TRIAGE_AUTH_LOCKOUT_MS, DEFAULT_AUTH_LOCKOUT_MS),
  };
  if ((authUser && !authPass) || (!authUser && authPass)) {
    throw new Error('AUTH_USER and AUTH_PASS must both be provided to enable HTTP Basic auth.');
  }
  if (authUser && authPass) {
    app.use(buildAuthMiddleware(authUser, authPass, authThrottle));
  }

  const apiMiddleware = createTriageApiMiddleware({ rootDir, outDir });
  app.use((req: Request, res: Response, next: NextFunction) => {
    apiMiddleware(req, res, next);
  });

  app.use(
    express.static(distDir, {
      index: false,
      etag: true,
      maxAge: '1h',
    }),
  );

  app.get('*', (_req: Request, res: Response) => {
    const indexPath = path.resolve(distDir, 'index.html');
    if (!fs.existsSync(indexPath)) {
      res.status(503).send('UI build missing. Run "npm run build" in ui/ before starting the server.');
      return;
    }
    res.sendFile(indexPath);
  });

  return app;
}

export function startStandaloneServer(options: StandaloneServerOptions = {}) {
  const port = options.port ?? parsePositiveInt(process.env.PORT, 4173);
  const authUser = options.authUser ?? process.env.AUTH_USER;
  const authPass = options.authPass ?? process.env.AUTH_PASS;
  const allowInsecurePublicBind = options.allowInsecurePublicBind
    ?? parseBoolean(process.env.TRIAGE_ALLOW_INSECURE_PUBLIC_BIND, false);
  const { bindHost, publicBind } = resolveBindConfig(options);
  if (!isLoopbackHost(bindHost) && !(authUser && authPass)) {
    throw new Error(`Non-local bind host "${bindHost}" requires AUTH_USER and AUTH_PASS.`);
  }
  if (!isLoopbackHost(bindHost) && !allowInsecurePublicBind) {
    throw new Error(
      `Non-local bind host "${bindHost}" requires TRIAGE_ALLOW_INSECURE_PUBLIC_BIND=true (terminate TLS at a reverse proxy).`,
    );
  }

  const app = createStandaloneApp(options);
  const server = app.listen(port, bindHost, () => {
    const authEnabled = Boolean(authUser && authPass);
    process.stdout.write(`${JSON.stringify({
      ts: new Date().toISOString(),
      event: 'standalone_server_started',
      port,
      bind_host: bindHost,
      public_bind: publicBind,
      auth_enabled: authEnabled,
    })}\n`);
  });
  return server;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
const modulePath = fileURLToPath(import.meta.url);
if (invokedPath && modulePath === invokedPath) {
  startStandaloneServer();
}
