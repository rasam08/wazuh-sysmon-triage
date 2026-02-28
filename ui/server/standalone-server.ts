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
  authUser?: string;
  authPass?: string;
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

function buildAuthMiddleware(user: string, pass: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parsed = parseBasicAuth(req.header('authorization'));
    if (!parsed || !safeEqual(parsed.user, user) || !safeEqual(parsed.pass, pass)) {
      sendUnauthorized(req, res);
      return;
    }
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
  if ((authUser && !authPass) || (!authUser && authPass)) {
    throw new Error('AUTH_USER and AUTH_PASS must both be provided to enable HTTP Basic auth.');
  }
  if (authUser && authPass) {
    app.use(buildAuthMiddleware(authUser, authPass));
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
  const { bindHost, publicBind } = resolveBindConfig(options);
  if (!isLoopbackHost(bindHost) && !(authUser && authPass)) {
    throw new Error(`Non-local bind host "${bindHost}" requires AUTH_USER and AUTH_PASS.`);
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
