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
  const app = createStandaloneApp(options);
  app.listen(port, '0.0.0.0', () => {
    const authEnabled = Boolean((options.authUser ?? process.env.AUTH_USER) && (options.authPass ?? process.env.AUTH_PASS));
    process.stdout.write(`${JSON.stringify({
      ts: new Date().toISOString(),
      event: 'standalone_server_started',
      port,
      auth_enabled: authEnabled,
    })}\n`);
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
const modulePath = fileURLToPath(import.meta.url);
if (invokedPath && modulePath === invokedPath) {
  startStandaloneServer();
}
