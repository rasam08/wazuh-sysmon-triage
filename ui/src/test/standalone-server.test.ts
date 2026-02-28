// @vitest-environment node
import fs from 'node:fs';
import { createServer, request as httpRequest, type IncomingHttpHeaders, type Server } from 'node:http';
import path from 'node:path';
import type { Express } from 'express';
import { afterEach, describe, expect, it } from 'vitest';
import { createStandaloneApp } from '../../server/standalone-server';

interface RunningServer {
  origin: string;
  close: () => Promise<void>;
}

function getHeader(headers: IncomingHttpHeaders, name: string): string | null {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0] ?? null;
  return typeof value === 'string' ? value : null;
}

async function requestText(
  origin: string,
  pathname: string,
  options: { headers?: Record<string, string> } = {},
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(pathname, origin);
    const req = httpRequest(
      target,
      {
        method: 'GET',
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf-8'),
          });
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}

async function startApp(app: Express): Promise<RunningServer> {
  const server: Server = createServer(app);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to start standalone test server');
  }
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    }),
  };
}

const tempDirs: string[] = [];
afterEach(() => {
  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  tempDirs.length = 0;
});

function makeTempDir(label: string): string {
  const dir = path.resolve(`ui/.tmp-standalone-${label}-${Date.now()}`);
  fs.mkdirSync(dir, { recursive: true });
  tempDirs.push(dir);
  return dir;
}

describe('standalone express server', () => {
  it('serves built static UI index', async () => {
    const outDir = makeTempDir('out');
    const distDir = makeTempDir('dist');
    fs.writeFileSync(path.resolve(distDir, 'index.html'), '<html><body>standalone-ok</body></html>', 'utf-8');

    const app = createStandaloneApp({
      rootDir: path.resolve('.'),
      outDir,
      distDir,
    });
    const server = await startApp(app);
    try {
      const response = await requestText(server.origin, '/');
      expect(response.status).toBe(200);
      expect(response.body).toContain('standalone-ok');
    } finally {
      await server.close();
    }
  });

  it('enforces optional basic auth when AUTH_USER/AUTH_PASS are configured', async () => {
    const outDir = makeTempDir('out-auth');
    const distDir = makeTempDir('dist-auth');
    fs.writeFileSync(path.resolve(distDir, 'index.html'), '<html><body>auth</body></html>', 'utf-8');

    const app = createStandaloneApp({
      rootDir: path.resolve('.'),
      outDir,
      distDir,
      authUser: 'analyst',
      authPass: 'secret',
    });
    const server = await startApp(app);
    try {
      const unauthorized = await requestText(server.origin, '/api/runs');
      expect(unauthorized.status).toBe(401);
      expect(getHeader(unauthorized.headers, 'www-authenticate')).toContain('Basic');

      const basic = Buffer.from('analyst:secret').toString('base64');
      const authorized = await requestText(server.origin, '/api/runs', {
        headers: { Authorization: `Basic ${basic}` },
      });
      expect(authorized.status).toBe(200);
    } finally {
      await server.close();
    }
  });
});
