// @vitest-environment node
import fs from 'node:fs';
import { createServer, request as httpRequest, type IncomingHttpHeaders, type Server } from 'node:http';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createTriageApiMiddleware } from '../../server/lib/routes';

interface RunningServer {
  origin: string;
  close: () => Promise<void>;
}

function asTextChunk(chunk: unknown): string {
  if (typeof chunk === 'string') return chunk;
  if (chunk instanceof Uint8Array) return Buffer.from(chunk).toString('utf-8');
  return String(chunk);
}

function getHeader(headers: IncomingHttpHeaders, name: string): string | null {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0] ?? null;
  return typeof value === 'string' ? value : null;
}

async function requestApi(
  origin: string,
  pathname: string,
  options: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(pathname, origin);
    const request = httpRequest(
      target,
      {
        method: options.method ?? 'GET',
        headers: options.headers,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });
        response.on('end', () => {
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf-8'),
          });
        });
      },
    );
    request.on('error', reject);
    if (options.body) {
      request.write(options.body);
    }
    request.end();
  });
}

async function startApiServer(options: Parameters<typeof createTriageApiMiddleware>[0]): Promise<RunningServer> {
  const middleware = createTriageApiMiddleware(options);
  const server: Server = createServer((req, res) => {
    middleware(req, res, () => {
      res.statusCode = 404;
      res.end('not found');
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to resolve test server address');
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

afterEach(() => {
  vi.restoreAllMocks();
});

describe('triage API middleware', () => {
  it('propagates incoming request IDs and generates one when missing', async () => {
    const outDir = path.resolve('ui/.tmp-middleware-request-id');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    vi.spyOn(process.stdout, 'write').mockImplementation((_chunk: unknown) => true);

    const server = await startApiServer({ outDir });
    try {
      const withHeader = await requestApi(server.origin, '/api/runs', {
        headers: { 'x-request-id': 'req-provided-123' },
      });
      expect(withHeader.status).toBe(200);
      expect(getHeader(withHeader.headers, 'x-request-id')).toBe('req-provided-123');

      const generated = await requestApi(server.origin, '/api/runs');
      expect(generated.status).toBe(200);
      const requestId = getHeader(generated.headers, 'x-request-id');
      expect(requestId).toBeTruthy();
      expect(requestId).toMatch(/^[a-f0-9-]{36}$/i);
    } finally {
      await server.close();
    }
  });

  it('enforces per-route rate limits at 100 requests per minute', async () => {
    const outDir = path.resolve('ui/.tmp-middleware-rate-limit');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    vi.spyOn(process.stdout, 'write').mockImplementation((_chunk: unknown) => true);

    const server = await startApiServer({ outDir });
    try {
      for (let idx = 0; idx < 100; idx += 1) {
        const response = await requestApi(server.origin, '/api/runs');
        expect(response.status).toBe(200);
      }

      const limited = await requestApi(server.origin, '/api/runs');
      expect(limited.status).toBe(429);
      expect(getHeader(limited.headers, 'x-request-id')).toBeTruthy();
      const payload = JSON.parse(limited.body) as { error?: string };
      expect(payload.error).toContain('Rate limit exceeded');
    } finally {
      await server.close();
    }
  });

  it('writes structured JSON middleware logs to stdout', async () => {
    const outDir = path.resolve('ui/.tmp-middleware-logging');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((_chunk: unknown) => true);

    const server = await startApiServer({ outDir });
    try {
      const response = await requestApi(server.origin, '/api/runs', {
        headers: { 'x-request-id': 'req-log-001' },
      });
      expect(response.status).toBe(200);

      const lines = stdoutSpy.mock.calls.map((call) => asTextChunk(call[0]).trim()).filter(Boolean);
      const matchingLine = lines.find((line) => line.includes('"request_id":"req-log-001"'));
      expect(matchingLine).toBeTruthy();

      const parsed = JSON.parse(matchingLine ?? '{}') as Record<string, unknown>;
      expect(parsed).toMatchObject({
        event: 'api_request',
        request_id: 'req-log-001',
        method: 'GET',
        route: '/api/runs',
        path: '/api/runs',
        status: 200,
        rate_limited: false,
      });
      expect(typeof parsed.ts).toBe('string');
      expect(typeof parsed.duration_ms).toBe('number');
    } finally {
      await server.close();
    }
  });
});
