// @vitest-environment node
import fs from 'node:fs';
import { createServer, request as httpRequest, type IncomingHttpHeaders, type Server } from 'node:http';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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

async function requestSseEvents(
  origin: string,
  pathname: string,
  options: { headers?: Record<string, string>; maxEvents?: number } = {},
): Promise<Array<{ event: string; payload: Record<string, unknown> }>> {
  return new Promise((resolve, reject) => {
    const target = new URL(pathname, origin);
    const req = httpRequest(
      target,
      {
        method: 'GET',
        headers: options.headers,
      },
      (response) => {
        const maxEvents = options.maxEvents ?? 8;
        const events: Array<{ event: string; payload: Record<string, unknown> }> = [];
        let buffer = '';

        const flushBuffer = () => {
          let delimiter = buffer.indexOf('\n\n');
          while (delimiter >= 0) {
            const block = buffer.slice(0, delimiter).trim();
            buffer = buffer.slice(delimiter + 2);
            if (!block) {
              delimiter = buffer.indexOf('\n\n');
              continue;
            }
            const lines = block.split('\n');
            const eventLine = lines.find((line) => line.startsWith('event:'));
            const dataLine = lines.find((line) => line.startsWith('data:'));
            if (!eventLine || !dataLine) {
              delimiter = buffer.indexOf('\n\n');
              continue;
            }
            const event = eventLine.slice('event:'.length).trim();
            const data = dataLine.slice('data:'.length).trim();
            try {
              const payload = JSON.parse(data) as Record<string, unknown>;
              events.push({ event, payload });
            } catch {
              // Ignore malformed events in tests.
            }
            if (event === 'terminal' || events.length >= maxEvents) {
              req.destroy();
              resolve(events);
              return;
            }
            delimiter = buffer.indexOf('\n\n');
          }
        };

        response.on('data', (chunk) => {
          buffer += Buffer.isBuffer(chunk) ? chunk.toString('utf-8') : String(chunk);
          flushBuffer();
        });
        response.on('end', () => {
          flushBuffer();
          resolve(events);
        });
      },
    );
    req.on('error', reject);
    req.end();
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

let originalEnforceCsrf: string | undefined;
let originalAsyncRunsEnabled: string | undefined;
beforeEach(() => {
  originalEnforceCsrf = process.env.TRIAGE_ENFORCE_CSRF;
  originalAsyncRunsEnabled = process.env.TRIAGE_ASYNC_RUNS_ENABLED;
  delete process.env.TRIAGE_ENFORCE_CSRF;
  delete process.env.TRIAGE_ASYNC_RUNS_ENABLED;
});

afterEach(() => {
  if (originalEnforceCsrf === undefined) {
    delete process.env.TRIAGE_ENFORCE_CSRF;
  } else {
    process.env.TRIAGE_ENFORCE_CSRF = originalEnforceCsrf;
  }
  if (originalAsyncRunsEnabled === undefined) {
    delete process.env.TRIAGE_ASYNC_RUNS_ENABLED;
  } else {
    process.env.TRIAGE_ASYNC_RUNS_ENABLED = originalAsyncRunsEnabled;
  }
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

  it('applies rate limits per client key (not globally per route)', async () => {
    const outDir = path.resolve('ui/.tmp-middleware-rate-limit-clients');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    vi.spyOn(process.stdout, 'write').mockImplementation((_chunk: unknown) => true);

    const server = await startApiServer({
      outDir,
      rateLimitMaxRequests: 2,
      rateLimitWindowMs: 60_000,
      clientKeyResolver: (req) => {
        const raw = req.headers['x-test-client'];
        const value = Array.isArray(raw) ? raw[0] : raw;
        return typeof value === 'string' ? value : 'unknown';
      },
    });
    try {
      for (let idx = 0; idx < 2; idx += 1) {
        const response = await requestApi(server.origin, '/api/runs', {
          headers: { 'x-test-client': 'client-a' },
        });
        expect(response.status).toBe(200);
      }

      const limited = await requestApi(server.origin, '/api/runs', {
        headers: { 'x-test-client': 'client-a' },
      });
      expect(limited.status).toBe(429);

      const otherClient = await requestApi(server.origin, '/api/runs', {
        headers: { 'x-test-client': 'client-b' },
      });
      expect(otherClient.status).toBe(200);
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

  it('exposes Prometheus metrics on /metrics', async () => {
    const outDir = path.resolve('ui/.tmp-middleware-metrics');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    vi.spyOn(process.stdout, 'write').mockImplementation((_chunk: unknown) => true);

    const server = await startApiServer({ outDir });
    try {
      const runsResponse = await requestApi(server.origin, '/api/runs');
      expect(runsResponse.status).toBe(200);
      const healthResponse = await requestApi(server.origin, '/api/health?profile=soc');
      expect(healthResponse.status).toBe(200);

      const metrics = await requestApi(server.origin, '/metrics');
      expect(metrics.status).toBe(200);
      expect(getHeader(metrics.headers, 'content-type')).toContain('text/plain');
      expect(metrics.body).toContain('triage_up 1');
      expect(metrics.body).toContain('triage_api_requests_total');
      expect(metrics.body).toContain('triage_api_success_rate_ratio');
      expect(metrics.body).toContain('triage_run_queue_depth{state="queued"}');
      expect(metrics.body).toContain('triage_health_requests_total');
      expect(metrics.body).toContain('route="/api/runs"');
    } finally {
      await server.close();
    }
  });

  it('enforces CSRF guard for browser mutating requests when enabled', async () => {
    process.env.TRIAGE_ENFORCE_CSRF = 'true';
    const outDir = path.resolve('ui/.tmp-middleware-csrf-enforce');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    vi.spyOn(process.stdout, 'write').mockImplementation((_chunk: unknown) => true);

    const server = await startApiServer({ outDir });
    try {
      const missingHeader = await requestApi(server.origin, '/api/cases/CASE-CSRF-001', {
        method: 'DELETE',
        headers: { Origin: server.origin },
      });
      expect(missingHeader.status).toBe(403);
      expect(JSON.parse(missingHeader.body)).toEqual({
        error: expect.stringContaining('X-Requested-With'),
      });

      const sameOrigin = await requestApi(server.origin, '/api/cases/CASE-CSRF-001', {
        method: 'DELETE',
        headers: {
          Origin: server.origin,
          'X-Requested-With': 'XMLHttpRequest',
        },
      });
      expect([200, 404]).toContain(sameOrigin.status);
      expect(sameOrigin.status).not.toBe(403);
    } finally {
      await server.close();
    }
  });

  it('rejects cross-origin browser mutating requests when CSRF is enabled', async () => {
    process.env.TRIAGE_ENFORCE_CSRF = 'true';
    const outDir = path.resolve('ui/.tmp-middleware-csrf-cross-origin');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    vi.spyOn(process.stdout, 'write').mockImplementation((_chunk: unknown) => true);

    const server = await startApiServer({ outDir });
    try {
      const response = await requestApi(server.origin, '/api/cases/CASE-CSRF-002', {
        method: 'DELETE',
        headers: {
          Origin: 'https://evil.example',
          'X-Requested-With': 'XMLHttpRequest',
        },
      });
      expect(response.status).toBe(403);
      expect(JSON.parse(response.body)).toEqual({
        error: expect.stringContaining('Cross-origin'),
      });
    } finally {
      await server.close();
    }
  });

  it('streams async run progress over SSE', async () => {
    process.env.TRIAGE_ASYNC_RUNS_ENABLED = 'true';
    const outDir = path.resolve('ui/.tmp-middleware-async-stream');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    vi.spyOn(process.stdout, 'write').mockImplementation((_chunk: unknown) => true);

    const runner = {
      previewRun: vi.fn(),
      startRun: vi.fn(async () => {
        await new Promise((resolve) => setTimeout(resolve, 40));
        return {
          case_id: 'CASE-STREAM-001',
          case_dir: path.resolve(outDir, 'CASE-STREAM-001'),
          log_path: path.resolve(outDir, 'CASE-STREAM-001', 'middleware-run.log'),
          exit_code: 0,
          stdout_tail: 'ok',
          stderr_tail: '',
          cancelled: false,
          cancel_reason: null,
        };
      }),
      cancelRun: vi.fn(),
      isCaseActive: vi.fn(() => false),
      getActiveCaseId: vi.fn(() => null),
    };

    const server = await startApiServer({ outDir, runner });
    try {
      const submit = await requestApi(server.origin, '/api/runs/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          params: {
            mode: 'offline',
            profile: 'soc',
            time_preset: '2h',
            queues: ['soc_malware', 'soc_policy'],
            include_dev_queue: false,
            min_alert_score: 70,
            out_dir: outDir,
            case_id: 'CASE-STREAM-001',
            dry_run: false,
            alerts_only: false,
            print_stats: true,
            input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
          },
        }),
      });
      expect(submit.status).toBe(202);
      const submitPayload = JSON.parse(submit.body) as { job_id: string };
      expect(typeof submitPayload.job_id).toBe('string');

      const events = await requestSseEvents(server.origin, `/api/runs/jobs/${encodeURIComponent(submitPayload.job_id)}/stream`);
      expect(events.length).toBeGreaterThan(0);
      expect(events[0]?.event).toBe('progress');
      expect(events.some((entry) => entry.event === 'terminal')).toBe(true);
      const terminal = [...events].reverse().find((entry) => entry.event === 'terminal');
      expect(terminal?.payload.status).toBe('success');
    } finally {
      await server.close();
    }
  });
});
