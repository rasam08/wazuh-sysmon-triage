// @vitest-environment node
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  spawn: vi.fn(),
  httpRequest: vi.fn(),
  httpsRequest: vi.fn(),
}));

vi.mock('node:child_process', () => ({
  spawn: mocks.spawn,
}));

vi.mock('node:http', () => ({
  default: {
    request: mocks.httpRequest,
  },
}));

vi.mock('node:https', () => ({
  default: {
    request: mocks.httpsRequest,
  },
}));

import { getHealthSnapshot } from '../../server/lib/health';

type MockChild = EventEmitter & {
  stdout: PassThrough;
  stderr: PassThrough;
};

const tempDirs: string[] = [];
let originalWazuhHost: string | undefined;

function makeTempDir(label: string): string {
  const dir = path.resolve(`ui/.tmp-health-${label}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  fs.mkdirSync(dir, { recursive: true });
  tempDirs.push(dir);
  return dir;
}

function mockDryRunSuccess(payload: Record<string, unknown>): void {
  mocks.spawn.mockImplementation((_command: string, _args: string[]) => {
    const child = new EventEmitter() as MockChild;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();

    queueMicrotask(() => {
      child.stdout.write(`${JSON.stringify(payload)}\n`);
      child.stdout.end();
      child.stderr.end();
      child.emit('close', 0);
    });

    return child as never;
  });
}

function mockHttpsResponse(statusCode: number): void {
  mocks.httpsRequest.mockImplementation((
    _options: unknown,
    onResponse: (res: { statusCode?: number; resume: () => void }) => void,
  ) => {
    const req = new EventEmitter() as EventEmitter & {
      end: () => void;
      destroy: (error?: Error) => void;
    };
    req.end = () => {
      onResponse({
        statusCode,
        resume: () => undefined,
      });
    };
    req.destroy = (error?: Error) => {
      if (error) req.emit('error', error);
    };
    return req as never;
  });
}

function mockHttpsError(message: string): void {
  mocks.httpsRequest.mockImplementation((
    _options: unknown,
    _onResponse: (res: { statusCode?: number; resume: () => void }) => void,
  ) => {
    const req = new EventEmitter() as EventEmitter & {
      end: () => void;
      destroy: (error?: Error) => void;
    };
    req.end = () => {
      req.emit('error', new Error(message));
    };
    req.destroy = (error?: Error) => {
      if (error) req.emit('error', error);
    };
    return req as never;
  });
}

beforeEach(() => {
  originalWazuhHost = process.env.WAZUH_OS_HOST;
  delete process.env.WAZUH_OS_HOST;

  mocks.spawn.mockReset();
  mocks.httpRequest.mockReset();
  mocks.httpsRequest.mockReset();

  mocks.httpRequest.mockImplementation((_options: unknown, _onResponse?: unknown) => {
    throw new Error('Unexpected http.request call in health test');
  });
  mocks.httpsRequest.mockImplementation((_options: unknown, _onResponse?: unknown) => {
    throw new Error('Unexpected https.request call in health test');
  });
});

afterEach(() => {
  if (originalWazuhHost === undefined) {
    delete process.env.WAZUH_OS_HOST;
  } else {
    process.env.WAZUH_OS_HOST = originalWazuhHost;
  }

  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  tempDirs.length = 0;
});

describe('health snapshot', () => {
  it('handles missing python executable gracefully and marks CLI unavailable', async () => {
    const enoent = new Error('spawn python ENOENT');
    (enoent as NodeJS.ErrnoException).code = 'ENOENT';
    mocks.spawn.mockImplementation((_command: string, _args: string[]) => {
      throw enoent;
    });

    const rootDir = makeTempDir('enoent-root');
    const outDir = makeTempDir('enoent-out');

    const health = await getHealthSnapshot({
      rootDir,
      outDir,
      profile: 'soc',
      timeoutMs: 50,
    });

    expect(health.cli_available).toBe(false);
    expect(health.opensearch_connectivity).toBe('unknown');
    expect(health.last_successful_fetch_at).toBeNull();
    expect(health.error).toContain('ENOENT');
  });

  it('marks OpenSearch unreachable when probe receives a non-2xx response', async () => {
    mockDryRunSuccess({
      resolved: {
        host: 'https://indexer.example.local:9200',
        verify_tls: true,
      },
    });
    mockHttpsResponse(503);

    const rootDir = makeTempDir('http-503-root');
    const outDir = makeTempDir('http-503-out');

    const health = await getHealthSnapshot({
      rootDir,
      outDir,
      profile: 'soc',
      timeoutMs: 50,
    });

    expect(health.cli_available).toBe(true);
    expect(health.opensearch_connectivity).toBe('unreachable');
    expect(health.opensearch_http_status).toBe(503);
    expect(health.tls_mode).toBe('verify');
  });

  it('marks OpenSearch unreachable and reports TLS errors from probe', async () => {
    mockDryRunSuccess({
      resolved: {
        host: 'https://indexer.example.local:9200',
        verify_tls: true,
      },
    });
    mockHttpsError('self signed certificate');

    const rootDir = makeTempDir('tls-root');
    const outDir = makeTempDir('tls-out');

    const health = await getHealthSnapshot({
      rootDir,
      outDir,
      profile: 'soc',
      timeoutMs: 50,
    });

    expect(health.cli_available).toBe(true);
    expect(health.opensearch_connectivity).toBe('unreachable');
    expect(health.opensearch_http_status).toBeNull();
    expect(health.error).toContain('self signed certificate');
  });

  it('returns null last_successful_fetch_at when telemetry summary is missing', async () => {
    mockDryRunSuccess({ resolved: {} });

    const rootDir = makeTempDir('missing-telemetry-root');
    const outDir = makeTempDir('missing-telemetry-out');

    const health = await getHealthSnapshot({
      rootDir,
      outDir,
      profile: 'soc',
      timeoutMs: 50,
    });

    expect(health.last_successful_fetch_at).toBeNull();
    expect(health.opensearch_connectivity).toBe('not_configured');
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
    expect(mocks.httpRequest).not.toHaveBeenCalled();
  });

  it('returns null last_successful_fetch_at when telemetry summary is malformed JSON', async () => {
    mockDryRunSuccess({ resolved: {} });

    const rootDir = makeTempDir('bad-telemetry-root');
    const outDir = makeTempDir('bad-telemetry-out');
    fs.writeFileSync(path.resolve(outDir, 'telemetry_summary.json'), '{bad-json', 'utf-8');

    const health = await getHealthSnapshot({
      rootDir,
      outDir,
      profile: 'soc',
      timeoutMs: 50,
    });

    expect(health.last_successful_fetch_at).toBeNull();
    expect(health.opensearch_connectivity).toBe('not_configured');
  });
});
