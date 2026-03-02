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

import { getHealthSnapshot, resetHealthSnapshotCache } from '../../server/lib/health';

type MockChild = EventEmitter & {
  stdout: PassThrough;
  stderr: PassThrough;
};

const tempDirs: string[] = [];
let originalWazuhHost: string | undefined;
let originalOpenSearchAllowlist: string | undefined;

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
  resetHealthSnapshotCache();
  originalWazuhHost = process.env.WAZUH_OS_HOST;
  originalOpenSearchAllowlist = process.env.TRIAGE_OPENSEARCH_HOST_ALLOWLIST;
  delete process.env.WAZUH_OS_HOST;
  delete process.env.TRIAGE_OPENSEARCH_HOST_ALLOWLIST;

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
  resetHealthSnapshotCache();
  if (originalWazuhHost === undefined) {
    delete process.env.WAZUH_OS_HOST;
  } else {
    process.env.WAZUH_OS_HOST = originalWazuhHost;
  }
  if (originalOpenSearchAllowlist === undefined) {
    delete process.env.TRIAGE_OPENSEARCH_HOST_ALLOWLIST;
  } else {
    process.env.TRIAGE_OPENSEARCH_HOST_ALLOWLIST = originalOpenSearchAllowlist;
  }

  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  tempDirs.length = 0;
  delete process.env.TRIAGE_HEALTH_CACHE_MS;
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

  it('rejects disallowed OpenSearch host before network probe when allowlist is configured', async () => {
    process.env.TRIAGE_OPENSEARCH_HOST_ALLOWLIST = 'indexer.example.local';
    mockDryRunSuccess({
      resolved: {
        host: 'https://blocked.example.local:9200',
        verify_tls: true,
      },
    });

    const rootDir = makeTempDir('allowlist-block-root');
    const outDir = makeTempDir('allowlist-block-out');

    const health = await getHealthSnapshot({
      rootDir,
      outDir,
      profile: 'soc',
      timeoutMs: 50,
    });

    expect(health.opensearch_connectivity).toBe('unreachable');
    expect(health.opensearch_http_status).toBeNull();
    expect(health.error).toContain('host_not_allowlisted');
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
    expect(mocks.httpRequest).not.toHaveBeenCalled();
  });

  it('allows OpenSearch host when exact allowlist entry matches', async () => {
    process.env.TRIAGE_OPENSEARCH_HOST_ALLOWLIST = 'indexer.example.local';
    mockDryRunSuccess({
      resolved: {
        host: 'https://indexer.example.local:9200',
        verify_tls: true,
      },
    });
    mockHttpsResponse(200);

    const rootDir = makeTempDir('allowlist-allow-root');
    const outDir = makeTempDir('allowlist-allow-out');

    const health = await getHealthSnapshot({
      rootDir,
      outDir,
      profile: 'soc',
      timeoutMs: 50,
    });

    expect(health.opensearch_connectivity).toBe('reachable');
    expect(health.opensearch_http_status).toBe(200);
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
  });

  it('supports IPv4 CIDR allowlist entries', async () => {
    process.env.TRIAGE_OPENSEARCH_HOST_ALLOWLIST = '10.10.0.0/16';
    mockDryRunSuccess({
      resolved: {
        host: 'https://10.10.5.9:9200',
        verify_tls: true,
      },
    });
    mockHttpsResponse(200);

    const rootDir = makeTempDir('allowlist-cidr-root');
    const outDir = makeTempDir('allowlist-cidr-out');

    const health = await getHealthSnapshot({
      rootDir,
      outDir,
      profile: 'soc',
      timeoutMs: 50,
    });

    expect(health.opensearch_connectivity).toBe('reachable');
    expect(health.opensearch_http_status).toBe(200);
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
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

  it('returns cached health snapshots within cache TTL', async () => {
    process.env.TRIAGE_HEALTH_CACHE_MS = '30000';
    mockDryRunSuccess({
      resolved: {
        host: 'https://indexer.example.local:9200',
        verify_tls: true,
      },
    });
    mockHttpsResponse(200);

    const rootDir = makeTempDir('cache-root');
    const outDir = makeTempDir('cache-out');
    const options = {
      rootDir,
      outDir,
      profile: 'soc' as const,
      timeoutMs: 50,
    };

    const first = await getHealthSnapshot(options);
    const second = await getHealthSnapshot(options);

    expect(first).toEqual(second);
    expect(mocks.spawn).toHaveBeenCalledTimes(1);
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
  });

  it('disables caching when TRIAGE_HEALTH_CACHE_MS=0', async () => {
    process.env.TRIAGE_HEALTH_CACHE_MS = '0';
    mockDryRunSuccess({
      resolved: {
        host: 'https://indexer.example.local:9200',
        verify_tls: true,
      },
    });
    mockHttpsResponse(200);

    const rootDir = makeTempDir('cache-disabled-root');
    const outDir = makeTempDir('cache-disabled-out');
    const options = {
      rootDir,
      outDir,
      profile: 'soc' as const,
      timeoutMs: 50,
    };

    await getHealthSnapshot(options);
    await getHealthSnapshot(options);

    expect(mocks.spawn).toHaveBeenCalledTimes(2);
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(2);
  });
});
