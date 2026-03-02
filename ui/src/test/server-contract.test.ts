// @vitest-environment node
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { dispatchApiRequest } from '../../server/lib/routes';
import { createRunner, type Runner, type SpawnedProcess } from '../../server/lib/runner';
import type { RunParams } from '../../server/lib/validators';

function writeJson(filePath: string, value: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2), 'utf-8');
}

function writeText(filePath: string, value: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value, 'utf-8');
}

const LEGACY_DERIVATION_TRUTH_TABLE = [
  {
    alert_type: 'powershell_obfuscation',
    score: 95,
    category: 'malware_execution',
    queue: 'soc_malware',
    confidence: 'high',
  },
  {
    alert_type: 'outbound_public_connection',
    score: 70,
    category: 'c2_outbound',
    queue: 'soc_malware',
    confidence: 'medium',
  },
  {
    alert_type: 'schtasks_persistence',
    score: 49,
    category: 'persistence',
    queue: 'soc_policy',
    confidence: 'low',
  },
  {
    alert_type: 'policy_allowlist_violation',
    score: 80,
    category: 'policy_violation',
    queue: 'soc_policy',
    confidence: 'high',
  },
  {
    alert_type: 'dev_tool_spawn',
    score: 50,
    category: 'developer_tooling',
    queue: 'soc_dev',
    confidence: 'medium',
  },
  {
    alert_type: 'totally_unknown_signal',
    score: 10,
    category: 'unknown',
    queue: 'soc_policy',
    confidence: 'low',
  },
] as const;

function createCurrentCase(outDir: string, caseId: string): void {
  const caseDir = path.resolve(outDir, caseId);
  fs.mkdirSync(caseDir, { recursive: true });

  writeJson(path.resolve(caseDir, 'run_metadata.json'), {
    schema_version: '1.1.0',
    case_id: caseId,
    profile: 'soc',
    start: '2026-02-25T17:12:02.000Z',
    end: '2026-02-25T17:12:12.000Z',
    counts: {
      normalized_events: 1,
      alerts: 1,
      suppressed_alerts: 0,
    },
    fetch_duration_ms: 10,
    normalize_duration_ms: 4,
    correlate_duration_ms: 2,
    detect_duration_ms: 2,
    render_duration_ms: 2,
    total_duration_ms: 20,
    queue_filter: {
      alert_queues: ['soc_malware', 'soc_policy'],
      include_dev_queue: false,
    },
    query: {
      input_ndjson: 'samples/scenario_gym/encoded_powershell.ndjson',
    },
  });

  writeJson(path.resolve(caseDir, 'stats.json'), {
    schema_version: '1.1.0',
    total_events: 1,
    events_by_type: {
      process_create: 1,
      network_connect: 0,
      file_create: 0,
    },
    suppression_hits: {},
    truncation: {
      truncated: false,
      reason: null,
    },
  });

  writeJson(path.resolve(caseDir, 'query.json'), {
    input_ndjson: 'samples/scenario_gym/encoded_powershell.ndjson',
  });

  writeJson(path.resolve(caseDir, 'process_tree.json'), {
    schema_version: '1.1.0',
    agent: { name: 'agent-test', id: '999' },
    time_range: { start: '2026-02-25T17:12:02.000Z', end: '2026-02-25T17:12:02.000Z' },
    nodes: [
      {
        guid: '{PS-ENC}',
        pid: 200,
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        cmdline: 'powershell.exe -enc ...',
        user: 'HOST\\user',
        first_seen: '2026-02-25T17:12:02.000Z',
        last_seen: '2026-02-25T17:12:02.000Z',
        synthetic: false,
        tags: ['attack.t1059'],
      },
    ],
    edges: [],
    artifacts: [],
  });

  writeText(
    path.resolve(caseDir, 'alerts.csv'),
    [
      'utc_time,score,alert_type,category,queue,confidence,reason,routing_why,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags',
      '2026-02-25T17:12:02.000Z,95,powershell_obfuscation,malware_execution,soc_malware,high,PowerShell obfuscation,Routed to soc_malware,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,powershell.exe -enc ...,C:\\Windows\\explorer.exe,,,{PS-ENC},signal:obfuscation',
    ].join('\n'),
  );

  writeText(
    path.resolve(caseDir, 'timeline.csv'),
    [
      'ts,event_id,image,command_line,parent_image,target_filename,user,rule_id,agent_name,agent_id',
      '2026-02-25T17:12:02.000Z,1,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,powershell.exe -enc ...,C:\\Windows\\explorer.exe,,HOST\\user,92203,agent-test,999',
    ].join('\n'),
  );

  writeJson(path.resolve(caseDir, 'alert_A001_bundle.json'), {
    alert: {
      alert_id: 'A001',
      score: 95,
      alert_type: 'powershell_obfuscation',
      reason: 'PowerShell obfuscation',
      process_guid: '{PS-ENC}',
    },
    anchor_event: {
      timestamp: '2026-02-25T17:12:02.000Z',
      event_id: 1,
      image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -enc ...',
      parent_image: 'C:\\Windows\\explorer.exe',
      user: 'HOST\\user',
      agent_name: 'agent-test',
      agent_id: '999',
    },
    network_connections: [],
    suppression_context: {
      suppressed_related_event_count: 0,
      matched_rules: [],
    },
  });

  writeText(path.resolve(caseDir, 'report.md'), '# Current Case\n');
}

function createLegacyCase(outDir: string, caseId: string): void {
  const caseDir = path.resolve(outDir, caseId);
  fs.mkdirSync(caseDir, { recursive: true });

  writeJson(path.resolve(caseDir, 'run_metadata.json'), {
    version: '1.0.0',
    case_id: caseId,
    profile: 'soc',
    start: '2026-02-18T19:15:54.000Z',
    end: '2026-02-19T19:15:54.000Z',
    counts: {
      normalized_events: 2,
      alerts: 1,
      suppressed_alerts: 1,
    },
    fetch_duration_ms: 5,
    normalize_duration_ms: 4,
    correlate_duration_ms: 3,
    detect_duration_ms: 2,
    render_duration_ms: 2,
    total_duration_ms: 16,
  });

  writeJson(path.resolve(caseDir, 'stats.json'), {
    hits: 2,
    events_by_type: {
      process_create: 1,
      file_create: 1,
    },
    suppression_hits: {
      'allowlist:chrome.exe': 1,
    },
    truncation: {
      truncated: false,
      reason: null,
    },
  });

  writeJson(path.resolve(caseDir, 'query.json'), {
    size: 1000,
    query: {
      bool: {
        filter: [
          {
            range: {
              '@timestamp': {
                gte: '2026-02-18T19:15:54.000Z',
                lte: '2026-02-19T19:15:54.000Z',
              },
            },
          },
          {
            bool: {
              should: [{ terms: { 'data.win.system.eventID': [1, 3, 11] } }],
            },
          },
        ],
      },
    },
  });

  writeJson(path.resolve(caseDir, 'process_tree.json'), {
    agent: { name: 'anon' },
    time_range: { start: '2026-02-18T19:15:54.000Z', end: '2026-02-19T19:15:54.000Z' },
    nodes: [],
    edges: [],
    artifacts: [],
  });

  writeText(
    path.resolve(caseDir, 'alerts.csv'),
    [
      'utc_time,score,alert_type,reason,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags',
      '2026-02-18T20:03:55.000Z,25,powershell_suspicious_execution,No-profile flag,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,powershell.exe -NoProfile,C:\\Windows\\explorer.exe,,,{LEG-PS},batcave;powershell',
    ].join('\n'),
  );

  writeText(
    path.resolve(caseDir, 'timeline.csv'),
    [
      'ts,event_id,image,command_line,parent_image,target_filename,user,rule_id,agent_name,agent_id',
      '2026-02-18T20:03:55.000Z,1,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,powershell.exe -NoProfile,C:\\Windows\\explorer.exe,,HOST\\legacy,92203,anon,010',
    ].join('\n'),
  );

  writeText(path.resolve(caseDir, 'report.md'), '# Legacy Case\n');
}

function writeLegacyTruthTableAlerts(caseDir: string): void {
  const lines = [
    'utc_time,score,alert_type,category,queue,confidence,reason,routing_why,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags',
    ...LEGACY_DERIVATION_TRUTH_TABLE.map((row, index) =>
      [
        `2026-02-18T20:03:${String(10 + index).padStart(2, '0')}.000Z`,
        String(row.score),
        row.alert_type,
        '',
        '',
        '',
        'legacy derivation test',
        '',
        'C:\\Windows\\System32\\cmd.exe',
        '',
        '',
        '',
        '',
        `{LEG-${String(index + 1).padStart(3, '0')}}`,
        '',
      ].join(','),
    ),
  ];
  writeText(path.resolve(caseDir, 'alerts.csv'), lines.join('\n'));
}

function buildParams(outDir: string, caseId: string): RunParams {
  return {
    mode: 'offline',
    profile: 'soc',
    time_preset: '2h',
    queues: ['soc_malware', 'soc_policy'],
    include_dev_queue: false,
    min_alert_score: 70,
    out_dir: outDir,
    case_id: caseId,
    dry_run: false,
    alerts_only: false,
    print_stats: true,
    verify_tls: true,
    allowlist_images: [],
    allow_overwrite: false,
    force: false,
  };
}

function fakeSpawn(delayMs = 30, exitCode = 0) {
  return () => {
    const proc = new EventEmitter() as EventEmitter & SpawnedProcess;
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    proc.stdout = stdout;
    proc.stderr = stderr;
    let settled = false;

    const closeWithCode = (code: number) => {
      if (settled) return;
      settled = true;
      stdout.end();
      stderr.end();
      proc.emit('close', code);
    };

    const closeTimer = setTimeout(() => {
      stdout.write('ok\n');
      closeWithCode(exitCode);
    }, delayMs);
    proc.kill = () => {
      clearTimeout(closeTimer);
      closeWithCode(1);
      return true;
    };

    return proc;
  };
}

async function waitForTerminalJob(
  outDir: string,
  jobId: string,
  options: { rootDir?: string; runner?: Runner; timeoutMs?: number } = {},
): Promise<{ job: Record<string, unknown> }> {
  const startedAt = Date.now();
  const timeoutMs = options.timeoutMs ?? 5000;
  while (Date.now() - startedAt < timeoutMs) {
    const response = await dispatchApiRequest(
      { method: 'GET', url: `/api/runs/jobs/${encodeURIComponent(jobId)}` },
      {
        outDir,
        rootDir: options.rootDir,
        runner: options.runner,
      },
    );
    if (!response || response.status !== 200) {
      await new Promise((resolve) => setTimeout(resolve, 25));
      continue;
    }
    const payload = response.body as { job: Record<string, unknown> };
    const status = String(payload.job.status ?? '');
    if (status === 'success' || status === 'failed' || status === 'cancelled') {
      return payload;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`Job ${jobId} did not reach terminal status within ${timeoutMs}ms`);
}

describe('server contract routes', () => {
  it('supports POST /api/runs then GET /api/cases/:id and GET /api/alerts?case=:id', async () => {
    const outDir = path.resolve('ui/.tmp-server-contract-flow');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    const caseId = 'CASE-FLOW-001';
    const runner = {
      previewRun: vi.fn(),
      startRun: vi.fn(async (params: RunParams) => {
        createCurrentCase(outDir, params.case_id);
        return {
          case_id: params.case_id,
          case_dir: path.resolve(outDir, params.case_id),
          log_path: path.resolve(outDir, params.case_id, 'middleware-run.log'),
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

    const runResponse = await dispatchApiRequest(
      {
        method: 'POST',
        url: '/api/runs',
        body: {
          params: {
            ...buildParams(outDir, caseId),
            input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
            allowlist_images: [
              'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
              'MsMpEng.exe',
            ],
          },
        },
      },
      { outDir, runner },
    );
    expect(runResponse).not.toBeNull();
    expect(runResponse?.status).toBe(200);
    expect(runner.startRun).toHaveBeenCalledTimes(1);
    expect(runner.startRun).toHaveBeenCalledWith(expect.objectContaining({
      allowlist_images: ['chrome.exe', 'msmpeng.exe'],
    }));

    const runPayload = runResponse?.body as { run: Record<string, unknown> };
    expect(typeof runPayload.run.id).toBe('string');
    expect((runPayload.run.params as Record<string, unknown>).case_id).toBe(caseId);

    const caseResponse = await dispatchApiRequest(
      { method: 'GET', url: `/api/cases/${encodeURIComponent(caseId)}` },
      { outDir },
    );
    expect(caseResponse).not.toBeNull();
    expect(caseResponse?.status).toBe(200);

    const casePayload = caseResponse?.body as { case: Record<string, unknown> };
    expect(casePayload.case.case_id).toBe(caseId);
    expect(Array.isArray(casePayload.case.alerts)).toBe(true);
    expect((casePayload.case.alerts as unknown[]).length).toBeGreaterThan(0);
    const caseAlert = (casePayload.case.alerts as Array<Record<string, unknown>>)[0];
    expect(typeof caseAlert.alert_id).toBe('string');
    expect(typeof caseAlert.score).toBe('number');
    expect(typeof caseAlert.alert_type).toBe('string');
    expect(typeof caseAlert.queue).toBe('string');
    expect(typeof caseAlert.confidence).toBe('string');

    const alertsResponse = await dispatchApiRequest(
      { method: 'GET', url: `/api/alerts?case=${encodeURIComponent(caseId)}` },
      { outDir },
    );
    expect(alertsResponse).not.toBeNull();
    expect(alertsResponse?.status).toBe(200);

    const alertsPayload = alertsResponse?.body as {
      alerts: Array<Record<string, unknown>>;
      case_id: string | null;
    };
    expect(alertsPayload.case_id).toBe(caseId);
    expect(alertsPayload.alerts.length).toBeGreaterThan(0);
    const alert = alertsPayload.alerts[0];
    expect(typeof alert.alert_id).toBe('string');
    expect(typeof alert.utc_time).toBe('string');
    expect(typeof alert.reason).toBe('string');
    expect(Array.isArray(alert.tags)).toBe(true);
  });

  it('returns consistent case shape for current and legacy case folders', async () => {
    const outDir = path.resolve('ui/.tmp-server-contract');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    createCurrentCase(outDir, 'CASE-CURRENT-001');
    createLegacyCase(outDir, 'incident-live-online-alert');

    for (const caseId of ['CASE-CURRENT-001', 'incident-live-online-alert']) {
      const response = await dispatchApiRequest(
        { method: 'GET', url: `/api/cases/${encodeURIComponent(caseId)}` },
        { outDir },
      );

      expect(response).not.toBeNull();
      expect(response?.status).toBe(200);

      const payload = response?.body as { case: Record<string, unknown> };
      const casePayload = payload.case;
      expect(typeof casePayload.case_id).toBe('string');
      expect(typeof casePayload.schema_version).toBe('string');
      expect(Array.isArray(casePayload.alerts)).toBe(true);
      expect(Array.isArray(casePayload.timeline)).toBe(true);
      expect(typeof casePayload.report_md).toBe('string');

      const firstAlert = (casePayload.alerts as Array<Record<string, unknown>>)[0];
      expect(typeof firstAlert.category).toBe('string');
      expect(typeof firstAlert.queue).toBe('string');
      expect(typeof firstAlert.confidence).toBe('string');

      const stats = casePayload.stats as Record<string, unknown>;
      expect(typeof stats.total_events).toBe('number');
      expect(typeof stats.alerts_generated).toBe('number');
      expect(typeof stats.network_connections).toBe('number');
    }
  });

  it('legacy derivation truth table', async () => {
    const outDir = path.resolve('ui/.tmp-server-legacy-derivation');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    const caseId = 'CASE-LEGACY-DERIVATION-001';
    createLegacyCase(outDir, caseId);
    writeLegacyTruthTableAlerts(path.resolve(outDir, caseId));

    const response = await dispatchApiRequest(
      { method: 'GET', url: `/api/cases/${encodeURIComponent(caseId)}` },
      { outDir },
    );
    expect(response).not.toBeNull();
    expect(response?.status).toBe(200);

    const payload = response?.body as {
      case: { alerts: Array<Record<string, unknown>> };
    };
    const alerts = payload.case.alerts;
    expect(alerts.length).toBe(LEGACY_DERIVATION_TRUTH_TABLE.length);

    for (const row of LEGACY_DERIVATION_TRUTH_TABLE) {
      const alert = alerts.find((item) => item.alert_type === row.alert_type);
      expect(alert).toBeTruthy();
      expect(alert?.category).toBe(row.category);
      expect(alert?.queue).toBe(row.queue);
      expect(alert?.confidence).toBe(row.confidence);
    }
  });

  it('rejects case path traversal attempts', async () => {
    const response = await dispatchApiRequest(
      { method: 'GET', url: '/api/cases/..%2Foutside' },
      { outDir: path.resolve('ui/.tmp-server-contract') },
    );
    expect(response).not.toBeNull();
    expect(response?.status).toBe(400);
    expect(response?.body).toEqual({ error: expect.any(String) });
  });

  it('deletes a case folder via API', async () => {
    const outDir = path.resolve('ui/.tmp-server-delete-contract');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    createCurrentCase(outDir, 'CASE-DELETE-001');

    const caseDir = path.resolve(outDir, 'CASE-DELETE-001');
    expect(fs.existsSync(caseDir)).toBe(true);

    const deleteResponse = await dispatchApiRequest(
      { method: 'DELETE', url: '/api/cases/CASE-DELETE-001' },
      { outDir },
    );
    expect(deleteResponse).not.toBeNull();
    expect(deleteResponse?.status).toBe(200);
    expect(deleteResponse?.body).toEqual({ deleted: true, case_id: 'CASE-DELETE-001' });
    expect(fs.existsSync(caseDir)).toBe(false);

    const missingResponse = await dispatchApiRequest(
      { method: 'GET', url: '/api/cases/CASE-DELETE-001' },
      { outDir },
    );
    expect(missingResponse).not.toBeNull();
    expect(missingResponse?.status).toBe(404);
  });

  it('blocks deleting a case while that case run is active', async () => {
    const outDir = path.resolve('ui/.tmp-server-delete-active-guard');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    createCurrentCase(outDir, 'CASE-ACTIVE-DELETE-001');

    const guardedRunner = {
      previewRun: vi.fn(),
      startRun: vi.fn(),
      cancelRun: vi.fn(),
      isCaseActive: vi.fn((caseId: string) => caseId === 'CASE-ACTIVE-DELETE-001'),
      getActiveCaseId: vi.fn(() => 'CASE-ACTIVE-DELETE-001'),
    };

    const response = await dispatchApiRequest(
      { method: 'DELETE', url: '/api/cases/CASE-ACTIVE-DELETE-001' },
      { outDir, runner: guardedRunner },
    );
    expect(response).not.toBeNull();
    expect(response?.status).toBe(409);
    expect(fs.existsSync(path.resolve(outDir, 'CASE-ACTIVE-DELETE-001'))).toBe(true);
  });

  it('rejects offline input_file absolute and traversal paths', async () => {
    const outDir = path.resolve('ui/.tmp-server-offline-path-guard');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    const badRequests = [
      'C:\\outside\\input.ndjson',
      '..\\samples\\scenario_gym\\encoded_powershell.ndjson',
    ];

    for (const inputFile of badRequests) {
      const response = await dispatchApiRequest(
        {
          method: 'POST',
          url: '/api/runs/preview',
          body: {
            params: {
              mode: 'offline',
              case_id: 'CASE-OFFLINE-PATH-001',
              input_file: inputFile,
            },
          },
        },
        {
          rootDir: path.resolve('.'),
          outDir,
          offlineInputRoots: ['samples'],
        },
      );
      expect(response).not.toBeNull();
      expect(response?.status).toBe(400);
    }
  });

  it('supports cancelling an active run via API', async () => {
    const outDir = path.resolve('ui/.tmp-server-cancel-run');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    const runner = createRunner({
      rootDir: path.resolve('.'),
      runTimeoutMs: 30_000,
      spawnProcess: fakeSpawn(250),
    });

    const runPromise = dispatchApiRequest(
      {
        method: 'POST',
        url: '/api/runs',
        body: {
          params: {
            ...buildParams(outDir, 'CASE-CANCEL-001'),
            input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
          },
        },
      },
      {
        rootDir: path.resolve('.'),
        outDir,
        runner,
        offlineInputRoots: ['samples'],
      },
    );

    await new Promise((resolve) => setTimeout(resolve, 20));
    const cancelResponse = await dispatchApiRequest(
      {
        method: 'POST',
        url: '/api/runs/CASE-CANCEL-001/cancel',
      },
      { outDir, runner },
    );
    expect(cancelResponse).not.toBeNull();
    expect(cancelResponse?.status).toBe(202);
    expect(cancelResponse?.body).toEqual({
      cancelled: true,
      case_id: 'CASE-CANCEL-001',
      reason: 'user',
    });

    const runResponse = await runPromise;
    expect(runResponse).not.toBeNull();
    expect(runResponse?.status).toBe(409);
    expect(runResponse?.body).toEqual({ error: expect.stringContaining('cancelled') });
  });

  it('fails fast on invalid run params and does not call startRun', async () => {
    const fakeRunner = {
      previewRun: vi.fn(),
      startRun: vi.fn(),
      cancelRun: vi.fn(),
      isCaseActive: vi.fn(() => false),
      getActiveCaseId: vi.fn(() => null),
    };
    const response = await dispatchApiRequest(
      {
        method: 'POST',
        url: '/api/runs',
        body: {
          params: {
            mode: 'invalid-mode',
            case_id: 'CASE-1',
          },
        },
      },
      { outDir: path.resolve('ui/.tmp-server-contract'), runner: fakeRunner },
    );

    expect(response).not.toBeNull();
    expect(response?.status).toBe(400);
    expect(response?.body).toEqual({ error: expect.any(String) });
    expect(fakeRunner.startRun).not.toHaveBeenCalled();
  });

  it('replays POST /api/runs response once per idempotency key', async () => {
    const outDir = path.resolve('ui/.tmp-server-idempotency-replay');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    const caseId = 'CASE-IDEMPOTENT-001';
    const idempotencyKey = `test-idempotency-${Date.now()}`;

    const runner = {
      previewRun: vi.fn(),
      startRun: vi.fn(async (params: RunParams) => {
        createCurrentCase(outDir, params.case_id);
        return {
          case_id: params.case_id,
          case_dir: path.resolve(outDir, params.case_id),
          log_path: path.resolve(outDir, params.case_id, 'middleware-run.log'),
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

    const requestBody = {
      params: {
        ...buildParams(outDir, caseId),
        input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
      },
    };
    const requestHeaders = { 'idempotency-key': idempotencyKey };

    const first = await dispatchApiRequest(
      {
        method: 'POST',
        url: '/api/runs',
        body: requestBody,
        headers: requestHeaders,
      },
      {
        rootDir: path.resolve('.'),
        outDir,
        runner,
        offlineInputRoots: ['samples'],
      },
    );
    const second = await dispatchApiRequest(
      {
        method: 'POST',
        url: '/api/runs',
        body: requestBody,
        headers: requestHeaders,
      },
      {
        rootDir: path.resolve('.'),
        outDir,
        runner,
        offlineInputRoots: ['samples'],
      },
    );

    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(first?.status).toBe(200);
    expect(second?.status).toBe(200);
    expect(second?.body).toEqual(first?.body);
    expect(runner.startRun).toHaveBeenCalledTimes(1);
  });

  it('rejects idempotency-key replay when request body differs', async () => {
    const outDir = path.resolve('ui/.tmp-server-idempotency-mismatch');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    const idempotencyKey = `test-idempotency-mismatch-${Date.now()}`;

    const runner = {
      previewRun: vi.fn(),
      startRun: vi.fn(async (params: RunParams) => {
        createCurrentCase(outDir, params.case_id);
        return {
          case_id: params.case_id,
          case_dir: path.resolve(outDir, params.case_id),
          log_path: path.resolve(outDir, params.case_id, 'middleware-run.log'),
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

    const first = await dispatchApiRequest(
      {
        method: 'POST',
        url: '/api/runs',
        body: {
          params: {
            ...buildParams(outDir, 'CASE-IDEMPOTENT-A'),
            input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
          },
        },
        headers: { 'idempotency-key': idempotencyKey },
      },
      {
        rootDir: path.resolve('.'),
        outDir,
        runner,
        offlineInputRoots: ['samples'],
      },
    );
    expect(first?.status).toBe(200);

    const second = await dispatchApiRequest(
      {
        method: 'POST',
        url: '/api/runs',
        body: {
          params: {
            ...buildParams(outDir, 'CASE-IDEMPOTENT-B'),
            input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
          },
        },
        headers: { 'idempotency-key': idempotencyKey },
      },
      {
        rootDir: path.resolve('.'),
        outDir,
        runner,
        offlineInputRoots: ['samples'],
      },
    );
    expect(second).not.toBeNull();
    expect(second?.status).toBe(409);
    expect(second?.body).toEqual({
      error: expect.stringContaining('Idempotency-Key'),
    });
    expect(runner.startRun).toHaveBeenCalledTimes(1);
  });

  it('returns health payload shape', async () => {
    const outDir = path.resolve('ui/.tmp-health-contract');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    writeJson(path.resolve(outDir, 'telemetry_summary.json'), {
      last_successful_live_fetch_at: '2026-02-26T01:00:00Z',
    });

    const response = await dispatchApiRequest(
      { method: 'GET', url: '/api/health?profile=soc' },
      { outDir, rootDir: path.resolve('.') },
    );
    expect(response).not.toBeNull();
    expect(response?.status).toBe(200);

    const payload = response?.body as { health: Record<string, unknown> };
    expect(payload.health).toBeTruthy();
    expect(typeof payload.health.opensearch_connectivity).toBe('string');
    expect(payload.health.last_successful_fetch_at).toBe('2026-02-26T01:00:00Z');
  });

  it('returns actionable error when async submit routes are disabled', async () => {
    const originalAsyncFlag = process.env.TRIAGE_ASYNC_RUNS_ENABLED;
    delete process.env.TRIAGE_ASYNC_RUNS_ENABLED;
    const outDir = path.resolve('ui/.tmp-server-async-disabled');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    try {
      const response = await dispatchApiRequest(
        {
          method: 'POST',
          url: '/api/runs/submit',
          body: {
            params: {
              ...buildParams(outDir, 'CASE-ASYNC-DISABLED-001'),
              input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
            },
          },
        },
        {
          rootDir: path.resolve('.'),
          outDir,
          offlineInputRoots: ['samples'],
        },
      );
      expect(response).not.toBeNull();
      expect(response?.status).toBe(404);
      expect(response?.body).toEqual({
        error: expect.stringContaining('Async runs disabled'),
      });
      expect(response?.body).toEqual({
        error: expect.stringContaining('POST /api/runs'),
      });
      expect(response?.body).toEqual({
        error: expect.stringContaining('TRIAGE_ASYNC_RUNS_ENABLED=true'),
      });
    } finally {
      if (originalAsyncFlag === undefined) {
        delete process.env.TRIAGE_ASYNC_RUNS_ENABLED;
      } else {
        process.env.TRIAGE_ASYNC_RUNS_ENABLED = originalAsyncFlag;
      }
    }
  });

  it('supports async submit and job status lifecycle when feature flag is enabled', async () => {
    const originalAsyncFlag = process.env.TRIAGE_ASYNC_RUNS_ENABLED;
    process.env.TRIAGE_ASYNC_RUNS_ENABLED = 'true';
    const outDir = path.resolve('ui/.tmp-server-async-lifecycle');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    const runner = createRunner({
      rootDir: path.resolve('.'),
      spawnProcess: fakeSpawn(80),
    });

    try {
      const submitResponse = await dispatchApiRequest(
        {
          method: 'POST',
          url: '/api/runs/submit',
          body: {
            params: {
              ...buildParams(outDir, 'CASE-ASYNC-001'),
              input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
            },
          },
        },
        {
          rootDir: path.resolve('.'),
          outDir,
          runner,
          offlineInputRoots: ['samples'],
        },
      );
      expect(submitResponse).not.toBeNull();
      expect(submitResponse?.status).toBe(202);
      const submitPayload = submitResponse?.body as {
        job_id: string;
        case_id: string;
        accepted_at: string;
      };
      expect(submitPayload.case_id).toBe('CASE-ASYNC-001');
      expect(typeof submitPayload.job_id).toBe('string');
      expect(typeof submitPayload.accepted_at).toBe('string');

      const terminalPayload = await waitForTerminalJob(outDir, submitPayload.job_id, {
        rootDir: path.resolve('.'),
        runner,
      });
      expect(terminalPayload.job.case_id).toBe('CASE-ASYNC-001');
      expect(terminalPayload.job.status).toBe('success');
      const queueDbPath = path.resolve(outDir, '.run-queue', 'run_queue.sqlite3');
      expect(fs.existsSync(queueDbPath)).toBe(true);
    } finally {
      if (originalAsyncFlag === undefined) {
        delete process.env.TRIAGE_ASYNC_RUNS_ENABLED;
      } else {
        process.env.TRIAGE_ASYNC_RUNS_ENABLED = originalAsyncFlag;
      }
    }
  });

  it('recovers legacy queue state file and drains jobs into sqlite-backed state', async () => {
    const originalAsyncFlag = process.env.TRIAGE_ASYNC_RUNS_ENABLED;
    process.env.TRIAGE_ASYNC_RUNS_ENABLED = 'true';
    const outDir = path.resolve('ui/.tmp-server-async-legacy-recovery');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(path.resolve(outDir, '.run-queue'), { recursive: true });
    const runner = createRunner({
      rootDir: path.resolve('.'),
      spawnProcess: fakeSpawn(80),
    });
    const caseId = 'CASE-ASYNC-LEGACY-RECOVERY-001';
    const jobId = 'job-legacy-recovery-001';
    const acceptedAt = new Date().toISOString();

    writeJson(path.resolve(outDir, '.run-queue', 'run_queue_state.json'), {
      version: 1,
      active_job_id: null,
      queue: [jobId],
      jobs: [
        {
          job_id: jobId,
          case_id: caseId,
          params: {
            ...buildParams(outDir, caseId),
            input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
          },
          status: 'queued',
          stage: 'queued',
          progress_pct: 0,
          accepted_at: acceptedAt,
          accepted_at_ms: Date.now(),
          request_hash: 'legacy-state-hash',
          idempotency_key: 'legacy-state-key',
          cancel_requested: false,
          message: 'Queued',
        },
      ],
    });

    try {
      const statusResponse = await dispatchApiRequest(
        {
          method: 'GET',
          url: `/api/runs/jobs/${encodeURIComponent(jobId)}`,
        },
        {
          rootDir: path.resolve('.'),
          outDir,
          runner,
        },
      );
      expect(statusResponse).not.toBeNull();
      expect(statusResponse?.status).toBe(200);

      const terminalPayload = await waitForTerminalJob(outDir, jobId, {
        rootDir: path.resolve('.'),
        runner,
        timeoutMs: 8000,
      });
      expect(terminalPayload.job.status).toBe('success');
      expect(fs.existsSync(path.resolve(outDir, '.run-queue', 'run_queue.sqlite3'))).toBe(true);
      expect(fs.existsSync(path.resolve(outDir, '.run-queue', 'run_queue_state.json'))).toBe(false);
    } finally {
      if (originalAsyncFlag === undefined) {
        delete process.env.TRIAGE_ASYNC_RUNS_ENABLED;
      } else {
        process.env.TRIAGE_ASYNC_RUNS_ENABLED = originalAsyncFlag;
      }
    }
  });

  it('supports cancelling async queued jobs by job ID', async () => {
    const originalAsyncFlag = process.env.TRIAGE_ASYNC_RUNS_ENABLED;
    process.env.TRIAGE_ASYNC_RUNS_ENABLED = 'true';
    const outDir = path.resolve('ui/.tmp-server-async-cancel');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    const runner = createRunner({
      rootDir: path.resolve('.'),
      spawnProcess: fakeSpawn(400),
    });

    try {
      const submitResponse = await dispatchApiRequest(
        {
          method: 'POST',
          url: '/api/runs/submit',
          body: {
            params: {
              ...buildParams(outDir, 'CASE-ASYNC-CANCEL-001'),
              input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
            },
          },
        },
        {
          rootDir: path.resolve('.'),
          outDir,
          runner,
          offlineInputRoots: ['samples'],
        },
      );
      expect(submitResponse?.status).toBe(202);
      const jobId = (submitResponse?.body as { job_id: string }).job_id;

      const cancelResponse = await dispatchApiRequest(
        {
          method: 'POST',
          url: `/api/runs/jobs/${encodeURIComponent(jobId)}/cancel`,
        },
        {
          rootDir: path.resolve('.'),
          outDir,
          runner,
        },
      );
      expect(cancelResponse).not.toBeNull();
      expect(cancelResponse?.status).toBe(202);
      const cancelPayload = cancelResponse?.body as { cancelled: boolean; job: Record<string, unknown> };
      expect(cancelPayload.cancelled).toBe(true);
      expect(cancelPayload.job.status).toMatch(/queued|running|cancelled/);

      const terminalPayload = await waitForTerminalJob(outDir, jobId, {
        rootDir: path.resolve('.'),
        runner,
        timeoutMs: 8000,
      });
      expect(terminalPayload.job.status).toBe('cancelled');
    } finally {
      if (originalAsyncFlag === undefined) {
        delete process.env.TRIAGE_ASYNC_RUNS_ENABLED;
      } else {
        process.env.TRIAGE_ASYNC_RUNS_ENABLED = originalAsyncFlag;
      }
    }
  });

  it('supports GET /api/runs query params for status, mode, limit, and offset', async () => {
    const originalAsyncFlag = process.env.TRIAGE_ASYNC_RUNS_ENABLED;
    process.env.TRIAGE_ASYNC_RUNS_ENABLED = 'true';
    const outDir = path.resolve('ui/.tmp-server-runs-query-params');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    const runner = createRunner({
      rootDir: path.resolve('.'),
      spawnProcess: fakeSpawn(300),
    });

    try {
      const submitResponse = await dispatchApiRequest(
        {
          method: 'POST',
          url: '/api/runs/submit',
          body: {
            params: {
              ...buildParams(outDir, 'CASE-QUERY-001'),
              input_file: 'samples/scenario_gym/encoded_powershell.ndjson',
            },
          },
        },
        {
          rootDir: path.resolve('.'),
          outDir,
          runner,
          offlineInputRoots: ['samples'],
        },
      );
      expect(submitResponse?.status).toBe(202);

      const runsResponse = await dispatchApiRequest(
        {
          method: 'GET',
          url: '/api/runs?mode=offline&limit=10&offset=0',
        },
        {
          rootDir: path.resolve('.'),
          outDir,
          runner,
        },
      );
      expect(runsResponse).not.toBeNull();
      expect(runsResponse?.status).toBe(200);
      const runsPayload = runsResponse?.body as { runs: Array<Record<string, unknown>> };
      expect(Array.isArray(runsPayload.runs)).toBe(true);
      expect(runsPayload.runs.some((run) => run.id === 'CASE-QUERY-001')).toBe(true);
      expect(runsPayload.runs.every((run) => (run.params as Record<string, unknown>).mode === 'offline')).toBe(true);
    } finally {
      if (originalAsyncFlag === undefined) {
        delete process.env.TRIAGE_ASYNC_RUNS_ENABLED;
      } else {
        process.env.TRIAGE_ASYNC_RUNS_ENABLED = originalAsyncFlag;
      }
    }
  });
});

describe('runner safety guards', () => {
  it('passes allowlist images as repeatable CLI flags', async () => {
    const outDir = path.resolve('ui/.tmp-runner-allowlist');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    let capturedArgs: string[] = [];
    const runner = createRunner({
      rootDir: path.resolve('.'),
      spawnProcess: (_command, args) => {
        capturedArgs = [...args];
        return fakeSpawn(1)();
      },
    });

    await runner.startRun({
      ...buildParams(outDir, 'CASE-ALLOWLIST-001'),
      allowlist_images: ['chrome.exe', 'msmpeng.exe'],
    });

    const allowlistFlags = capturedArgs
      .map((value, index) => ({ value, index }))
      .filter((entry) => entry.value === '--allowlist-image')
      .map((entry) => capturedArgs[entry.index + 1]);
    expect(allowlistFlags).toEqual(['chrome.exe', 'msmpeng.exe']);
  });

  it('enforces single active run lock', async () => {
    const outDir = path.resolve('ui/.tmp-runner-lock');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    const runner = createRunner({
      rootDir: path.resolve('.'),
      spawnProcess: fakeSpawn(40),
    });

    const first = runner.startRun(buildParams(outDir, 'CASE-LOCK-A'));
    await expect(runner.startRun(buildParams(outDir, 'CASE-LOCK-B'))).rejects.toMatchObject({ status: 409 });
    await first;
  });

  it('supports explicit cancellation and releases run lock', async () => {
    const outDir = path.resolve('ui/.tmp-runner-cancel');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    const runner = createRunner({
      rootDir: path.resolve('.'),
      runTimeoutMs: 30_000,
      spawnProcess: fakeSpawn(200),
    });

    const firstRun = runner.startRun(buildParams(outDir, 'CASE-CANCEL-A'));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(runner.cancelRun('CASE-CANCEL-A')).toEqual({
      cancelled: true,
      case_id: 'CASE-CANCEL-A',
      reason: 'user',
    });
    await expect(firstRun).rejects.toMatchObject({ status: 409 });
    await expect(runner.startRun(buildParams(outDir, 'CASE-CANCEL-B'))).resolves.toMatchObject({
      case_id: 'CASE-CANCEL-B',
    });
  });

  it('enforces run timeout and releases run lock afterwards', async () => {
    const outDir = path.resolve('ui/.tmp-runner-timeout');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });

    let invocation = 0;
    const runner = createRunner({
      rootDir: path.resolve('.'),
      runTimeoutMs: 30,
      spawnProcess: () => {
        invocation += 1;
        return invocation === 1 ? fakeSpawn(200)() : fakeSpawn(1)();
      },
    });

    await expect(runner.startRun(buildParams(outDir, 'CASE-TIMEOUT-A'))).rejects.toMatchObject({ status: 408 });
    await expect(runner.startRun(buildParams(outDir, 'CASE-TIMEOUT-B'))).resolves.toMatchObject({
      case_id: 'CASE-TIMEOUT-B',
    });
  });

  it('requires explicit overwrite permission when case folder exists', async () => {
    const outDir = path.resolve('ui/.tmp-runner-overwrite');
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(path.resolve(outDir, 'CASE-EXISTS'), { recursive: true });

    const runner = createRunner({
      rootDir: path.resolve('.'),
      spawnProcess: fakeSpawn(1),
    });

    await expect(runner.startRun(buildParams(outDir, 'CASE-EXISTS'))).rejects.toMatchObject({ status: 409 });
    await expect(
      runner.startRun({
        ...buildParams(outDir, 'CASE-EXISTS'),
        allow_overwrite: true,
      }),
    ).resolves.toMatchObject({ case_id: 'CASE-EXISTS' });
  });
});
