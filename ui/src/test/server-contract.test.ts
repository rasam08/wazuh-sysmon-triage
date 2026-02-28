// @vitest-environment node
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { dispatchApiRequest } from '../../server/lib/routes';
import { createRunner, type SpawnedProcess } from '../../server/lib/runner';
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

    setTimeout(() => {
      stdout.write('ok\n');
      stdout.end();
      stderr.end();
      proc.emit('close', exitCode);
    }, delayMs);

    return proc;
  };
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
        };
      }),
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

  it('fails fast on invalid run params and does not call startRun', async () => {
    const fakeRunner = {
      previewRun: vi.fn(),
      startRun: vi.fn(),
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
